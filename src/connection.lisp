(uiop:define-package #:ssh/connection
  (:use #:cl)
  (:import-from #:ssh/channel-buffer
                #:make-input-buffer #:input-buffer-mode #:input-buffer-count
                #:buffer-accept #:buffer-take #:buffer-snapshot)
  (:import-from #:ssh/constants
                #:+msg-global-request+
                #:+msg-request-success+
                #:+msg-request-failure+
                #:+msg-channel-open+
                #:+msg-channel-open-confirmation+
                #:+msg-channel-open-failure+
                #:+msg-channel-window-adjust+
                #:+msg-channel-data+
                #:+msg-channel-extended-data+
                #:+msg-channel-eof+
                #:+msg-channel-close+
                #:+msg-channel-request+
                #:+msg-channel-success+
                #:+msg-channel-failure+
                #:+open-administratively-prohibited+
                #:+extended-data-stderr+)
  (:import-from #:ssh/buffer
                #:make-write-buffer
                #:buffer-to-octets
                #:write-byte*
                #:write-uint32
                #:write-string*
                #:make-read-buffer
                #:read-byte*
                #:read-uint32
                #:read-string*)
  (:import-from #:ssh/transport
                #:transport
                #:transport-socket
                #:transport-send
                #:transport-disconnect)
  (:export
   #:connection
   #:connection-error
   #:make-connection
   #:connection-rekey
   #:connection-close
   #:connection-transport
   #:channel
   #:channel-connection
   #:channel-local-id
   #:channel-remote-id
   #:channel-local-window
   #:channel-remote-window
   #:channel-max-packet
   #:channel-open-p
   #:channel-eof-p
   #:channel-close-p
   #:channel-closed-p
   #:channel-stdout-buffer
   #:channel-stderr-buffer
   #:channel-exit-status
   #:channel-failure
   #:channel-state-lock
   #:channel-state-condition
   #:channel-read-lock
   #:channel-stderr-read-lock
   #:channel-write-lock
   #:open-channel
   #:channel-request
   #:channel-send-data
   #:channel-send-eof
   #:channel-close
   #:channel-wait-until))
(in-package #:ssh/connection)

(defconstant +initial-window-size+ (* 2 1024 1024))
(defconstant +maximum-packet-size+ 32768)
(defconstant +maximum-uint32+ #xffffffff)

(define-condition connection-error (error)
  ((reason :initarg :reason :reader connection-error-reason))
  (:report (lambda (condition stream)
             (format stream "SSH connection failed: ~A"
                     (connection-error-reason condition)))))

(define-condition channel-open-error (error)
  ((reason-code :initarg :reason-code :reader channel-open-error-reason-code)
   (description :initarg :description :reader channel-open-error-description))
  (:report (lambda (condition stream)
             (format stream "SSH channel open failed (~D): ~A"
                     (channel-open-error-reason-code condition)
                     (channel-open-error-description condition)))))

(defstruct channel
  connection
  (local-id 0 :type integer)
  (remote-id 0 :type integer)
  (local-window +initial-window-size+ :type integer)
  (local-window-maximum +initial-window-size+ :type integer)
  (local-max-packet +maximum-packet-size+ :type integer)
  (remote-window 0 :type integer)
  (max-packet +maximum-packet-size+ :type integer)
  (open-p nil)
  (open-state :pending)
  open-failure
  (eof-p nil)
  (eof-sent-p nil)
  (close-p nil)
  (closing-p nil)
  (close-sent-p nil)
  (close-send-pending-p nil)
  (stdout-input (make-input-buffer))
  (stderr-input (make-input-buffer))
  (stderr-closed-p nil)
  (window-credit 0)
  exit-status
  request-state
  failure
  (state-lock (bt2:make-lock :name "SSH channel state"))
  (state-condition (bt2:make-condition-variable :name "SSH channel state"))
  (read-lock (bt2:make-lock :name "SSH channel reader"))
  (stderr-read-lock (bt2:make-lock :name "SSH channel stderr reader"))
  (write-lock (bt2:make-lock :name "SSH channel writer")))

(define-condition channel-closed-error (error)
  ((channel :initarg :channel :reader closed-error-channel))
  (:report (lambda (condition stream)
             (format stream "SSH channel ~D is closing or closed"
                     (channel-local-id (closed-error-channel condition))))))

(defun channel-stdout-buffer (channel)
  "Copy a channel's retained standard output.
CHANNEL selects unread streaming bytes or explicitly captured full history.
Returns a fresh octet vector; modifying it does not alter the channel."
  (bt2:with-lock-held ((channel-state-lock channel))
    (buffer-snapshot (channel-stdout-input channel))))

(defun channel-stderr-buffer (channel)
  "Copy a channel's retained standard error.
CHANNEL selects unread bytes, explicitly captured history, or a diagnostic tail.
Returns a fresh octet vector; modifying it does not alter the channel."
  (bt2:with-lock-held ((channel-state-lock channel))
    (buffer-snapshot (channel-stderr-input channel))))

(defun %channel-input (channel stderr-p)
  (if stderr-p (channel-stderr-input channel) (channel-stdout-input channel)))

(defun %channel-read (channel destination start end stderr-p block-p)
  (let ((count 0) (status :data) (failure nil))
    (bt2:with-lock-held ((channel-state-lock channel))
      (loop
        (when (and stderr-p (channel-stderr-closed-p channel))
          (setf status :closed) (return))
        (when (or (= start end) (plusp (input-buffer-count (%channel-input channel stderr-p))))
          (multiple-value-bind (copied credit)
              (buffer-take (%channel-input channel stderr-p) destination start end)
            (setf count copied)
            (incf (channel-window-credit channel) credit))
          (return))
        (cond
          ((channel-failure channel)
           (setf status :failed failure (channel-failure channel)) (return))
          ((channel-close-p channel) (setf status :closed) (return))
          ((channel-eof-p channel) (setf status :eof) (return))
          ((not block-p) (setf status :blocked) (return)))
        (bt2:condition-wait (channel-state-condition channel) (channel-state-lock channel))))
    (when (and (channel-connection channel) (not (channel-close-p channel)))
      (%maybe-adjust-window channel))
    (values count status failure)))

(defstruct (connection-action (:constructor make-connection-action (kind &key payload reason channel)))
  kind
  payload
  reason
  channel
  (lock (bt2:make-lock :name "SSH dispatcher action"))
  (condition (bt2:make-condition-variable :name "SSH dispatcher action"))
  (done-p nil)
  error)

(defstruct (connection
            (:constructor %make-connection
                (&key transport control-reader control-writer dispatcher-thread
                      (state :new))))
  (transport (error "A transport is required") :type transport)
  (channels (make-hash-table :test #'eql))
  (next-channel-id 0 :type integer)
  (registry-lock (bt2:make-lock :name "SSH channel registry"))
  action-head
  action-tail
  (queue-lock (bt2:make-lock :name "SSH dispatcher queue"))
  (wake-pending-p nil)
  control-reader
  control-writer
  dispatcher-thread
  (state :new)
  failure
  (state-lock (bt2:make-lock :name "SSH connection state"))
  (state-condition (bt2:make-condition-variable :name "SSH connection state")))

(defun channel-closed-p (channel)
  "Report whether both sides have exchanged SSH_MSG_CHANNEL_CLOSE.
CHANNEL is the channel whose close handshake is inspected.
Returns true after both close messages have been sent and received."
  (and (channel-close-p channel)
       (channel-close-sent-p channel)))

(defun %make-control-socket-pair ()
  (let ((listener nil)
        (reader nil)
        (writer nil))
    (unwind-protect
         (progn
           (setf listener
                 (usocket:socket-listen "127.0.0.1" 0
                                        :reuse-address t
                                        :element-type '(unsigned-byte 8)))
           (setf writer
                 (usocket:socket-connect "127.0.0.1"
                                         (usocket:get-local-port listener)
                                         :element-type '(unsigned-byte 8)))
           (setf reader (usocket:socket-accept listener
                                               :element-type '(unsigned-byte 8)))
           (values reader writer))
      (when listener
        (ignore-errors (usocket:socket-close listener)))
      (unless (and reader writer)
        (when reader (ignore-errors (usocket:socket-close reader)))
        (when writer (ignore-errors (usocket:socket-close writer)))))))

(defun %wake-dispatcher (connection)
  (let ((stream (usocket:socket-stream (connection-control-writer connection))))
    (write-byte 1 stream)
    (force-output stream)))

(defun %queue-action-locked (connection action)
  (let ((cell (list action)))
    (if (connection-action-tail connection)
        (setf (cdr (connection-action-tail connection)) cell
              (connection-action-tail connection) cell)
        (setf (connection-action-head connection) cell
              (connection-action-tail connection) cell))))

(defun %enqueue-action (connection action &key allow-closing)
  (let ((wake-p nil))
    (bt2:with-lock-held ((connection-state-lock connection))
      (unless (or (eq (connection-state connection) :running)
                  (and allow-closing
                       (eq (connection-state connection) :closing)))
        (error (or (connection-failure connection)
                   (make-condition 'connection-error
                                   :reason "connection is not running"))))
      (bt2:with-lock-held ((connection-queue-lock connection))
        (%queue-action-locked connection action)
        (unless (connection-wake-pending-p connection)
          (setf (connection-wake-pending-p connection) t
                wake-p t))))
    (when wake-p
      (handler-case
          (%wake-dispatcher connection)
        (error (condition)
          (%fail-connection connection condition))))
    action))

(defun %dequeue-action (connection)
  (bt2:with-lock-held ((connection-queue-lock connection))
    (let ((head (connection-action-head connection)))
      (when head
        (setf (connection-action-head connection) (cdr head))
        (unless (connection-action-head connection)
          (setf (connection-action-tail connection) nil))
        (car head)))))

(defun %detach-actions (connection)
  (bt2:with-lock-held ((connection-queue-lock connection))
    (prog1 (connection-action-head connection)
      (setf (connection-action-head connection) nil
            (connection-action-tail connection) nil))))

(defun %complete-action (action &optional error)
  (bt2:with-lock-held ((connection-action-lock action))
    (setf (connection-action-error action) error
          (connection-action-done-p action) t)
    (bt2:condition-broadcast (connection-action-condition action))))

(defun %wait-for-action (action)
  (bt2:with-lock-held ((connection-action-lock action))
    (loop until (connection-action-done-p action)
          do (bt2:condition-wait (connection-action-condition action)
                                 (connection-action-lock action)))
    (when (connection-action-error action)
      (error (connection-action-error action))))
  t)

(defun %registered-channels (connection)
  (bt2:with-lock-held ((connection-registry-lock connection))
    (loop for channel being the hash-values of (connection-channels connection)
          collect channel)))

(defun %detach-channels (connection)
  (bt2:with-lock-held ((connection-registry-lock connection))
    (prog1
        (loop for channel being the hash-values of (connection-channels connection)
              collect channel)
      (clrhash (connection-channels connection)))))

(defun %fail-channel (channel failure)
  (bt2:with-lock-held ((channel-state-lock channel))
    (unless (channel-failure channel)
      (setf (channel-failure channel) failure))
    (bt2:condition-broadcast (channel-state-condition channel))))

(defun %fail-connection (connection failure)
  (let ((condition (if (typep failure 'condition)
                       failure
                       (make-condition 'connection-error :reason failure)))
        (changed-p nil))
    (bt2:with-lock-held ((connection-state-lock connection))
      (unless (eq (connection-state connection) :closed)
        (setf (connection-state connection) :closed
              (connection-failure connection) condition
              changed-p t)
        (bt2:condition-broadcast (connection-state-condition connection))))
    (when changed-p
      (dolist (channel (%detach-channels connection))
        (%fail-channel channel condition))
      (loop for cell on (%detach-actions connection)
            do (%complete-action (car cell) condition)))
    condition))

(defun %close-control-sockets (connection)
  (when (connection-control-reader connection)
    (ignore-errors (usocket:socket-close (connection-control-reader connection)))
    (setf (connection-control-reader connection) nil))
  (when (connection-control-writer connection)
    (ignore-errors (usocket:socket-close (connection-control-writer connection)))
    (setf (connection-control-writer connection) nil)))

(defun %drain-control-socket (connection)
  (let ((stream (usocket:socket-stream (connection-control-reader connection))))
    (read-byte stream nil nil))
  (bt2:with-lock-held ((connection-queue-lock connection))
    (setf (connection-wake-pending-p connection) nil)))

(defun %dispatcher-send (connection payload &optional channel)
  ;; Only this thread can send CLOSE or handle the peer's CLOSE. Validate here,
  ;; after earlier inbound messages, rather than trusting the caller's snapshot.
  (when channel
    (bt2:with-lock-held ((channel-state-lock channel))
      (when (or (channel-close-sent-p channel)
                (and (/= (aref payload 0) +msg-channel-close+)
                     (or (channel-close-p channel) (channel-failure channel))))
        (error 'channel-closed-error :channel channel))))
  (transport-send (connection-transport connection) payload)
  (when (and channel (= (aref payload 0) +msg-channel-close+))
    (let ((closed-p nil))
      (bt2:with-lock-held ((channel-state-lock channel))
        (setf (channel-close-sent-p channel) t
              (channel-close-send-pending-p channel) nil
              closed-p (channel-close-p channel))
        (bt2:condition-broadcast (channel-state-condition channel)))
      (when closed-p (%unregister-channel channel)))))

(defun %process-action (connection action)
  (handler-case
      (ecase (connection-action-kind action)
        (:send
         (handler-case
             (progn
               (%dispatcher-send connection (connection-action-payload action)
                                 (connection-action-channel action))
               (%complete-action action))
           ;; A stale channel action fails its caller, not the shared transport.
           (channel-closed-error (condition)
             (%complete-action action condition)))
         nil)
        (:rekey
         (ssh/transport::transport-rekey (connection-transport connection))
         (%complete-action action)
         nil)
        (:disconnect
         (transport-disconnect (connection-transport connection)
                               (or (connection-action-reason action)
                                   "normal closure"))
         (%complete-action action)
         t))
    (error (condition)
      (%complete-action action condition)
      (error condition))))

(defun %transport-pending-p (connection)
  (not (null (ssh/transport::transport-pending-packets
              (connection-transport connection)))))

(defun %dispatcher-loop (connection)
  (let ((normal-close-p nil))
    (unwind-protect
         (handler-case
             (loop
               (let ((action (%dequeue-action connection)))
                 (when (and action (%process-action connection action))
                   (setf normal-close-p t)
                   (return))
                 (let* ((ssh-socket (transport-socket
                                     (connection-transport connection)))
                        (control-socket (connection-control-reader connection))
                        (pending-p (%transport-pending-p connection))
                        (ready (unless pending-p
                                 (usocket:wait-for-input
                                  (list control-socket ssh-socket)
                                  :timeout (and action 0)
                                  :ready-only t))))
                   (when (and ready (member control-socket ready :test #'eq))
                     (%drain-control-socket connection))
                   (when (or pending-p
                             (and ready (member ssh-socket ready :test #'eq)))
                     (let ((packet (ssh/transport::transport-recv-step
                                    (connection-transport connection))))
                       (when packet
                         (%handle-packet connection packet)))))))
           (error (condition)
             (%fail-connection connection condition)))
      ;; The dispatcher owns this socket on every exit, including nonlocal unwinds.
      (unless normal-close-p
        (ignore-errors (usocket:socket-close
                        (transport-socket (connection-transport connection)))))
      (unless (eq (connection-state connection) :closed)
        (%fail-connection
         connection
         (make-condition 'connection-error
                         :reason (if normal-close-p
                                     "connection closed"
                                     "dispatcher stopped"))))
      (%close-control-sockets connection))))

(defun make-connection (transport)
  "Create and start the event-driven dispatcher for an SSH connection.
TRANSPORT is the authenticated transport transferred to the dispatcher on success.
Returns a shared connection, releasing control sockets if construction unwinds."
  (multiple-value-bind (reader writer) (%make-control-socket-pair)
    (let ((connection nil) (transferred-p nil))
      (unwind-protect
           (progn
             (setf connection (%make-connection :transport transport :control-reader reader
                                                :control-writer writer :state :running))
             (setf (connection-dispatcher-thread connection)
                   (bt2:make-thread (lambda () (%dispatcher-loop connection))
                                    :name "SSH connection dispatcher"))
             (setf transferred-p t)
             connection)
        (unless transferred-p
          (if connection (%close-control-sockets connection)
              (progn
                (ignore-errors (usocket:socket-close reader))
                (ignore-errors (usocket:socket-close writer)))))))))

(defun connection-close (connection &optional (reason "normal closure"))
  "Close a multiplexed SSH connection and wait for its dispatcher to finish.
CONNECTION is the connection to close.
REASON is the SSH disconnect description sent to the peer.
Returns true after the dispatcher and transport have stopped."
  (if (null (connection-dispatcher-thread connection))
      (progn
        (transport-disconnect (connection-transport connection) reason)
        (%fail-connection connection
                          (make-condition 'connection-error :reason reason))
        t)
      (let ((action nil)
            (wake-p nil))
        (bt2:with-lock-held ((connection-state-lock connection))
          (case (connection-state connection)
            (:running
             (setf (connection-state connection) :closing
                   action (make-connection-action :disconnect :reason reason))
             (bt2:with-lock-held ((connection-queue-lock connection))
               (%queue-action-locked connection action)
               (unless (connection-wake-pending-p connection)
                 (setf (connection-wake-pending-p connection) t
                       wake-p t))))
            (:closing)
            (:closed)))
        (when wake-p
          (handler-case
              (%wake-dispatcher connection)
            (error (condition)
              (%fail-connection connection condition))))
        (if action
            (%wait-for-action action)
            (bt2:with-lock-held ((connection-state-lock connection))
              (loop until (eq (connection-state connection) :closed)
                    do (bt2:condition-wait
                        (connection-state-condition connection)
                        (connection-state-lock connection)))))
        (let ((thread (connection-dispatcher-thread connection)))
          (when (and thread
                     (not (eq thread (bt2:current-thread))))
            (bt2:join-thread thread)))
        t)))

(defun connection-rekey (connection)
  "Perform a key exchange through the connection's transport owner.
CONNECTION is the running multiplexed SSH connection.
Returns true after the dispatcher completes the key exchange."
  (if (null (connection-dispatcher-thread connection))
      (progn
        (ssh/transport::transport-rekey (connection-transport connection))
        t)
      (let ((action (make-connection-action :rekey)))
        (%enqueue-action connection action)
        (%wait-for-action action))))

(defun %conn-send (connection payload &key channel)
  (if (or (null (connection-dispatcher-thread connection))
          (eq (connection-dispatcher-thread connection) (bt2:current-thread)))
      (%dispatcher-send connection payload channel)
      (let ((action (make-connection-action :send :payload payload :channel channel)))
        (%enqueue-action connection action)
        (%wait-for-action action))))

(defun %allocate-channel (connection initial-window max-packet)
  (bt2:with-lock-held ((connection-registry-lock connection))
    (loop repeat (1+ +maximum-uint32+)
          for id = (connection-next-channel-id connection)
          do (setf (connection-next-channel-id connection)
                   (logand +maximum-uint32+ (1+ id)))
          unless (gethash id (connection-channels connection))
            do (let ((channel (make-channel :connection connection
                                            :local-id id
                                            :local-window initial-window
                                            :local-window-maximum initial-window
                                            :local-max-packet max-packet)))
                 (setf (gethash id (connection-channels connection)) channel)
                 (return channel))
          finally (error "No SSH channel identifiers remain"))))

(defun %find-channel (connection local-id &optional errorp)
  (bt2:with-lock-held ((connection-registry-lock connection))
    (or (gethash local-id (connection-channels connection))
        (when errorp
          (error "Unknown SSH channel recipient id ~D" local-id)))))

(defun %unregister-channel (channel)
  (let ((connection (channel-connection channel)))
    (bt2:with-lock-held ((connection-registry-lock connection))
      (when (eq channel
                (gethash (channel-local-id channel)
                         (connection-channels connection)))
        (remhash (channel-local-id channel)
                 (connection-channels connection))))))

(defun channel-wait-until (channel predicate)
  "Wait without polling until a channel predicate becomes true.
CHANNEL supplies the state lock and condition variable used for the wait.
PREDICATE is called with CHANNEL while its state lock is held.
Returns CHANNEL when the predicate succeeds."
  (bt2:with-lock-held ((channel-state-lock channel))
    (loop
      (when (funcall predicate channel)
        (return channel))
      (when (channel-failure channel)
        (error (channel-failure channel)))
      (bt2:condition-wait (channel-state-condition channel)
                          (channel-state-lock channel)))))

(defun open-channel (connection &key (type "session")
                                       (initial-window +initial-window-size+)
                                       (max-packet +maximum-packet-size+)
                                       capture-output stderr-tail)
  "Open an SSH channel and wait for its confirmation.
CONNECTION is the multiplexed SSH connection that owns the channel.
TYPE is the SSH channel type name.
INITIAL-WINDOW is the initial receive window advertised to the peer.
MAX-PACKET is the largest incoming channel data packet advertised to the peer.
CAPTURE-OUTPUT retains complete output history instead of reclaiming read bytes.
STDERR-TAIL selects a bounded diagnostic sink instead of a readable stderr queue.
Returns the confirmed channel."
  (check-type initial-window (integer 0 #xffffffff))
  (check-type max-packet (integer 1 #xffffffff))
  (let ((channel (%allocate-channel connection initial-window max-packet)))
    (handler-case
        (let ((buffer (make-write-buffer)))
          (setf (channel-stdout-input channel)
                (make-input-buffer :mode (if capture-output :capture :stream))
                (channel-stderr-input channel)
                (make-input-buffer :mode (cond (stderr-tail :tail)
                                               (capture-output :capture)
                                               (t :stream))))
          (write-byte* buffer +msg-channel-open+)
          (write-string* buffer type)
          (write-uint32 buffer (channel-local-id channel))
          (write-uint32 buffer initial-window)
          (write-uint32 buffer max-packet)
          (%conn-send connection (buffer-to-octets buffer))
          (channel-wait-until
           channel (lambda (candidate) (member (channel-open-state candidate) '(:open :failed))))
          (when (eq (channel-open-state channel) :failed)
            (destructuring-bind (reason description) (channel-open-failure channel)
              (error 'channel-open-error :reason-code reason :description description)))
          channel)
      (error (condition)
        (%unregister-channel channel)
        (error condition)))))

(defun %send-channel-message (channel message &optional writer)
  (let ((buffer (make-write-buffer)))
    (write-byte* buffer message)
    (write-uint32 buffer (channel-remote-id channel))
    (when writer
      (funcall writer buffer))
    (%conn-send (channel-connection channel) (buffer-to-octets buffer) :channel channel)))

(defun channel-request (channel request-type &key (want-reply t) data-writer)
  "Send a serialized channel request and optionally wait for its reply.
CHANNEL is the open channel receiving the request.
REQUEST-TYPE is the SSH channel request name.
WANT-REPLY controls whether the peer must report success or failure.
DATA-WRITER writes request-specific fields into the request buffer.
Returns true on success, or NIL when the peer rejects the request."
  (bt2:with-lock-held ((channel-write-lock channel))
    (bt2:with-lock-held ((channel-state-lock channel))
      (when (or (channel-closing-p channel) (channel-close-p channel)
                (channel-close-sent-p channel) (channel-failure channel))
        (error 'channel-closed-error :channel channel))
      (when want-reply (setf (channel-request-state channel) :pending)))
    (handler-case
        (progn
          (%send-channel-message
           channel +msg-channel-request+
           (lambda (buffer)
             (write-string* buffer request-type)
             (write-byte* buffer (if want-reply 1 0))
             (when data-writer
               (funcall data-writer buffer))))
          (if want-reply
              (progn
                (channel-wait-until
                 channel
                 (lambda (candidate)
                   (or (member (channel-request-state candidate)
                               '(:success :failure))
                       (channel-close-p candidate)
                       (channel-closing-p candidate))))
                (bt2:with-lock-held ((channel-state-lock channel))
                  (when (and (or (channel-close-p channel) (channel-closing-p channel))
                             (eq (channel-request-state channel) :pending))
                    (setf (channel-request-state channel) nil)
                    (error 'channel-closed-error :channel channel))
                  (prog1 (eq (channel-request-state channel) :success)
                    (setf (channel-request-state channel) nil))))
              t))
      (error (condition)
        (when want-reply
          (bt2:with-lock-held ((channel-state-lock channel))
            (setf (channel-request-state channel) nil)))
        (error condition)))))

(defun %wait-for-remote-window (channel)
  (channel-wait-until
   channel
   (lambda (candidate)
     (or (plusp (channel-remote-window candidate))
         (channel-close-p candidate)
         (channel-closing-p candidate)))))

(defun channel-send-data (channel data &key (start 0) end)
  "Send channel data while respecting the peer's flow-control window.
CHANNEL is the open channel receiving DATA.
DATA is an octet vector.
START is the first octet index to send.
END is the exclusive ending index, or the vector length when omitted.
Returns the number of octets sent."
  (let ((end (or end (length data))))
    (check-type data (vector (unsigned-byte 8)))
    (unless (<= 0 start end (length data))
      (error "Invalid channel data bounds ~D..~D" start end))
    (bt2:with-lock-held ((channel-write-lock channel))
      (loop with offset = start
            while (< offset end)
            do (%wait-for-remote-window channel)
               (let ((count nil))
                 (bt2:with-lock-held ((channel-state-lock channel))
                   (when (channel-failure channel)
                     (error (channel-failure channel)))
                   (when (or (channel-closing-p channel)
                             (channel-close-p channel) (channel-close-sent-p channel)
                             (channel-eof-sent-p channel))
                     (error 'channel-closed-error :channel channel))
                   (setf count (min (- end offset)
                                    (channel-remote-window channel)
                                    (channel-max-packet channel)))
                   (decf (channel-remote-window channel) count))
                 (%send-channel-message
                  channel +msg-channel-data+
                  (lambda (buffer)
                    (write-string* buffer (subseq data offset (+ offset count)))))
                 (incf offset count)))
      (- end start))))

(defun %channel-send-eof-locked (channel)
  (let ((send-p nil))
    (bt2:with-lock-held ((channel-state-lock channel))
      (unless (or (channel-close-p channel)
                  (channel-eof-sent-p channel)
                  (channel-close-sent-p channel))
        (setf (channel-eof-sent-p channel) t
              send-p t)))
    (when send-p
      (%send-channel-message channel +msg-channel-eof+))
    t))

(defun channel-send-eof (channel)
  "Send SSH_MSG_CHANNEL_EOF once, ordered after earlier writes.
CHANNEL is the channel whose outgoing byte stream is finished.
Returns true after EOF has been sent or was already sent."
  (bt2:with-lock-held ((channel-write-lock channel))
    (%channel-send-eof-locked channel)))

(defun %channel-send-close-locked (channel)
  (let ((send-p nil))
    (bt2:with-lock-held ((channel-state-lock channel))
      (unless (or (channel-close-sent-p channel)
                  (channel-close-send-pending-p channel))
        (setf (channel-close-send-pending-p channel) t
              send-p t)))
    (when send-p
      (handler-case
          (progn
            (%send-channel-message channel +msg-channel-close+)
            (bt2:with-lock-held ((channel-state-lock channel))
              (setf (channel-close-send-pending-p channel) nil
                    (channel-close-sent-p channel) t)
              (bt2:condition-broadcast (channel-state-condition channel))))
        (error (condition)
          (bt2:with-lock-held ((channel-state-lock channel))
            (setf (channel-close-send-pending-p channel) nil)
            (bt2:condition-broadcast (channel-state-condition channel)))
          (error condition))))
    ;; A peer CLOSE can arrive while our send is still pending. Its handler
    ;; cannot unregister yet, so finish that half of the handshake here too.
    (when (channel-closed-p channel) (%unregister-channel channel))
    send-p))

(defun channel-close (channel &key abort)
  "Close a channel and cancel unfinished writes waiting for flow control or replies.
CHANNEL is the channel whose outgoing work is stopped.
ABORT skips EOF and peer acknowledgement, and wakes blocked readers with failure.
Returns true after sending CLOSE; normal closure also waits for the peer's CLOSE."
  ;; Announce shutdown before taking the writer lock: its owner may be waiting
  ;; for window credit or a request reply that the peer will never send.
  (bt2:with-lock-held ((channel-state-lock channel))
    (setf (channel-closing-p channel) t)
    (when (and abort (not (channel-failure channel)))
      (setf (channel-failure channel)
            (make-condition 'channel-closed-error :channel channel)))
    (bt2:condition-broadcast (channel-state-condition channel)))
  (bt2:with-lock-held ((channel-write-lock channel))
    (unless abort
      (handler-case (%channel-send-eof-locked channel)
        ;; The peer may have closed while our EOF was still queued.
        (channel-closed-error () nil)))
    (%channel-send-close-locked channel))
  (unless abort
    (channel-wait-until channel #'channel-closed-p))
  (when (channel-closed-p channel) (%unregister-channel channel))
  t)

(defun %append-octets (destination octets)
  (loop for octet across octets
        do (vector-push-extend octet destination)))

(defun %maybe-adjust-window (channel)
  (let ((adjustment 0))
    (bt2:with-lock-held ((channel-state-lock channel))
      (when (and (not (or (channel-closing-p channel) (channel-close-p channel)
                         (channel-close-sent-p channel) (channel-failure channel)))
                 (plusp (channel-window-credit channel))
                 (or (zerop (channel-local-window channel))
                     (>= (channel-window-credit channel)
                         (max 1 (floor (channel-local-window-maximum channel) 2)))))
        (setf adjustment (min (channel-window-credit channel)
                              (- (channel-local-window-maximum channel)
                                 (channel-local-window channel))))
        (decf (channel-window-credit channel) adjustment)
        (incf (channel-local-window channel) adjustment)))
    (when (plusp adjustment)
      (handler-case
          (%send-channel-message
           channel +msg-channel-window-adjust+
           (lambda (buffer) (write-uint32 buffer adjustment)))
        ;; Reading has already consumed the bytes. A racing CLOSE must not
        ;; turn that successful read into an error and lose those bytes.
        (channel-closed-error () nil)))))

(defun %decode-description (octets)
  (handler-case
      (babel:octets-to-string octets :encoding :utf-8)
    (error () (format nil "~S" octets))))

(defun %reject-server-channel-open (connection buffer)
  (read-string* buffer)
  (let ((sender-channel (read-uint32 buffer))
        (reply (make-write-buffer)))
    (write-byte* reply +msg-channel-open-failure+)
    (write-uint32 reply sender-channel)
    (write-uint32 reply +open-administratively-prohibited+)
    (write-string* reply "server-initiated channels are not supported")
    (write-string* reply "")
    (%conn-send connection (buffer-to-octets reply))))

(defun %handle-open-confirmation (connection buffer)
  (let* ((recipient (read-uint32 buffer))
         (sender (read-uint32 buffer))
         (window (read-uint32 buffer))
         (max-packet (read-uint32 buffer))
         (channel (%find-channel connection recipient t)))
    (when (zerop max-packet)
      (error "Peer advertised a zero maximum packet size"))
    (bt2:with-lock-held ((channel-state-lock channel))
      (unless (eq (channel-open-state channel) :pending)
        (error "Duplicate channel open confirmation for ~D" recipient))
      (setf (channel-remote-id channel) sender
            (channel-remote-window channel) window
            (channel-max-packet channel) max-packet
            (channel-open-state channel) :open
            (channel-open-p channel) t)
      (bt2:condition-broadcast (channel-state-condition channel)))))

(defun %handle-open-failure (connection buffer)
  (let* ((recipient (read-uint32 buffer))
         (reason (read-uint32 buffer))
         (description (%decode-description (read-string* buffer)))
         (channel (%find-channel connection recipient t)))
    (read-string* buffer)
    (bt2:with-lock-held ((channel-state-lock channel))
      (setf (channel-open-state channel) :failed
            (channel-open-failure channel) (list reason description))
      (bt2:condition-broadcast (channel-state-condition channel)))))

(defun %handle-window-adjust (connection buffer)
  (let* ((recipient (read-uint32 buffer))
         (increment (read-uint32 buffer))
         (channel (%find-channel connection recipient t)))
    (when (zerop increment)
      (error "Peer sent a zero channel window adjustment"))
    (bt2:with-lock-held ((channel-state-lock channel))
      (when (> (+ (channel-remote-window channel) increment)
               +maximum-uint32+)
        (error "SSH channel window adjustment overflow"))
      (incf (channel-remote-window channel) increment)
      (bt2:condition-broadcast (channel-state-condition channel)))))

(defun %handle-channel-data (connection buffer extended-p)
  (let* ((recipient (read-uint32 buffer))
         (channel (%find-channel connection recipient t))
         (data-type (and extended-p (read-uint32 buffer)))
         (data (read-string* buffer)))
    (when (> (length data) (channel-local-max-packet channel))
      (error "Peer exceeded the channel maximum packet size"))
    (bt2:with-lock-held ((channel-state-lock channel))
      (when (> (length data) (channel-local-window channel))
        (error "Peer exceeded the SSH channel receive window"))
      (decf (channel-local-window channel) (length data))
      (cond
        ((not extended-p)
         (incf (channel-window-credit channel)
               (buffer-accept (channel-stdout-input channel) data)))
        ((= data-type +extended-data-stderr+)
         (incf (channel-window-credit channel)
               (buffer-accept (channel-stderr-input channel) data)))
        (t (incf (channel-window-credit channel) (length data))))
      (bt2:condition-broadcast (channel-state-condition channel)))
    (%maybe-adjust-window channel)))

(defun %handle-channel-eof (connection buffer)
  (let ((channel (%find-channel connection (read-uint32 buffer) t)))
    (bt2:with-lock-held ((channel-state-lock channel))
      (setf (channel-eof-p channel) t)
      (bt2:condition-broadcast (channel-state-condition channel)))))

(defun %handle-channel-close (connection buffer)
  (let* ((channel (%find-channel connection (read-uint32 buffer) t))
         (reply-p nil))
    (bt2:with-lock-held ((channel-state-lock channel))
      (setf (channel-close-p channel) t)
      (unless (or (channel-close-sent-p channel)
                  (channel-close-send-pending-p channel))
        (setf (channel-close-send-pending-p channel) t
              reply-p t))
      (bt2:condition-broadcast (channel-state-condition channel)))
    (when reply-p
      (handler-case
          (progn
            (%send-channel-message channel +msg-channel-close+)
            (bt2:with-lock-held ((channel-state-lock channel))
              (setf (channel-close-send-pending-p channel) nil
                    (channel-close-sent-p channel) t)
              (bt2:condition-broadcast (channel-state-condition channel))))
        (error (condition)
          (bt2:with-lock-held ((channel-state-lock channel))
            (setf (channel-close-send-pending-p channel) nil)
            (bt2:condition-broadcast (channel-state-condition channel)))
          (error condition))))
    (when (channel-closed-p channel)
      (%unregister-channel channel))))

(defun %handle-channel-request (connection buffer)
  (let* ((channel (%find-channel connection (read-uint32 buffer) t))
         (request-type (%decode-description (read-string* buffer)))
         (want-reply (not (zerop (read-byte* buffer))))
         (recognized-p nil))
    (cond
      ((string= request-type "exit-status")
       (let ((status (read-uint32 buffer)))
         (bt2:with-lock-held ((channel-state-lock channel))
           (setf (channel-exit-status channel) status)
           (bt2:condition-broadcast (channel-state-condition channel))))
       (setf recognized-p t))
      ((string= request-type "exit-signal")
       ;; The signal name, core-dump flag, message and language are informational.
       (read-string* buffer)
       (read-byte* buffer)
       (read-string* buffer)
       (read-string* buffer)
       (bt2:with-lock-held ((channel-state-lock channel))
         (setf (channel-exit-status channel) 128)
         (bt2:condition-broadcast (channel-state-condition channel)))
       (setf recognized-p t)))
    (when want-reply
      (%send-channel-message channel
                             (if recognized-p
                                 +msg-channel-success+
                                 +msg-channel-failure+)))))

(defun %handle-channel-reply (connection buffer success-p)
  (let ((channel (%find-channel connection (read-uint32 buffer) t)))
    (bt2:with-lock-held ((channel-state-lock channel))
      (unless (eq (channel-request-state channel) :pending)
        ;; Closing cancels a request waiter before a valid in-flight reply may
        ;; reach us. Keep that reply local to this closing channel.
        (when (channel-closing-p channel)
          (return-from %handle-channel-reply nil))
        (error "Unexpected channel request reply for ~D"
               (channel-local-id channel)))
      (setf (channel-request-state channel)
            (if success-p :success :failure))
      (bt2:condition-broadcast (channel-state-condition channel)))))

(defun %handle-packet (connection packet)
  (let* ((buffer (make-read-buffer packet))
         (message (read-byte* buffer)))
    (case message
      (#.+msg-global-request+
       (read-string* buffer)
       (when (not (zerop (read-byte* buffer)))
         (let ((reply (make-write-buffer)))
           (write-byte* reply +msg-request-failure+)
           (%conn-send connection (buffer-to-octets reply))))
       t)
      (#.+msg-request-success+ t)
      (#.+msg-request-failure+ nil)
      (#.+msg-channel-open+
       (%reject-server-channel-open connection buffer)
       t)
      (#.+msg-channel-open-confirmation+
       (%handle-open-confirmation connection buffer)
       t)
      (#.+msg-channel-open-failure+
       (%handle-open-failure connection buffer)
       t)
      (#.+msg-channel-window-adjust+
       (%handle-window-adjust connection buffer)
       t)
      (#.+msg-channel-data+
       (%handle-channel-data connection buffer nil)
       t)
      (#.+msg-channel-extended-data+
       (%handle-channel-data connection buffer t)
       t)
      (#.+msg-channel-eof+
       (%handle-channel-eof connection buffer)
       t)
      (#.+msg-channel-close+
       (%handle-channel-close connection buffer)
       t)
      (#.+msg-channel-request+
       (%handle-channel-request connection buffer)
       t)
      (#.+msg-channel-success+
       (%handle-channel-reply connection buffer t)
       t)
      (#.+msg-channel-failure+
       (%handle-channel-reply connection buffer nil)
       t)
      (otherwise nil))))
