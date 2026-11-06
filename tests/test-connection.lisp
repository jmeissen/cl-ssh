;;;; Tests for ssh/connection channel byte handling.

(defpackage :ssh/tests/connection
  (:use :cl :parachute)
  (:import-from :ssh/tests #:octets)
  (:import-from :ssh/connection
                #:channel-send-data
                #:channel-stdout-buffer
                #:channel-stderr-buffer)
  (:import-from :ssh/buffer
                #:make-write-buffer
                #:make-read-buffer
                #:write-byte*
                #:write-uint32
                #:write-string*
                #:read-byte*
                #:read-uint32
                #:read-string*
                #:buffer-to-octets)
  (:import-from :ssh/constants
                #:+msg-channel-open+
                #:+msg-channel-open-confirmation+
                #:+msg-channel-open-failure+
                #:+msg-channel-window-adjust+
                #:+msg-channel-success+
                #:+msg-channel-data+
                #:+msg-channel-extended-data+
                #:+msg-channel-eof+
                #:+msg-channel-close+
                #:+extended-data-stderr+))

(in-package :ssh/tests/connection)

(define-test receive-window-is-released-by-consumption :parent (:ssh/tests ssh/tests)
  (let* ((conn (make-test-connection))
         (ch (add-test-channel conn
                               (ssh/connection::make-channel :connection conn :local-id 3
                                  :remote-id 7 :local-window 4 :local-window-maximum 4)))
         (sent nil)
         (original (symbol-function 'ssh/transport:transport-send)))
    (unwind-protect
         (progn
           (setf (symbol-function 'ssh/transport:transport-send)
                 (lambda (transport payload) (declare (ignore transport)) (push payload sent)))
           (ssh/connection::%handle-packet conn
             (build-channel-data-packet +msg-channel-data+ 3 (octets 1 2 3 4)))
           (false sent)
           (is = 0 (ssh/connection:channel-local-window ch))
           (let ((out (octets 0 0)))
             (ssh/connection::%channel-read ch out 0 2 nil t))
           (is = 2 (ssh/connection:channel-local-window ch))
           (is = 1 (length sent))
           (is equalp (octets 3 4) (channel-stdout-buffer ch)))
      (setf (symbol-function 'ssh/transport:transport-send) original))))

(defun add-test-channel (conn ch)
  (setf (gethash (ssh/connection:channel-local-id ch)
                 (ssh/connection::connection-channels conn))
        ch)
  ch)

(defun make-test-connection (&optional (transport (ssh/transport::make-transport)))
  (ssh/connection::%make-connection :transport transport))

(defun make-test-socket-pair ()
  (let ((listener nil)
        (client nil)
        (server nil))
    (unwind-protect
         (progn
           (setf listener
                 (usocket:socket-listen "127.0.0.1" 0
                                        :reuse-address t
                                        :element-type '(unsigned-byte 8))
                 client
                 (usocket:socket-connect "127.0.0.1"
                                         (usocket:get-local-port listener)
                                         :element-type '(unsigned-byte 8))
                 server
                 (usocket:socket-accept listener
                                        :element-type '(unsigned-byte 8)))
           (values client server))
      (when listener
        (ignore-errors (usocket:socket-close listener)))
      (unless (and client server)
        (when client (ignore-errors (usocket:socket-close client)))
        (when server (ignore-errors (usocket:socket-close server)))))))

(defun build-channel-data-packet (message-type local-id data &key data-type)
  (let ((buf (make-write-buffer)))
    (write-byte* buf message-type)
    (write-uint32 buf local-id)
    (when data-type
      (write-uint32 buf data-type))
    (write-string* buf data)
    (buffer-to-octets buf)))

(define-test channel-send-data-preserves-raw-bytes
  :parent (:ssh/tests ssh/tests)
  (let* ((transport (ssh/transport::make-transport))
         (conn (make-test-connection transport))
         (ch (ssh/connection::make-channel :connection conn
                                           :remote-id 7
                                           :remote-window 4
                                           :max-packet 4
                                           :open-p t))
         (raw (octets 0 #x80 #xff 10))
         (sent '())
         (original-send (symbol-function 'ssh/transport:transport-send)))
    (unwind-protect
         (progn
           (setf (symbol-function 'ssh/transport:transport-send)
                 (lambda (_transport payload)
                   (declare (ignore _transport))
                   (push payload sent)))
           (channel-send-data ch raw)
           (is = 1 (length sent))
           (let ((buf (make-read-buffer (first sent))))
             (is = +msg-channel-data+ (read-byte* buf))
             (is = 7 (read-uint32 buf))
             (is equalp raw (read-string* buf)))
           (is = 0 (ssh/connection::channel-remote-window ch)))
      (setf (symbol-function 'ssh/transport:transport-send) original-send))))

(define-test channel-receive-data-preserves-stdout-raw-bytes
  :parent (:ssh/tests ssh/tests)
  (let* ((conn (make-test-connection))
         (ch (add-test-channel conn
                               (ssh/connection::make-channel :local-id 3
                                                             :remote-id 7
                                                             :open-p t)))
         (initial-window (ssh/connection::channel-local-window ch))
         (raw (octets 0 #x80 #xff 10))
         (packet (build-channel-data-packet +msg-channel-data+ 3 raw)))
    (true (ssh/connection::%handle-packet conn packet))
    (is equalp raw (channel-stdout-buffer ch))
    (is = (- initial-window (length raw))
        (ssh/connection::channel-local-window ch))))

(define-test channel-receive-extended-data-preserves-stderr-raw-bytes
  :parent (:ssh/tests ssh/tests)
  (let* ((conn (make-test-connection))
         (ch (add-test-channel conn
                               (ssh/connection::make-channel :local-id 3
                                                             :remote-id 7
                                                             :open-p t)))
         (initial-window (ssh/connection::channel-local-window ch))
         (raw (octets #xff 0 #x80 10))
         (packet (build-channel-data-packet +msg-channel-extended-data+ 3 raw
                                            :data-type +extended-data-stderr+)))
    (true (ssh/connection::%handle-packet conn packet))
    (is equalp raw (channel-stderr-buffer ch))
    (is = (- initial-window (length raw))
        (ssh/connection::channel-local-window ch))))

(define-test interleaved-channel-data-is-routed-by-recipient-id
  :parent (:ssh/tests ssh/tests)
  (let* ((conn (make-test-connection))
         (first (add-test-channel conn
                                  (ssh/connection::make-channel :local-id 3
                                                                :remote-id 30
                                                                :open-p t)))
         (second (add-test-channel conn
                                   (ssh/connection::make-channel :local-id 4
                                                                 :remote-id 40
                                                                 :open-p t))))
    (ssh/connection::%handle-packet
     conn (build-channel-data-packet +msg-channel-data+ 4 (octets 4 4)))
    (ssh/connection::%handle-packet
     conn (build-channel-data-packet +msg-channel-data+ 3 (octets 3 3 3)))
    (is equalp (octets 3 3 3) (channel-stdout-buffer first))
    (is equalp (octets 4 4) (channel-stdout-buffer second))))

(define-test channel-confirmations-and-request-replies-are-isolated
  :parent (:ssh/tests ssh/tests)
  (let* ((conn (make-test-connection))
         (first (add-test-channel conn (ssh/connection::make-channel :local-id 1)))
         (second (add-test-channel conn (ssh/connection::make-channel :local-id 2)))
         (confirmation (make-write-buffer))
         (success (make-write-buffer)))
    (write-byte* confirmation +msg-channel-open-confirmation+)
    (write-uint32 confirmation 2)
    (write-uint32 confirmation 22)
    (write-uint32 confirmation 4096)
    (write-uint32 confirmation 1024)
    (ssh/connection::%handle-packet conn (buffer-to-octets confirmation))
    (false (ssh/connection:channel-open-p first))
    (true (ssh/connection:channel-open-p second))
    (is = 22 (ssh/connection:channel-remote-id second))
    (setf (ssh/connection::channel-request-state first) :pending
          (ssh/connection::channel-request-state second) :pending)
    (write-byte* success +msg-channel-success+)
    (write-uint32 success 1)
    (ssh/connection::%handle-packet conn (buffer-to-octets success))
    (is eq :success (ssh/connection::channel-request-state first))
    (is eq :pending (ssh/connection::channel-request-state second))))

(define-test channel-open-failure-is-routed-and-preserves-reason
  :parent (:ssh/tests ssh/tests)
  (let* ((conn (make-test-connection))
         (channel (add-test-channel
                   conn
                   (ssh/connection::make-channel :connection conn
                                                  :local-id 6)))
         (failure (make-write-buffer)))
    (write-byte* failure +msg-channel-open-failure+)
    (write-uint32 failure 6)
    (write-uint32 failure 2)
    (write-string* failure "channel type unavailable")
    (write-string* failure "")
    (ssh/connection::%handle-packet conn (buffer-to-octets failure))
    (is eq :failed (ssh/connection::channel-open-state channel))
    (is = 2 (first (ssh/connection::channel-open-failure channel)))
    (is string= "channel type unavailable"
        (second (ssh/connection::channel-open-failure channel)))))

(define-test remote-window-adjust-wakes-a-blocked-writer
  :parent (:ssh/tests ssh/tests)
  (let* ((conn (make-test-connection))
         (channel (add-test-channel
                   conn
                   (ssh/connection::make-channel :connection conn
                                                  :local-id 8
                                                  :remote-id 80
                                                  :remote-window 0
                                                  :max-packet 8
                                                  :open-p t)))
         (sent nil)
         (original-send (symbol-function 'ssh/transport:transport-send))
         (writer nil))
    (unwind-protect
         (progn
           (setf (symbol-function 'ssh/transport:transport-send)
                 (lambda (_transport payload)
                   (declare (ignore _transport))
                   (setf sent payload)))
           (setf writer
                 (bt2:make-thread
                  (lambda ()
                    (channel-send-data channel (octets 5 6 7)))))
           (let ((adjust (make-write-buffer)))
             (write-byte* adjust +msg-channel-window-adjust+)
             (write-uint32 adjust 8)
             (write-uint32 adjust 3)
             (ssh/connection::%handle-packet conn (buffer-to-octets adjust)))
           (bt2:join-thread writer)
           (true sent)
           (is = 0 (ssh/connection::channel-remote-window channel)))
      (setf (symbol-function 'ssh/transport:transport-send) original-send))))

(define-test connection-failure-wakes-all-channels-and-cleans-registry
  :parent (:ssh/tests ssh/tests)
  (let* ((conn (make-test-connection))
         (first (add-test-channel
                 conn
                 (ssh/connection::make-channel :connection conn :local-id 1)))
         (second (add-test-channel
                  conn
                  (ssh/connection::make-channel :connection conn :local-id 2)))
         (first-error nil)
         (second-error nil)
         (first-waiter
           (bt2:make-thread
            (lambda ()
              (setf first-error
                    (handler-case
                        (progn
                          (ssh/connection:channel-wait-until
                           first #'ssh/connection:channel-open-p)
                          nil)
                      (error (condition) condition))))))
         (second-waiter
           (bt2:make-thread
            (lambda ()
              (setf second-error
                    (handler-case
                        (progn
                          (ssh/connection:channel-wait-until
                           second #'ssh/connection:channel-open-p)
                          nil)
                      (error (condition) condition)))))))
    (ssh/connection::%fail-connection conn "test disconnect")
    (bt2:join-thread first-waiter)
    (bt2:join-thread second-waiter)
    (of-type 'ssh/connection:connection-error first-error)
    (of-type 'ssh/connection:connection-error second-error)
    (is = 0 (hash-table-count (ssh/connection::connection-channels conn)))))

(define-test concurrent-close-preserves-eof-close-order-and-cleans-channel
  :parent (:ssh/tests ssh/tests)
  (let* ((conn (make-test-connection))
         (channel (add-test-channel
                   conn
                   (ssh/connection::make-channel :connection conn
                                                  :local-id 10
                                                  :remote-id 100
                                                  :open-p t)))
         (gate (bt2:make-lock :name "channel close test"))
         (changed (bt2:make-condition-variable :name "channel close test"))
         (sent nil)
         (original-send (symbol-function 'ssh/transport:transport-send))
         (closer nil))
    (unwind-protect
         (progn
           (setf (symbol-function 'ssh/transport:transport-send)
                 (lambda (_transport payload)
                   (declare (ignore _transport))
                   (bt2:with-lock-held (gate)
                     (setf sent (nconc sent (list payload)))
                     (bt2:condition-broadcast changed))))
           (setf closer
                 (bt2:make-thread
                  (lambda () (ssh/connection:channel-close channel))))
           (bt2:with-lock-held (gate)
             (loop until (= (length sent) 2)
                   do (bt2:condition-wait changed gate)))
           (let ((remote-close (make-write-buffer)))
             (write-byte* remote-close +msg-channel-close+)
             (write-uint32 remote-close 10)
             (ssh/connection::%handle-packet
              conn (buffer-to-octets remote-close)))
           (bt2:join-thread closer)
           (is equal (list +msg-channel-eof+ +msg-channel-close+)
               (mapcar (lambda (payload) (aref payload 0)) sent))
           (is = 0 (hash-table-count
                    (ssh/connection::connection-channels conn))))
      (setf (symbol-function 'ssh/transport:transport-send) original-send))))

(define-test channel-state-waiters-wake-without-polling
  :parent (:ssh/tests ssh/tests)
  (let* ((channel (ssh/connection::make-channel))
         (result nil)
         (thread (bt2:make-thread
                  (lambda ()
                    (setf result
                          (ssh/connection::channel-wait-until
                           channel #'ssh/connection:channel-open-p))))))
    (bt2:with-lock-held ((ssh/connection::channel-state-lock channel))
      (setf (ssh/connection::channel-open-p channel) t)
      (bt2:condition-broadcast (ssh/connection::channel-state-condition channel)))
    (bt2:join-thread thread)
    (true result)))

(define-test server-initiated-channel-open-is-rejected
  :parent (:ssh/tests ssh/tests)
  (let* ((conn (make-test-connection))
         (packet (make-write-buffer))
         (sent nil)
         (original-send (symbol-function 'ssh/transport:transport-send)))
    (write-byte* packet +msg-channel-open+)
    (write-string* packet "session")
    (write-uint32 packet 91)
    (write-uint32 packet 4096)
    (write-uint32 packet 1024)
    (unwind-protect
         (progn
           (setf (symbol-function 'ssh/transport:transport-send)
                 (lambda (_transport payload)
                   (declare (ignore _transport))
                   (setf sent payload)))
           (true (ssh/connection::%handle-packet conn (buffer-to-octets packet)))
           (let ((reply (make-read-buffer sent)))
             (is = ssh/constants:+msg-channel-open-failure+ (read-byte* reply))
             (is = 91 (read-uint32 reply))))
      (setf (symbol-function 'ssh/transport:transport-send) original-send))))

(define-test dispatcher-waits-for-events-and-routes-channel-lifecycle
  :parent (:ssh/tests ssh/tests)
  (multiple-value-bind (client-socket server-socket)
      (make-test-socket-pair)
    (let* ((client-packets
             (ssh/packet:make-packet-stream
              (usocket:socket-stream client-socket)))
           (server-packets
             (ssh/packet:make-packet-stream
              (usocket:socket-stream server-socket)))
           (transport (ssh/transport::make-transport
                       :socket client-socket
                       :packet-stream client-packets))
           (connection (ssh/connection:make-connection transport))
           (server-thread nil)
           (server-open-type nil)
           (server-close-type nil))
      (unwind-protect
           (progn
             (setf server-thread
                   (bt2:make-thread
                    (lambda ()
                      (let* ((open-packet (ssh/packet:recv-packet server-packets))
                             (open-buffer (make-read-buffer open-packet)))
                        (setf server-open-type (read-byte* open-buffer))
                        (read-string* open-buffer)
                        (let ((local-id (read-uint32 open-buffer)))
                          (let ((confirmation (make-write-buffer)))
                            (write-byte* confirmation +msg-channel-open-confirmation+)
                            (write-uint32 confirmation local-id)
                            (write-uint32 confirmation 71)
                            (write-uint32 confirmation 4096)
                            (write-uint32 confirmation 1024)
                            (ssh/packet:send-packet
                             server-packets (buffer-to-octets confirmation)))
                          (ssh/packet:send-packet
                           server-packets
                           (build-channel-data-packet
                            +msg-channel-data+ local-id (octets 9 8 7)))
                          (dolist (message (list +msg-channel-eof+
                                                 +msg-channel-close+))
                            (let ((packet (make-write-buffer)))
                              (write-byte* packet message)
                              (write-uint32 packet local-id)
                              (ssh/packet:send-packet
                               server-packets (buffer-to-octets packet))))
                          (let ((close-reply
                                  (ssh/packet:recv-packet server-packets)))
                            (setf server-close-type (aref close-reply 0))))))))
             (let ((channel (ssh/connection:open-channel connection)))
               (ssh/connection:channel-wait-until
                channel #'ssh/connection:channel-close-p)
               (is equalp (octets 9 8 7)
                   (channel-stdout-buffer channel)))
             (bt2:join-thread server-thread)
             (is = +msg-channel-open+ server-open-type)
             (is = +msg-channel-close+ server-close-type))
        (ignore-errors (ssh/connection:connection-close connection))
        (ignore-errors (usocket:socket-close server-socket))))))

(defun dispatcher-control-message-progress (control-packet)
  (multiple-value-bind (client-socket server-socket)
      (make-test-socket-pair)
    (let* ((client-packets (ssh/packet:make-packet-stream
                            (usocket:socket-stream client-socket)))
           (server-packets (ssh/packet:make-packet-stream
                            (usocket:socket-stream server-socket)))
           (transport (ssh/transport::make-transport
                       :socket client-socket :packet-stream client-packets))
           (original-recv (symbol-function 'ssh/packet:recv-packet))
           (gate (bt2:make-lock :name "control packet received"))
           (changed (bt2:make-condition-variable :name "control packet received"))
           (received-p nil)
           (connection nil)
           (outbound (octets ssh/constants:+msg-request-failure+)))
      (labels ((wait-for (predicate lock condition)
                 (bt2:with-lock-held (lock)
                   (loop until (funcall predicate)
                         do (unless (bt2:condition-wait condition lock :timeout 2)
                              (return (funcall predicate)))
                         finally (return t))))
               (submit (action)
                 (ssh/connection::%enqueue-action connection action)
                 (and (wait-for
                       (lambda () (ssh/connection::connection-action-done-p action))
                       (ssh/connection::connection-action-lock action)
                       (ssh/connection::connection-action-condition action))
                      (null (ssh/connection::connection-action-error action)))))
        (unwind-protect
             (progn
               ;; Observe receipt before queueing work, so the ignored message
               ;; is guaranteed to precede the outgoing action.
               ;; Hook the cross-file packet call: ECL can bind the transport's
               ;; same-file RECV-TRANSPORT-PACKET call directly at compile time.
               (setf (symbol-function 'ssh/packet:recv-packet)
                     (lambda (candidate)
                       (let ((packet (funcall original-recv candidate)))
                         (when (eq candidate client-packets)
                           (bt2:with-lock-held (gate)
                             (setf received-p t)
                             (bt2:condition-broadcast changed)))
                         packet)))
               (ssh/packet:send-packet server-packets control-packet)
               (setf connection (ssh/connection:make-connection transport))
               (let* ((received (wait-for (lambda () received-p) gate changed))
                      (sent (and received
                                 (submit (ssh/connection::make-connection-action
                                          :send :payload outbound))))
                      (closed (and sent
                                   (submit (ssh/connection::make-connection-action
                                            :disconnect)))))
                 (values received sent closed
                         (when (and sent closed)
                           (list (ssh/packet:recv-packet server-packets)
                                 (aref (ssh/packet:recv-packet server-packets) 0))))))
          ;; Closing the peer also releases a dispatcher blocked by a regression,
          ;; allowing the failure to be reported instead of hanging the suite.
          (ignore-errors (usocket:socket-close server-socket))
          (when connection
            (bt2:join-thread (ssh/connection::connection-dispatcher-thread connection)))
          (setf (symbol-function 'ssh/packet:recv-packet) original-recv)
          (ignore-errors (usocket:socket-close client-socket)))))))

(define-test dispatcher-remains-responsive-after-ignore-and-debug
  :parent (:ssh/tests ssh/tests)
  (dolist (message (list ssh/constants:+msg-ignore+ ssh/constants:+msg-debug+))
    (let ((packet (make-write-buffer)))
      (write-byte* packet message)
      (when (= message ssh/constants:+msg-debug+)
        (write-byte* packet 0))
      (write-string* packet "idle server")
      (when (= message ssh/constants:+msg-debug+)
        (write-string* packet ""))
      (multiple-value-bind (received sent closed packets)
          (dispatcher-control-message-progress (buffer-to-octets packet))
        (true received)
        (true sent)
        (true closed)
        (is equalp (list (octets ssh/constants:+msg-request-failure+)
                        ssh/constants:+msg-disconnect+)
            packets)))))
