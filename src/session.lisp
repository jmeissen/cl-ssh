;;;; SSH session channels and concurrent Gray streams — RFC 4254 section 6.

(uiop:define-package #:ssh/session
  (:use #:cl #:trivial-gray-streams)
  (:import-from #:ssh/constants
                #:+channel-session+
                #:+request-exec+
                #:+request-shell+
                #:+request-subsystem+
                #:+request-pty+
                #:+request-env+)
  (:import-from #:ssh/buffer
                #:write-uint32
                #:write-string*)
  (:import-from #:ssh/connection
                #:connection
                #:channel
                #:channel-open-p
                #:channel-eof-p
                #:channel-close-p
                #:channel-stdout-buffer
                #:channel-stderr-buffer
                #:channel-exit-status
                #:channel-failure
                #:channel-state-lock
                #:channel-state-condition
                #:channel-read-lock
                #:open-channel
                #:channel-send-data
                #:channel-close
                #:channel-request
                #:channel-wait-until
                #:connection-error)
  (:export
   #:run-command
   #:ssh-channel-stream
   #:ssh-channel-stream-channel
   #:open-shell
   #:shell-write-line
   #:shell-read-line
   #:shell-read-until
   #:open-subsystem
   #:send-env
   #:shell-stream-closed))

(in-package #:ssh/session)

(defclass ssh-channel-input-stream (fundamental-binary-input-stream)
  ((connection :initarg :connection :reader ssh-channel-stream-connection)
   (channel :initarg :channel :reader ssh-channel-stream-channel)
   (stderr-p :initarg :stderr-p :initform nil :reader %stream-stderr-p)
   (byte-buffer :initform (make-array 1 :element-type '(unsigned-byte 8)))))

(defclass ssh-channel-stream (ssh-channel-input-stream fundamental-binary-output-stream)
  ()
  (:documentation "A full-duplex SSH channel stream with one reader and one writer."))

(define-condition shell-stream-closed (end-of-file)
  ((stream :initarg :stream :reader shell-stream-closed-stream)
   (cause :initarg :cause :initform nil :reader shell-stream-closed-cause))
  (:report (lambda (condition output)
             (format output "SSH shell stream closed: ~S"
                     (shell-stream-closed-stream condition)))))

(defun %stream-read-lock (stream)
  (if (%stream-stderr-p stream)
      (ssh/connection:channel-stderr-read-lock (ssh-channel-stream-channel stream))
      (channel-read-lock (ssh-channel-stream-channel stream))))

(defun %stream-read-locked (stream sequence start end block-p)
  (unless (open-stream-p stream)
    (error 'shell-stream-closed :stream stream))
  (multiple-value-bind (count status cause)
      (ssh/connection::%channel-read (ssh-channel-stream-channel stream)
                                    sequence start end (%stream-stderr-p stream) block-p)
    (when (member status '(:closed :failed))
      (error 'shell-stream-closed :stream stream :cause cause))
    (values count status)))

(defun %shell-stream-next-byte-locked (stream &key (block-p t))
  (let ((buffer (slot-value stream 'byte-buffer)))
    (multiple-value-bind (count status) (%stream-read-locked stream buffer 0 1 block-p)
      (if (plusp count) (values (aref buffer 0) :byte) (values nil status)))))

(defun %shell-read-collect-locked (stream stop-predicate finalize-fn block-p)
  (let ((octets (make-array 128 :element-type '(unsigned-byte 8)
                                :adjustable t
                                :fill-pointer 0)))
    (labels ((finish (status)
               (funcall finalize-fn octets status)))
      (handler-case
          (loop
            (multiple-value-bind (byte status)
                (%shell-stream-next-byte-locked stream :block-p block-p)
              (case status
                (:byte
                 (vector-push-extend byte octets)
                 (when (funcall stop-predicate octets byte)
                   (return (finish :found))))
                (:eof (return (finish :eof)))
                (:blocked (return (finish :blocked))))))
        (shell-stream-closed (condition)
          (if (plusp (length octets))
              (finish :closed)
              (error condition)))))))

(defun %shell-read-collect (stream stop-predicate finalize-fn &key (block-p t))
  (bt2:with-lock-held ((%stream-read-lock stream))
    (%shell-read-collect-locked stream stop-predicate finalize-fn block-p)))

(defmethod stream-read-byte ((stream ssh-channel-input-stream))
  (bt2:with-lock-held ((%stream-read-lock stream))
    (multiple-value-bind (byte status)
        (%shell-stream-next-byte-locked stream)
      (if (eq status :eof) :eof byte))))

(defmethod stream-listen ((stream ssh-channel-input-stream))
  (let ((channel (ssh-channel-stream-channel stream)))
    (bt2:with-lock-held ((channel-state-lock channel))
      (plusp (ssh/channel-buffer:input-buffer-count
              (ssh/connection::%channel-input channel (%stream-stderr-p stream)))))))

(defmethod stream-read-sequence ((stream ssh-channel-input-stream) sequence start end
                                 &key &allow-other-keys)
  (bt2:with-lock-held ((%stream-read-lock stream))
    (loop with index = start
          while (< index end)
          do (multiple-value-bind (count status)
                 (%stream-read-locked stream sequence index end t)
               (incf index count)
               (when (eq status :eof) (return index)))
          finally (return index))))

(defmethod stream-write-byte ((stream ssh-channel-stream) byte)
  (channel-send-data
   (ssh-channel-stream-channel stream)
   (make-array 1 :element-type '(unsigned-byte 8) :initial-element byte))
  byte)

(defmethod stream-write-sequence ((stream ssh-channel-stream) sequence start end
                                  &key &allow-other-keys)
  (let ((data (if (and (typep sequence '(vector (unsigned-byte 8)))
                       (= start 0)
                       (= end (length sequence)))
                  sequence
                  (let ((copy (make-array (- end start)
                                          :element-type '(unsigned-byte 8))))
                    (replace copy sequence :start2 start :end2 end)
                    copy))))
    (channel-send-data (ssh-channel-stream-channel stream) data))
  sequence)

(defmethod close ((stream ssh-channel-input-stream) &key abort)
  (when (open-stream-p stream)
    (if (%stream-stderr-p stream)
        (let ((channel (ssh-channel-stream-channel stream)))
          (bt2:with-lock-held ((channel-state-lock channel))
            (let* ((old (ssh/connection::channel-stderr-input channel))
                   (tail (ssh/channel-buffer:make-input-buffer :mode :tail)))
              (when (eq (ssh/channel-buffer:input-buffer-mode old) :stream)
                (incf (ssh/connection::channel-window-credit channel)
                      (ssh/channel-buffer:input-buffer-count old)))
              (ssh/channel-buffer:buffer-accept tail (ssh/channel-buffer:buffer-snapshot old))
              (setf (ssh/connection::channel-stderr-input channel) tail
                    (ssh/connection::channel-stderr-closed-p channel) t)
              (bt2:condition-broadcast (channel-state-condition channel))))
          (when (channel-connection-present-p channel)
            (ssh/connection::%maybe-adjust-window channel)))
        (ignore-errors (channel-close (ssh-channel-stream-channel stream) :abort abort))))
  (call-next-method))

(defun channel-connection-present-p (channel)
  (and (ssh/connection:channel-connection channel) (not (channel-close-p channel))))

(defun %string-to-octets (string)
  (ssh/buffer:utf-8-to-octets string))

(defun %octets-to-string (octets &key (start 0) end)
  (babel:octets-to-string (subseq octets start end) :encoding :utf-8))

(defun shell-write-line (stream line)
  "Write a UTF-8 line to an interactive SSH shell.
STREAM is the bidirectional stream returned by OPEN-SHELL.
LINE is the text written before a newline.
Returns LINE."
  (write-sequence (%string-to-octets line) stream)
  (write-byte 10 stream)
  (force-output stream)
  line)

(defun shell-read-line (stream &key (error-p t) (block-p t))
  "Read one newline-terminated UTF-8 line from an SSH shell.
STREAM is the bidirectional stream returned by OPEN-SHELL.
ERROR-P controls whether clean EOF and CLOSE signal conditions.
BLOCK-P controls whether the reader waits for more channel state.
Returns the accumulated string and one of :FOUND, :BLOCKED, :EOF, or :CLOSED."
  (%shell-read-collect
   stream
   (lambda (octets byte)
     (declare (ignore octets))
     (= byte 10))
   (lambda (octets status)
     (let* ((end (length octets))
            (line-end (if (and (plusp end)
                               (= (aref octets (1- end)) 10))
                          (1- end)
                          end)))
       (when (and (plusp line-end)
                  (= (aref octets (1- line-end)) 13))
         (decf line-end))
       (let ((string (%octets-to-string octets :end line-end)))
         (case status
           ((:found :blocked) (values string status))
           ((:eof :closed)
            (if error-p
                (error (if (eq status :eof)
                           'end-of-file
                           'shell-stream-closed)
                       :stream stream)
                (values string status)))
           (otherwise (error "Unknown shell read status ~S" status))))))
   :block-p block-p))

(defun shell-read-until (stream marker &key include-marker (error-p t) (block-p t))
  "Read UTF-8 shell output until a marker is seen.
STREAM is the bidirectional stream returned by OPEN-SHELL.
MARKER is a string delimiter, or NIL to read until another terminal state.
INCLUDE-MARKER controls whether a found marker remains in the returned text.
ERROR-P controls whether clean EOF and CLOSE signal conditions.
BLOCK-P controls whether the reader waits for more channel state.
Returns the accumulated string and one of :FOUND, :BLOCKED, :EOF, or :CLOSED."
  (let* ((marker-octets (and marker (%string-to-octets marker)))
         (marker-length (length marker-octets)))
    (when (and marker (zerop marker-length))
      (error "MARKER must not be empty"))
    (%shell-read-collect
     stream
     (lambda (octets byte)
       (declare (ignore byte))
       (and marker
            (let ((start (- (length octets) marker-length)))
              (and (>= start 0)
                   (loop for index below marker-length
                         always (= (aref octets (+ start index))
                                   (aref marker-octets index)))))))
     (lambda (octets status)
       (let* ((end (length octets))
              (string
                (if (and (eq status :found) marker (not include-marker))
                    (%octets-to-string octets :end (- end marker-length))
                    (%octets-to-string octets :end end))))
         (case status
           ((:found :blocked) (values string status))
           ((:eof :closed)
            (if error-p
                (error (if (eq status :eof)
                           'end-of-file
                           'shell-stream-closed)
                       :stream stream)
                (values string status)))
           (otherwise (error "Unknown shell read status ~S" status)))))
     :block-p block-p)))

(defun request-pty (channel &key (term "xterm") (cols 80) (rows 24)
                                  (width-px 0) (height-px 0))
  (channel-request
   channel +request-pty+
   :data-writer
   (lambda (buffer)
     (write-string* buffer term)
     (write-uint32 buffer cols)
     (write-uint32 buffer rows)
     (write-uint32 buffer width-px)
     (write-uint32 buffer height-px)
     (write-string* buffer (make-array 0 :element-type '(unsigned-byte 8))))))

(defun send-env (channel name value)
  "Send an environment variable request on an SSH channel.
CHANNEL is the session channel receiving the request.
NAME is the environment variable name.
VALUE is the environment variable value.
Returns true after the request is queued for delivery."
  (channel-request channel +request-env+
                   :want-reply nil
                   :data-writer
                   (lambda (buffer)
                     (write-string* buffer name)
                     (write-string* buffer value))))

(defun run-command (connection command &key environment)
  "Execute a command on a new channel of a multiplexed connection.
CONNECTION is the authenticated shared connection.
COMMAND is the command string passed to the server.
ENVIRONMENT is an association list of variable names and values.
Returns stdout text, stderr text, and the remote exit status."
  (let ((channel (open-channel connection :type +channel-session+ :capture-output t)))
    (unwind-protect
         (progn
           (dolist (pair environment) (send-env channel (car pair) (cdr pair)))
           (unless (channel-request channel +request-exec+
                                    :data-writer (lambda (buffer) (write-string* buffer command)))
             (error 'connection-error :reason "server rejected exec request"))
           (channel-wait-until channel #'channel-close-p)
           (values (%octets-to-string (channel-stdout-buffer channel))
                   (%octets-to-string (channel-stderr-buffer channel))
                   (or (channel-exit-status channel) 0)))
      ;; This private channel is never transferred to the caller. Do not wait
      ;; for a peer acknowledgement while unwinding an unrelated error.
      (ignore-errors (channel-close channel :abort t)))))

(defun %channel-streams (connection channel)
  (values (make-instance 'ssh-channel-stream :connection connection :channel channel)
          channel
          (make-instance 'ssh-channel-input-stream :connection connection
                         :channel channel :stderr-p t)))

(defun open-shell (connection &key pty (pty-term "xterm") (pty-cols 80) (pty-rows 24)
                                   environment capture-output)
  "Open a full-duplex interactive shell on a multiplexed connection.
CONNECTION is the authenticated shared connection.
PTY controls whether a pseudo-terminal is requested.
PTY-TERM is the terminal type name.
PTY-COLS and PTY-ROWS are the initial terminal dimensions.
ENVIRONMENT is an association list of variable names and values.
CAPTURE-OUTPUT retains full output history instead of bounding unread stream data.
Returns a bidirectional stdout stream, its channel, and a stderr input stream."
  (let ((channel (open-channel connection :type +channel-session+ :capture-output capture-output))
        (transferred-p nil))
    (unwind-protect
         (multiple-value-prog1
             (progn
               (dolist (pair environment) (send-env channel (car pair) (cdr pair)))
               (when pty
                 (unless (request-pty channel :term pty-term :cols pty-cols :rows pty-rows)
                   (error 'connection-error :reason "server rejected pty-req")))
               (unless (channel-request channel +request-shell+)
                 (error 'connection-error :reason "server rejected shell request"))
               (%channel-streams connection channel))
           (setf transferred-p t))
      (unless transferred-p (ignore-errors (channel-close channel :abort t))))))

(defun open-subsystem (connection subsystem-name &key capture-output stderr-tail)
  "Open a full-duplex subsystem channel on a multiplexed connection.
CONNECTION is the authenticated shared connection.
SUBSYSTEM-NAME is the remote subsystem name, such as sftp.
CAPTURE-OUTPUT retains full output history instead of bounding unread stream data.
STDERR-TAIL selects an internal bounded diagnostic sink for protocol consumers.
Returns a bidirectional stdout stream, its channel, and a stderr input stream."
  (let ((channel (open-channel connection :type +channel-session+
                              :capture-output capture-output :stderr-tail stderr-tail))
        (transferred-p nil))
    (unwind-protect
         (multiple-value-prog1
             (progn
               (unless (channel-request channel +request-subsystem+
                                        :data-writer (lambda (buffer)
                                                       (write-string* buffer subsystem-name)))
                 (error 'connection-error
                        :reason (format nil "server rejected subsystem ~S" subsystem-name)))
               (%channel-streams connection channel))
           (setf transferred-p t))
      (unless transferred-p (ignore-errors (channel-close channel :abort t))))))
