;;;; SSH session channel — RFC 4254 §6.
;;;;
;;;; Provides:
;;;;   RUN-COMMAND   — exec a command, capture stdout/stderr, return exit status
;;;;   OPEN-SHELL    — request a PTY + shell; return Gray stream wrappers
;;;;   OPEN-SUBSYSTEM — open a subsystem (e.g. "sftp"); return Gray streams
;;;;
;;;; Gray streams (trivial-gray-streams) expose channels as CL streams so
;;;; callers can use READ-BYTE, WRITE-BYTE, READ-SEQUENCE, WRITE-SEQUENCE, etc.

(uiop:define-package ssh/session
  (:use #:cl #:trivial-gray-streams)
  (:import-from #:ssh/constants
                #:+channel-session+
                #:+request-exec+
                #:+request-shell+
                #:+request-subsystem+
                #:+request-pty+
                #:+request-env+)
  (:import-from #:ssh/buffer
                #:make-write-buffer #:write-byte* #:write-boolean #:write-uint32
                #:write-string* #:buffer-to-octets)
  (:import-from #:ssh/connection
                #:connection #:make-connection #:channel
                #:channel-local-id
                #:channel-open-p #:channel-eof-p #:channel-close-p
                #:channel-stdout-buffer #:channel-stderr-buffer #:channel-exit-status
                #:open-channel #:channel-send-data #:channel-send-eof #:channel-close
                #:channel-request #:channel-dispatch-until
                #:connection-error)
  (:import-from #:ssh/packet
                #:ssh-protocol-error)
  (:export
   ;; Blocking exec
   #:run-command
   ;; Gray stream session
   #:ssh-channel-stream
   #:ssh-channel-stream-channel
   #:open-shell
   #:shell-write-line
   #:shell-read-line
   #:shell-read-until
   #:open-subsystem
   ;; Env variable helper
   #:send-env
   ;; Shell stream condition
   #:shell-stream-closed))

(in-package #:ssh/session)

;;;; Gray stream wrapper

(defclass ssh-channel-stream (fundamental-binary-input-stream
                              fundamental-binary-output-stream)
  ((connection :initarg :connection :reader ssh-channel-stream-connection)
   (channel    :initarg :channel    :reader ssh-channel-stream-channel)
   ;; Read position within the channel's stdout-buffer
   (read-pos   :initform 0))
  (:documentation "A Gray stream that maps a session channel to CL I/O.
   Reading pulls from the channel's stdout-buffer (blocking as needed).
   Writing sends SSH_MSG_CHANNEL_DATA."))

(define-condition shell-stream-closed (end-of-file)
  ((stream :initarg :stream :reader shell-stream-closed-stream))
  (:report (lambda (condition stream)
             (format stream "SSH shell stream closed: ~S"
                     (shell-stream-closed-stream condition)))))

(defun %shell-stream-next-byte (stream &key (block-p t))
  "Get the next byte from STREAM.

BLOCK-P determines whether the stream reading blocks to wait for the next byte.

Signals SHELL-STREAM-CLOSED upon SSH_MSG_CHANNEL_CLOSE and other transport errors.

Returns two values: the byte (when available) and a status keyword - being one of
:BYTE, :EOF, or :BLOCKED."
  (let ((conn (ssh-channel-stream-connection stream))
        (ch   (ssh-channel-stream-channel stream)))
    (labels ((buffered-byte ()
               (let* ((buf (channel-stdout-buffer ch))
                      (pos (slot-value stream 'read-pos)))
                 (when (< pos (length buf))
                   (incf (slot-value stream 'read-pos))
                   (values (aref buf pos) t))))
             (blocking-pump ()
               (handler-case
                   (channel-dispatch-until conn
                                           (lambda (pkt)
                                             (let ((type (aref pkt 0)))
                                               (or (and (= type
                                                           ssh/constants:+msg-channel-data+)
                                                        (%pkt-for-channel-p pkt ch))
                                                   (and (= type
                                                           ssh/constants:+msg-channel-eof+)
                                                        (%pkt-for-channel-p pkt ch))
                                                   (and (= type
                                                           ssh/constants:+msg-channel-close+)
                                                        (%pkt-for-channel-p pkt ch))))))
                 (error ()
                   (error 'shell-stream-closed :stream stream)))))
      (loop
        (multiple-value-bind (byte present-p)
            (buffered-byte)
          (when present-p
            (return (values byte :byte))))
        (cond
          ((channel-close-p ch)
           (error 'shell-stream-closed :stream stream))
          ((channel-eof-p ch)
           (return (values nil :eof)))
          (block-p
           (blocking-pump))
          ((stream-listen stream)
           nil)
          (t
           (return (values nil :blocked))))))))

(defun %shell-read-collect (stream stop-predicate finalize-fn &key (block-p t))
  (let ((octets (make-array 128 :element-type '(unsigned-byte 8)
                                :adjustable t
                                :fill-pointer 0)))
    (labels ((finish (status)
               (funcall finalize-fn octets status)))
      (handler-case
          (loop
            (multiple-value-bind (byte status)
                (%shell-stream-next-byte stream :block-p block-p)
              (case status
                (:byte
                 (vector-push-extend byte octets)
                 (when (funcall stop-predicate octets byte)
                   (return (finish :found))))
                (:eof
                 (return (finish :eof)))
                (:blocked
                 (return (finish :blocked))))))
        (shell-stream-closed (condition)
          (if (plusp (length octets))
              (finish :closed)
              (error condition)))))))

;;; Input — READ-BYTE

(defmethod stream-read-byte ((stream ssh-channel-stream))
  (multiple-value-bind (byte status)
      (%shell-stream-next-byte stream)
    (declare (ignore status))
    byte))

(defmethod stream-listen ((stream ssh-channel-stream))
  (let ((conn (ssh-channel-stream-connection stream))
        (ch   (ssh-channel-stream-channel stream)))
    (labels ((buffered-p ()
               (< (slot-value stream 'read-pos)
                  (length (channel-stdout-buffer ch))))
             (socket-readable-p ()
               (let* ((transport (ssh/connection::connection-transport conn))
                      (socket (and transport (ssh/transport::transport-socket transport))))
                 (and socket
                      (handler-case
                          (multiple-value-bind (ready-sockets remaining)
                              (usocket:wait-for-input socket :timeout 0 :ready-only t)
                            (declare (ignore remaining))
                            ready-sockets)
                        (error () nil)))))
             (pump-available-data ()
               (loop while (and (not (buffered-p)) (socket-readable-p))
                     do (handler-case
                            (channel-dispatch-until conn
                                                    (lambda (pkt)
                                                      (declare (ignore pkt))
                                                      t))
                          (error (condition)
                            (declare (ignore condition))
                            (error 'shell-stream-closed :stream stream))))))
      (or (buffered-p)
          (and (not (or (channel-eof-p ch) (channel-close-p ch)))
               (progn
                 (pump-available-data)
                 (buffered-p)))))))

(defun %pkt-for-channel-p (pkt ch)
  "Return T if PKT is addressed to CH's local channel id."
  (and (>= (length pkt) 5)
       (= (logior (ash (aref pkt 1) 24)
                  (ash (aref pkt 2) 16)
                  (ash (aref pkt 3)  8)
                       (aref pkt 4))
          (channel-local-id ch))))

;;; Input — READ-SEQUENCE

(defmethod stream-read-sequence ((stream ssh-channel-stream) seq start end
                                 &key &allow-other-keys)
  (loop for i from start below end
        for b = (stream-read-byte stream)
        while (not (eq b :eof))
        do (setf (elt seq i) b)
        finally (return i)))

;;; Output — WRITE-BYTE

(defmethod stream-write-byte ((stream ssh-channel-stream) byte)
  (let ((conn (ssh-channel-stream-connection stream))
        (ch   (ssh-channel-stream-channel    stream))
        (buf  (make-array 1 :element-type '(unsigned-byte 8)
                            :initial-element byte)))
    (channel-send-data conn ch buf))
  byte)

;;; Output — WRITE-SEQUENCE

(defmethod stream-write-sequence ((stream ssh-channel-stream) seq start end
                                  &key &allow-other-keys)
  (let ((conn (ssh-channel-stream-connection stream))
        (ch   (ssh-channel-stream-channel    stream)))
    (let ((data (if (and (typep seq '(vector (unsigned-byte 8)))
                         (= start 0)
                         (= end (length seq)))
                    seq
                    (let ((v (make-array (- end start) :element-type '(unsigned-byte 8))))
                      (replace v seq :start2 start :end2 end)
                      v))))
      (channel-send-data conn ch data)))
  seq)

;;; Close

(defmethod close ((stream ssh-channel-stream) &key abort)
  (declare (ignore abort))
  (let ((conn (ssh-channel-stream-connection stream))
        (ch   (ssh-channel-stream-channel    stream)))
    (ignore-errors (channel-close conn ch)))
  (call-next-method))

;;;; Convenience shell I/O helpers

(defun %string-to-octets (string)
  (let ((octets (make-array (length string) :element-type '(unsigned-byte 8))))
    (loop for ch across string
          for i from 0
          for code = (char-code ch)
          do (when (> code 255)
               (error "Cannot write non-octet character ~S to SSH shell stream" ch))
             (setf (aref octets i) code))
    octets))

(defun %octets-to-string (octets &key (start 0) end)
  (map 'string #'code-char (subseq octets start end)))

(defun shell-write-line (stream line)
  "Write LINE plus a newline to shell STREAM, then force output.

STREAM is the bidirectional binary stream returned by OPEN-SHELL.

LINE is encoded as single-byte character codes, matching the rest of
cl-ssh's channel stream API."
  (write-sequence (%string-to-octets line) stream)
  (write-byte 10 stream)
  (force-output stream)
  line)

(defun shell-read-line (stream &key (error-p t) (block-p t))
  "Read one newline-terminated line from shell STREAM.

ERROR-P suppresses clean EOF and CLOSE errors. Otherwise, the function
may signal one of SHELL-STREAM-CLOSED or END-OF-FILE.

Returns a string and a keyword. The keyword is one of :FOUND, :BLOCKED,
:EOF, or :CLOSED."
  (%shell-read-collect
   stream
   (lambda (octets byte)
     (declare (ignore octets))
     (= byte 10))
   (lambda (octets status)
     (let* ((end (length octets))
            (string (progn
                      (when (and (plusp end) (= (aref octets (1- end)) 13))
                        (decf end))
                      (%octets-to-string octets :end end))))
       (case status
         ((:found :blocked)
          (values string status))
         ((:eof :closed)
          (if error-p
              (error (case status
                       (:eof 'end-of-file)
                       (:closed 'shell-stream-closed))
                     :stream stream)
              (values string status)))
         (otherwise
          (error "Unknown shell read status ~S" status)))))
   :block-p block-p))

(defun shell-read-until (stream marker &key include-marker (error-p t) (block-p t))
  "Read from shell STREAM until MARKER is seen

MARKER can be a string or nil. If it is a string, then it is a substring
that determines the read limit when BLOCK-P is t. If MARKER is nil and
BLOCK-P is t, then it will never stop reading until a user interrupts,
or a condition is signaled. When BLOCK-P is nil, then whichever is first
determines when the function returns.

INCLUDE-MARKER keeps the MARKER in the returned string if MARKER is a
string, otherwise its otiose.

ERROR-P suppresses clean EOF and CLOSE errors. Otherwise, the function
may signal one of SHELL-STREAM-CLOSED or END-OF-FILE.

BLOCK-P determines whether the function should block until MARKER is
found.

Returns two values: a string and a keyword. The string is the
accumulated string until the end was reached, and the keyword is the
read status, which is one of :FOUND or :BLOCKED. When ERROR-P is nil,
then it may also be one of :EOF or :CLOSED."
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
                   (loop for i below marker-length
                         always (= (aref octets (+ start i))
                                   (aref marker-octets i)))))))
     (lambda (octets status)
       (let* ((end (length octets))
              (string (if (and (and (eq status :found) marker (not include-marker)))
                          (%octets-to-string octets :end (- end marker-length))
                          (%octets-to-string octets :end end))))
         (case status
           ((:found :blocked)
            (values string status))
           ((:eof :closed)
            (if error-p
                (error (case status
                         (:eof 'end-of-file)
                         (:closed 'shell-stream-closed))
                       :stream stream)
                (values string status)))
           (otherwise
            (error "Unknown shell read status ~S" status)))))
     :block-p block-p)))

;;;; PTY request helper

(defun request-pty (conn ch &key (term "xterm") (cols 80) (rows 24)
                              (width-px 0) (height-px 0))
  "Send a pty-req channel request."
  (let ((extra (make-write-buffer)))
    (write-string* extra term)
    (write-uint32  extra cols)
    (write-uint32  extra rows)
    (write-uint32  extra width-px)
    (write-uint32  extra height-px)
    ;; Empty terminal modes string
    (write-string* extra (make-array 0 :element-type '(unsigned-byte 8)))
    (channel-request conn ch +request-pty+ t extra)))

;;;; Environment variable

(defun send-env (conn ch name value)
  "Send an env channel request to set NAME=VALUE in the remote environment."
  (let ((extra (make-write-buffer)))
    (write-string* extra name)
    (write-string* extra value)
    (channel-request conn ch +request-env+ nil extra)))

;;;; Blocking exec

(defun run-command (transport command &key environment)
  "Execute COMMAND on a new session channel over TRANSPORT.

   ENVIRONMENT is an alist of (name . value) strings to set before exec.

   Returns (values stdout-string stderr-string exit-code)."
  (let* ((conn (make-connection transport))
         (ch   (open-channel conn +channel-session+)))
    (unless (channel-open-p ch)
      (error 'connection-error :message "server refused to open session channel"))
    ;; Send environment variables
    (dolist (pair environment)
      (send-env conn ch (car pair) (cdr pair)))
    ;; Send exec request
    (let ((extra (make-write-buffer)))
      (write-string* extra command)
      (unless (channel-request conn ch +request-exec+ t extra)
        (error 'connection-error :message "server rejected exec request")))
    ;; Drain until channel close (collects stdout, stderr, exit-status).
    ;; Loop terminates on CLOSE; CLOSE alone is sufficient (implies EOF).
    ;; The inner predicate wakes the loop on any relevant channel message
    ;; so that window adjustments and data packets are not missed.
    (loop until (channel-close-p ch)
          do (channel-dispatch-until
              conn
              (lambda (pkt)
                (and (%pkt-for-channel-p pkt ch)
                     (let ((type (aref pkt 0)))
                       (or (= type ssh/constants:+msg-channel-data+)
                           (= type ssh/constants:+msg-channel-extended-data+)
                           (= type ssh/constants:+msg-channel-eof+)
                           (= type ssh/constants:+msg-channel-close+)
                           (= type ssh/constants:+msg-channel-request+)))))))
    ;; Send close
    (ignore-errors (channel-close conn ch))
    ;; Convert buffers to strings
    (values
     (map 'string #'code-char (channel-stdout-buffer ch))
     (map 'string #'code-char (channel-stderr-buffer ch))
     (or (channel-exit-status ch) 0))))

;;;; Interactive shell

(defun open-shell (transport &key pty (pty-term "xterm") (pty-cols 80) (pty-rows 24)
                                   environment)
  "Open a session channel, optionally request a PTY, then request a shell.
   Returns (values stdin/stdout-stream stderr-string-accumulator channel).

   The returned stream is bidirectional:
     - Writing sends data to the remote shell's stdin
     - Reading reads from the remote shell's stdout

   Stderr data accumulates in the channel's stderr-buffer and can be
   accessed via (channel-stderr-buffer channel)."
  (let* ((conn (make-connection transport))
         (ch   (open-channel conn +channel-session+)))
    (unless (channel-open-p ch)
      (error 'connection-error :message "server refused to open session channel"))
    (dolist (pair environment)
      (send-env conn ch (car pair) (cdr pair)))
    (when pty
      (unless (request-pty conn ch :term pty-term :cols pty-cols :rows pty-rows)
        (error 'connection-error :message "server rejected pty-req")))
    (unless (channel-request conn ch +request-shell+ t nil)
      (error 'connection-error :message "server rejected shell request"))
    (let ((stream (make-instance 'ssh-channel-stream
                                 :connection conn
                                 :channel    ch)))
      (values stream ch))))

;;;; Subsystem

(defun open-subsystem (transport subsystem-name)
  "Open a session channel and request SUBSYSTEM-NAME (e.g. \"sftp\").
   Returns (values stream channel) where STREAM is a bidirectional Gray stream."
  (let* ((conn (make-connection transport))
         (ch   (open-channel conn +channel-session+)))
    (unless (channel-open-p ch)
      (error 'connection-error :message "server refused to open session channel"))
    (let ((extra (make-write-buffer)))
      (write-string* extra subsystem-name)
      (unless (channel-request conn ch +request-subsystem+ t extra)
        (error 'connection-error
               :message (format nil "server rejected subsystem ~S" subsystem-name))))
    (let ((stream (make-instance 'ssh-channel-stream
                                 :connection conn
                                 :channel    ch)))
      (values stream ch))))
