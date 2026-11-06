(defpackage #:ssh/tests/sftp-channel
  (:use #:cl #:parachute #:ssh/constants #:ssh/buffer)
  (:import-from #:ssh/tests #:octets))
(in-package #:ssh/tests/sftp-channel)

(defun packet (type id &optional writer)
  (let ((buffer (make-write-buffer)))
    (write-byte* buffer type) (write-uint32 buffer id)
    (when writer (funcall writer buffer))
    (buffer-to-octets buffer)))

(defun multiplex-server (packets gate condition state)
  (let ((sftp-id nil) (held-id nil) (commands 0))
    (labels ((send (type id &optional writer)
               (ssh/packet:send-packet packets (packet type id writer)))
             (data (id octets)
               (send +msg-channel-data+ id (lambda (b) (write-string* b octets))))
             (frame (type writer)
               (let ((buffer (make-write-buffer)))
                 (funcall writer buffer)
                 (let ((frame (ssh/sftp/codec::encode-frame type (buffer-to-octets buffer))))
                   ;; Fragment length, type, request ID and response fields alike.
                   (loop for start from 0 below (length frame) by 3
                         do (data sftp-id (subseq frame start (min (+ start 3) (length frame)))))))))
      (loop
        (let* ((buffer (make-read-buffer (ssh/packet:recv-packet packets)))
               (type (read-byte* buffer)))
          (cond
            ((= type +msg-channel-open+)
             (read-string* buffer)
             (let ((id (read-uint32 buffer)))
               (send +msg-channel-open-confirmation+ id
                     (lambda (b) (write-uint32 b (+ id 71))
                                 (write-uint32 b 1048576) (write-uint32 b 1024)))))
            ((= type +msg-channel-request+)
             (let* ((id (- (read-uint32 buffer) 71))
                    (request (ssh:sftp-name-string (read-string* buffer))))
               (read-byte* buffer) (read-string* buffer)
               (send +msg-channel-success+ id)
               (cond
                 ((string= request "subsystem") (setf sftp-id id))
                 ((string= request "exec")
                  (incf commands)
                  (data id (utf-8-to-octets "command output"))
                  (send +msg-channel-request+ id
                        (lambda (b) (write-string* b "exit-status")
                                    (write-byte* b 0) (write-uint32 b 0)))
                  (send +msg-channel-eof+ id) (send +msg-channel-close+ id)
                  (when held-id
                    (frame 105 (lambda (b) (write-uint32 b held-id)
                                 (ssh/sftp/codec::encode-attributes b
                                   (ssh:make-sftp-attributes :size 23))))
                    (setf held-id nil))))))
            ((= type +msg-channel-data+)
             (read-uint32 buffer)
             (let ((sftp (make-read-buffer (read-string* buffer))))
               (read-uint32 sftp)
               (case (read-byte* sftp)
                 (1
                  (frame 2 (lambda (b) (write-uint32 b 3)))
                  (dotimes (i 8)
                    (send +msg-channel-extended-data+ sftp-id
                          (lambda (b) (write-uint32 b +extended-data-stderr+)
                            (write-string* b (make-array 16384 :element-type '(unsigned-byte 8)
                                                        :initial-element i))))))
                 (17
                  (let ((id (read-uint32 sftp)))
                    (if (zerop commands)
                        (progn
                          (setf held-id id)
                          (bt2:with-lock-held (gate)
                            (setf (car state) t) (bt2:condition-broadcast condition)))
                        ;; An unsolicited response must fail SFTP, not the dispatcher.
                        (frame 105 (lambda (b) (write-uint32 b (+ id 100))
                                     (ssh/sftp/codec::encode-attributes b nil)))))))))
            ((= type +msg-channel-close+)
             (let ((id (- (read-uint32 buffer) 71)))
               (when (= id sftp-id) (send +msg-channel-close+ id))
               (when (and (/= id sftp-id) (= commands 2)) (return))))
            ((= type +msg-disconnect+) (return))))))))

(define-test sftp-shares-dispatcher-and-isolates-protocol-failure :parent (:ssh/tests ssh/tests)
  (multiple-value-bind (client-socket server-socket)
      (ssh/tests/connection::make-test-socket-pair)
    (let* ((transport (ssh/transport::make-transport :socket client-socket
                       :packet-stream (ssh/packet:make-packet-stream (usocket:socket-stream client-socket))))
           (connection (ssh/connection:make-connection transport))
           (packets (ssh/packet:make-packet-stream (usocket:socket-stream server-socket)))
           (gate (bt2:make-lock)) (changed (bt2:make-condition-variable)) (state (list nil))
           (server-error nil) (stat-error nil) (attributes nil) (session nil) (stat-thread nil)
           (server (bt2:make-thread
                     (lambda () (handler-case (multiplex-server packets gate changed state)
                                  (error (cause) (setf server-error cause)))))))
      (unwind-protect
           (progn
             (setf session (ssh/sftp:open-sftp-session connection)
                   stat-thread (bt2:make-thread
                     (lambda () (handler-case (setf attributes (ssh:sftp-stat session "file"))
                                  (error (cause) (setf stat-error cause))))))
             (bt2:with-lock-held (gate)
               (loop until (car state) do (bt2:condition-wait changed gate)))
             (is equal '("command output" "" 0)
                 (multiple-value-list (ssh/session:run-command connection "while sftp waits")))
             (bt2:join-thread stat-thread)
             (false stat-error)
             (is = 23 (ssh:sftp-attributes-size attributes))
             (multiple-value-bind (tail truncated) (ssh:sftp-diagnostics session)
               (true truncated) (is = 65536 (length tail))
               (is = 7 (aref tail (1- (length tail)))))
             (fail (ssh:sftp-stat session "bad reply") 'ssh:sftp-protocol-error)
             (ssh:close-sftp session :abort t)
             (is string= "command output" (ssh/session:run-command connection "after sftp failure"))
             (bt2:join-thread server)
             (false server-error))
        (when session (ignore-errors (ssh:close-sftp session :abort t)))
        (ignore-errors (ssh/connection:connection-close connection))
        (ignore-errors (usocket:socket-close server-socket))))))

(define-test failed-channel-writer-wakes-before-sftp-abort-close :parent (:ssh/tests ssh/tests)
  (let* ((connection (ssh/tests/connection::make-test-connection))
         (channel (ssh/tests/connection::add-test-channel connection
                    (ssh/connection::make-channel :connection connection :remote-id 71
                      :remote-window 0 :open-p t)))
         (session (ssh/sftp::%make-session :channel channel :state :ready))
         (original (symbol-function 'ssh/transport:transport-send))
         (sent nil) (writer-error nil) (writer nil))
    (unwind-protect
         (progn
           (setf (symbol-function 'ssh/transport:transport-send)
                 (lambda (transport payload) (declare (ignore transport))
                   (push (aref payload 0) sent)
                   ;; Exercise receipt of CLOSE while our own CLOSE is pending.
                   (when (= (aref payload 0) +msg-channel-close+)
                     (ssh/connection::%handle-packet connection (packet +msg-channel-close+ 0)))))
           (setf writer (bt2:make-thread
             (lambda () (handler-case (ssh/connection:channel-send-data channel (octets 1))
                          (error (cause) (setf writer-error cause))))))
           (true (ssh:close-sftp session :abort t))
           (bt2:join-thread writer)
           (of-type 'error writer-error)
           (is equal (list +msg-channel-close+) sent)
           (is = 0 (hash-table-count (ssh/connection::connection-channels connection))))
      (setf (symbol-function 'ssh/transport:transport-send) original))))
