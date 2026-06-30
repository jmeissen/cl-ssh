;;;; Tests for ssh/connection channel byte handling.

(defpackage :ssh/tests/connection
  (:use :cl :parachute)
  (:import-from :ssh/tests #:octets)
  (:import-from :ssh/connection
                #:make-connection
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
                #:+msg-channel-data+
                #:+msg-channel-extended-data+
                #:+extended-data-stderr+))

(in-package :ssh/tests/connection)

(defun add-test-channel (conn ch)
  (vector-push-extend ch (ssh/connection::connection-channels conn))
  ch)

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
         (conn (make-connection transport))
         (ch (ssh/connection::make-channel :remote-id 7
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
           (channel-send-data conn ch raw)
           (is = 1 (length sent))
           (let ((buf (make-read-buffer (first sent))))
             (is = +msg-channel-data+ (read-byte* buf))
             (is = 7 (read-uint32 buf))
             (is equalp raw (read-string* buf)))
           (is = 0 (ssh/connection::channel-remote-window ch)))
      (setf (symbol-function 'ssh/transport:transport-send) original-send))))

(define-test channel-receive-data-preserves-stdout-raw-bytes
  :parent (:ssh/tests ssh/tests)
  (let* ((conn (make-connection (ssh/transport::make-transport)))
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
  (let* ((conn (make-connection (ssh/transport::make-transport)))
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
