;;;; Tests for ssh/transport — version exchange.

(defpackage :ssh/tests/transport
  (:use :cl :parachute :trivial-gray-streams)
  (:import-from :ssh/transport
                #:recv-version
                #:transport-error))

(in-package :ssh/tests/transport)

;;;; In-process input stream

(defclass pipe-input-stream (fundamental-binary-input-stream)
  ((buffer   :initarg :buffer)
   (read-pos :initform 0)))

(defmethod stream-read-byte ((s pipe-input-stream))
  (with-slots (buffer read-pos) s
    (if (< read-pos (length buffer))
        (prog1 (aref buffer read-pos)
          (incf read-pos))
        (error "pipe-input-stream underflow in test"))))

(defun string->octets (string)
  (map '(vector (unsigned-byte 8)) #'char-code string))

(defun crlf ()
  (coerce '(#\Return #\Newline) 'string))

(defun make-input-stream (string)
  (make-instance 'pipe-input-stream
                 :buffer (string->octets string)))

;;; ---- recv-version -------------------------------------------------------

(define-test recv-version-skips-long-banner-before-version
  :parent (:ssh/tests ssh/tests)
  (let* ((banner  (make-string 1000 :initial-element #\x))
         (version "SSH-2.0-test-client")
         (stream  (make-input-stream
                   (concatenate 'string banner (crlf) version (crlf)))))
    (is equalp (string->octets version)
        (recv-version stream))))

(define-test recv-version-accepts-maximum-length-identification-line
  :parent (:ssh/tests ssh/tests)
  (let* ((version (concatenate 'string "SSH-2.0-"
                               (make-string 245 :initial-element #\a)))
         (stream  (make-input-stream (concatenate 'string version (crlf)))))
    (is equalp (string->octets version)
        (recv-version stream))))

(define-test recv-version-rejects-overlong-identification-line
  :parent (:ssh/tests ssh/tests)
  (let* ((version (concatenate 'string "SSH-2.0-"
                               (make-string 246 :initial-element #\a)))
         (stream  (make-input-stream (concatenate 'string version (crlf)))))
    (of-type 'transport-error
      (handler-case (progn (recv-version stream) nil)
        (transport-error (c) c)))))

(define-test recv-version-rejects-ssh-prefixed-pre-banner-line
  :parent (:ssh/tests ssh/tests)
  (let* ((banner "SSH-not-a-version")
         (version "SSH-2.0-test-client")
         (stream  (make-input-stream
                   (concatenate 'string banner (crlf) version (crlf)))))
    (of-type 'transport-error
      (handler-case (progn (recv-version stream) nil)
        (transport-error (c) c)))))

(define-test recv-version-accepts-ssh-1.99-compatibility-line-without-cr
  :parent (:ssh/tests ssh/tests)
  (let* ((version (concatenate 'string "SSH-1.99-"
                               (make-string 245 :initial-element #\a)))
         (stream  (make-input-stream
                   (concatenate 'string version (string #\Newline)))))
    (is equalp (string->octets version)
        (recv-version stream))))
