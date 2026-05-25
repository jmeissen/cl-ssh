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

(defun ext-info-payload (&rest entries)
  (let ((buf (ssh/buffer:make-write-buffer)))
    (ssh/buffer:write-byte* buf ssh/constants::+msg-ext-info+)
    (ssh/buffer:write-uint32 buf (length entries))
    (dolist (entry entries)
      (ssh/buffer:write-string* buf (first entry))
      (ssh/buffer:write-string* buf (second entry)))
    (ssh/buffer:buffer-to-octets buf)))

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
         (stream (make-input-stream
                  (concatenate 'string version (string #\Newline)))))
    (is equalp (string->octets version)
        (recv-version stream))))

;;; ---- RFC 8308 ------------------------------------------------------------

(define-test kexinit-advertises-ext-info-c
  :parent (:ssh/tests ssh/tests)
  (let* ((payload (ssh/algorithms:kexinit-payload))
         (kexinit (ssh/algorithms:parse-kexinit payload))
         (algs (ssh/algorithms::kexinit-kex-algorithms kexinit)))
    (true (member ssh/constants::+ext-info-c+ algs :test #'string=))
    (false (member ssh/constants::+ext-info-s+ algs :test #'string=))))

(define-test ext-info-parsing-preserves-opaque-values
  :parent (:ssh/tests ssh/tests)
  (let* ((sig-algs-bytes (map '(vector (unsigned-byte 8)) #'char-code
                              "rsa-sha2-512,ssh-rsa"))
         (payload (ext-info-payload (list "unknown-ext" (coerce '(0 255 1 0) '(vector (unsigned-byte 8))))
                                    (list "server-sig-algs" sig-algs-bytes)))
         (extensions (ssh/transport::parse-ext-info-payload payload))
         (transport (ssh/transport::make-transport :server-sig-algs '("old"))))
    (is equal "unknown-ext" (caar extensions))
    (is equalp #(0 255 1 0) (cdar extensions))
    (ssh/transport::process-ext-info transport payload)
    (is equal '("rsa-sha2-512" "ssh-rsa")
        (ssh/transport::transport-server-sig-algs transport))))

(define-test ext-info-replaces-previous-server-sig-algs
  :parent (:ssh/tests ssh/tests)
  (let* ((payload (ext-info-payload (list "other-extension" (coerce '(1 2 3) '(vector (unsigned-byte 8))))))
         (transport (ssh/transport::make-transport
                     :server-sig-algs '("rsa-sha2-512"))))
    (ssh/transport::process-ext-info transport payload)
    (null (ssh/transport::transport-server-sig-algs transport))))

(define-test server-kexinit-rejects-wrong-role-ext-info-c
  :parent (:ssh/tests ssh/tests)
  (let* ((payload (ssh/algorithms:kexinit-payload :include-ext-info-c-p nil))
         (kexinit (ssh/algorithms:parse-kexinit payload)))
    (setf (ssh/algorithms::kexinit-kex-algorithms kexinit)
          (append (ssh/algorithms::kexinit-kex-algorithms kexinit)
                  (list ssh/constants::+ext-info-c+)))
    (fail (ssh/transport::validate-server-kexinit kexinit)
          'ssh/transport::transport-error)))
