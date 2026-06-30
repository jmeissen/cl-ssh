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

(defun rekey-kexinit-payload ()
  (ssh/algorithms:kexinit-payload :include-ext-info-c-p nil))

(defun dummy-kex-result (session-id)
  (ssh/kex::make-kex-result
   :session-id session-id
   :shared-secret 1
   :exchange-hash (make-array 32 :element-type '(unsigned-byte 8)
                                 :initial-element 7)
   :iv-c2s (make-array 16 :element-type '(unsigned-byte 8)
                          :initial-element 1)
   :iv-s2c (make-array 16 :element-type '(unsigned-byte 8)
                          :initial-element 2)
   :key-c2s (make-array 32 :element-type '(unsigned-byte 8)
                           :initial-element 3)
   :key-s2c (make-array 32 :element-type '(unsigned-byte 8)
                           :initial-element 4)
   :mac-c2s (make-array 64 :element-type '(unsigned-byte 8)
                           :initial-element 5)
   :mac-s2c (make-array 64 :element-type '(unsigned-byte 8)
                           :initial-element 6)))

(defun make-rekey-test-transport (&key (session-id (ssh/tests:octets 1 2 3)))
  (let ((ps (ssh/packet:make-packet-stream (make-input-stream ""))))
    (ssh/transport::make-transport
     :packet-stream ps
     :session-id session-id
     :hostname "example.test"
     :client-version (string->octets "SSH-2.0-cl-ssh-test")
     :server-version (string->octets "SSH-2.0-server-test")
     :last-rekey-time 1000)))

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

(define-test negotiate-algorithms-accepts-curve25519-sha256-libssh-alias
  :parent (:ssh/tests ssh/tests)
  (let* ((payload (ssh/algorithms:kexinit-payload))
         (server-kexinit (ssh/algorithms:parse-kexinit payload)))
    (setf (ssh/algorithms::kexinit-kex-algorithms server-kexinit)
          (list ssh/constants::+kex-curve25519-sha256-libssh+))
    (is string= ssh/constants::+kex-curve25519-sha256-libssh+
        (ssh/algorithms::negotiated-kex
         (ssh/algorithms::negotiate-algorithms server-kexinit)))))

(define-test negotiate-algorithms-selects-aes256-ctr
  :parent (:ssh/tests ssh/tests)
  (let* ((payload (ssh/algorithms:kexinit-payload))
         (server-kexinit (ssh/algorithms:parse-kexinit payload)))
    (setf (ssh/algorithms::kexinit-encryption-algorithms-c2s server-kexinit)
          (list ssh/constants::+cipher-aes256-ctr+)
          (ssh/algorithms::kexinit-encryption-algorithms-s2c server-kexinit)
          (list ssh/constants::+cipher-aes256-ctr+))
    (let ((negotiated (ssh/algorithms::negotiate-algorithms server-kexinit)))
      (is string= ssh/constants::+cipher-aes256-ctr+
          (ssh/algorithms::negotiated-cipher-c2s negotiated))
      (is string= ssh/constants::+cipher-aes256-ctr+
          (ssh/algorithms::negotiated-cipher-s2c negotiated)))))

(define-test negotiate-algorithms-selects-hmac-sha2-512
  :parent (:ssh/tests ssh/tests)
  (let* ((payload (ssh/algorithms:kexinit-payload))
         (server-kexinit (ssh/algorithms:parse-kexinit payload)))
    (setf (ssh/algorithms::kexinit-mac-algorithms-c2s server-kexinit)
            (list ssh/constants:+mac-hmac-sha2-512+)
          (ssh/algorithms::kexinit-mac-algorithms-s2c server-kexinit)
            (list ssh/constants:+mac-hmac-sha2-512+))
    (let ((negotiated (ssh/algorithms:negotiate-algorithms server-kexinit)))
      (is string= ssh/constants:+mac-hmac-sha2-512+
          (ssh/algorithms::negotiated-mac-c2s negotiated))
      (is string= ssh/constants:+mac-hmac-sha2-512+
          (ssh/algorithms::negotiated-mac-s2c negotiated)))))

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

(define-test ext-info-extension-names-are-us-ascii
  :parent (:ssh/tests ssh/tests)
  (let ((payload (ext-info-payload (list (coerce '(#xff) '(vector (unsigned-byte 8)))
                                        (ssh/tests:octets 1 2 3)))))
    (fail (ssh/transport::parse-ext-info-payload payload)
          'ssh/transport:transport-error)))

(define-test ext-info-server-sig-algs-is-us-ascii-name-list
  :parent (:ssh/tests ssh/tests)
  (let ((payload (ext-info-payload (list "server-sig-algs"
                                        (ssh/tests:octets #x73 #x73 #x68 #xff)))))
    (fail (ssh/transport::process-ext-info
           (ssh/transport::make-transport)
           payload)
          'ssh/transport:transport-error)))

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

(define-test rekey-policy-detects-packet-byte-and-time-limits
  :parent (:ssh/tests ssh/tests)
  (let* ((transport (make-rekey-test-transport))
         (ps (ssh/transport::transport-packet-stream transport)))
    (setf (ssh/transport::transport-rekey-packet-limit transport) 2
          (ssh/transport::transport-rekey-byte-limit transport) 10
          (ssh/transport::transport-rekey-seconds-limit transport) 60
          (ssh/packet:packet-stream-packets-out ps) 1
          (ssh/packet:packet-stream-bytes-in ps) 9)
    (false (ssh/transport::transport-rekey-needed-p transport :now 1059))
    (setf (ssh/packet:packet-stream-packets-out ps) 2)
    (true (ssh/transport::transport-rekey-needed-p transport :now 1059))
    (setf (ssh/packet:packet-stream-packets-out ps) 0
          (ssh/packet:packet-stream-bytes-in ps) 10)
    (true (ssh/transport::transport-rekey-needed-p transport :now 1059))
    (setf (ssh/packet:packet-stream-bytes-in ps) 0)
    (true (ssh/transport::transport-rekey-needed-p transport :now 1060))))

(define-test rekey-limit-normalization-validates-documented-values
  :parent (:ssh/tests ssh/tests)
  (is = 10 (ssh/transport::normalize-rekey-limit :unset 10))
  (is = 10 (ssh/transport::normalize-rekey-limit :default 10))
  (is eq nil (ssh/transport::normalize-rekey-limit nil 10))
  (is = 64 (ssh/transport::normalize-rekey-limit 64 10))
  (fail (ssh/transport::normalize-rekey-limit 0 10)
        'ssh/transport:transport-error)
  (fail (ssh/transport::normalize-rekey-limit -1 10)
        'ssh/transport:transport-error)
  (fail (ssh/transport::normalize-rekey-limit "64K" 10)
        'ssh/transport:transport-error))

(define-test transport-send-initiates-rekey-before-application-data
  :parent (:ssh/tests ssh/tests)
  (let* ((transport (make-rekey-test-transport))
         (ps (ssh/transport::transport-packet-stream transport))
         (session-id (ssh/transport::transport-session-id transport))
         (incoming (list (rekey-kexinit-payload)
                         (ssh/tests:octets ssh/constants::+msg-newkeys+)))
         (sent '())
         (kex-session-ids '())
         (original-send (symbol-function 'ssh/packet:send-packet))
         (original-recv (symbol-function 'ssh/packet:recv-packet))
         (original-curve (symbol-function 'ssh/kex:perform-kex-curve25519)))
    (setf (ssh/transport::transport-rekey-packet-limit transport) 1
          (ssh/packet:packet-stream-packets-out ps) 1)
    (unwind-protect
         (progn
           (setf (symbol-function 'ssh/packet:send-packet)
                 (lambda (stream payload)
                   (declare (ignore stream))
                   (setf sent (append sent (list payload)))
                   0)
                 (symbol-function 'ssh/packet:recv-packet)
                 (lambda (stream)
                   (declare (ignore stream))
                   (pop incoming))
                 (symbol-function 'ssh/kex:perform-kex-curve25519)
                 (lambda (&rest args)
                   (push (sixth args) kex-session-ids)
                   (dummy-kex-result session-id)))
           (ssh/transport:transport-send transport
                                         (ssh/tests:octets ssh/constants::+msg-ignore+ 1))
           (is = 3 (length sent))
           (is = ssh/constants::+msg-kexinit+ (aref (first sent) 0))
           (false (member ssh/constants::+ext-info-c+
                          (ssh/algorithms::kexinit-kex-algorithms
                           (ssh/algorithms:parse-kexinit (first sent)))
                          :test #'string=))
           (is = ssh/constants::+msg-newkeys+ (aref (second sent) 0))
           (is = ssh/constants::+msg-ignore+ (aref (third sent) 0))
           (is equalp session-id (first kex-session-ids))
           (is equalp session-id (ssh/transport::transport-session-id transport)))
      (setf (symbol-function 'ssh/packet:send-packet) original-send
            (symbol-function 'ssh/packet:recv-packet) original-recv
            (symbol-function 'ssh/kex:perform-kex-curve25519) original-curve))))

(define-test client-initiated-rekey-rejects-second-kexinit
  :parent (:ssh/tests ssh/tests)
  (let* ((transport (make-rekey-test-transport))
         (ps (ssh/transport::transport-packet-stream transport))
         (incoming (list (rekey-kexinit-payload)
                         (rekey-kexinit-payload)))
         (original-send (symbol-function 'ssh/packet:send-packet))
         (original-recv (symbol-function 'ssh/packet:recv-packet)))
    (setf (ssh/transport::transport-rekey-packet-limit transport) 1
          (ssh/packet:packet-stream-packets-out ps) 1)
    (unwind-protect
         (progn
           (setf (symbol-function 'ssh/packet:send-packet)
                 (lambda (stream payload)
                   (declare (ignore stream payload))
                   0)
                 (symbol-function 'ssh/packet:recv-packet)
                 (lambda (stream)
                   (declare (ignore stream))
                   (pop incoming)))
           (fail (ssh/transport:transport-send
                  transport
                  (ssh/tests:octets ssh/constants::+msg-ignore+ 1))
                 'ssh/packet:ssh-protocol-error))
      (setf (symbol-function 'ssh/packet:send-packet) original-send
            (symbol-function 'ssh/packet:recv-packet) original-recv))))

(define-test transport-recv-answers-server-initiated-rekey
  :parent (:ssh/tests ssh/tests)
  (let* ((transport (make-rekey-test-transport))
         (session-id (ssh/transport::transport-session-id transport))
         (application-packet (ssh/tests:octets 94 9))
         (incoming (list (rekey-kexinit-payload)
                         (ssh/tests:octets ssh/constants::+msg-newkeys+)
                         application-packet))
         (sent '())
         (original-send (symbol-function 'ssh/packet:send-packet))
         (original-recv (symbol-function 'ssh/packet:recv-packet))
         (original-curve (symbol-function 'ssh/kex:perform-kex-curve25519)))
    (unwind-protect
         (progn
           (setf (symbol-function 'ssh/packet:send-packet)
                 (lambda (stream payload)
                   (declare (ignore stream))
                   (setf sent (append sent (list payload)))
                   0)
                 (symbol-function 'ssh/packet:recv-packet)
                 (lambda (stream)
                   (declare (ignore stream))
                   (pop incoming))
                 (symbol-function 'ssh/kex:perform-kex-curve25519)
                 (lambda (&rest args)
                   (declare (ignore args))
                   (dummy-kex-result session-id)))
           (is equalp application-packet
               (ssh/transport:transport-recv transport))
           (is = 2 (length sent))
           (is = ssh/constants::+msg-kexinit+ (aref (first sent) 0))
           (is = ssh/constants::+msg-newkeys+ (aref (second sent) 0))
           (is equalp session-id (ssh/transport::transport-session-id transport)))
      (setf (symbol-function 'ssh/packet:send-packet) original-send
            (symbol-function 'ssh/packet:recv-packet) original-recv
            (symbol-function 'ssh/kex:perform-kex-curve25519) original-curve))))

(define-test client-initiated-rekey-queues-in-flight-packets
  :parent (:ssh/tests ssh/tests)
  (let* ((transport (make-rekey-test-transport))
         (ps (ssh/transport::transport-packet-stream transport))
         (session-id (ssh/transport::transport-session-id transport))
         (in-flight (ssh/tests:octets 94 7))
         (incoming (list in-flight
                         (rekey-kexinit-payload)
                         (ssh/tests:octets ssh/constants::+msg-newkeys+)))
         (original-send (symbol-function 'ssh/packet:send-packet))
         (original-recv (symbol-function 'ssh/packet:recv-packet))
         (original-curve (symbol-function 'ssh/kex:perform-kex-curve25519)))
    (setf (ssh/transport::transport-rekey-packet-limit transport) 1
          (ssh/packet:packet-stream-packets-out ps) 1)
    (unwind-protect
         (progn
           (setf (symbol-function 'ssh/packet:send-packet)
                 (lambda (stream payload)
                   (declare (ignore stream payload))
                   0)
                 (symbol-function 'ssh/packet:recv-packet)
                 (lambda (stream)
                   (declare (ignore stream))
                   (pop incoming))
                 (symbol-function 'ssh/kex:perform-kex-curve25519)
                 (lambda (&rest args)
                   (declare (ignore args))
                   (dummy-kex-result session-id)))
           (ssh/transport:transport-send transport
                                         (ssh/tests:octets ssh/constants::+msg-ignore+ 1))
           (is = 1 (ssh/transport::transport-pending-packet-count transport))
           (is = (length in-flight)
               (ssh/transport::transport-pending-packet-bytes transport))
           (is equalp in-flight
               (ssh/transport:transport-recv transport))
           (is = 0 (ssh/transport::transport-pending-packet-count transport))
           (is = 0 (ssh/transport::transport-pending-packet-bytes transport)))
      (setf (symbol-function 'ssh/packet:send-packet) original-send
            (symbol-function 'ssh/packet:recv-packet) original-recv
            (symbol-function 'ssh/kex:perform-kex-curve25519) original-curve))))

(define-test client-initiated-rekey-bounds-in-flight-packet-count
  :parent (:ssh/tests ssh/tests)
  (let* ((transport (make-rekey-test-transport))
         (ps (ssh/transport::transport-packet-stream transport))
         (incoming (list (ssh/tests:octets 94 1)
                         (ssh/tests:octets 94 2)
                         (rekey-kexinit-payload)
                         (ssh/tests:octets ssh/constants::+msg-newkeys+)))
         (original-send (symbol-function 'ssh/packet:send-packet))
         (original-recv (symbol-function 'ssh/packet:recv-packet)))
    (setf (ssh/transport::transport-rekey-packet-limit transport) 1
          (ssh/transport::transport-rekey-pending-packet-limit transport) 1
          (ssh/packet:packet-stream-packets-out ps) 1)
    (unwind-protect
         (progn
           (setf (symbol-function 'ssh/packet:send-packet)
                 (lambda (stream payload)
                   (declare (ignore stream payload))
                   0)
                 (symbol-function 'ssh/packet:recv-packet)
                 (lambda (stream)
                   (declare (ignore stream))
                   (pop incoming)))
           (fail (ssh/transport:transport-send
                  transport
                  (ssh/tests:octets ssh/constants::+msg-ignore+ 1))
                 'ssh/transport:transport-error))
      (setf (symbol-function 'ssh/packet:send-packet) original-send
            (symbol-function 'ssh/packet:recv-packet) original-recv))))

(define-test client-initiated-rekey-bounds-in-flight-packet-bytes
  :parent (:ssh/tests ssh/tests)
  (let* ((transport (make-rekey-test-transport))
         (ps (ssh/transport::transport-packet-stream transport))
         (incoming (list (ssh/tests:octets 94 1 2 3)
                         (rekey-kexinit-payload)
                         (ssh/tests:octets ssh/constants::+msg-newkeys+)))
         (original-send (symbol-function 'ssh/packet:send-packet))
         (original-recv (symbol-function 'ssh/packet:recv-packet)))
    (setf (ssh/transport::transport-rekey-packet-limit transport) 1
          (ssh/transport::transport-rekey-pending-byte-limit transport) 3
          (ssh/packet:packet-stream-packets-out ps) 1)
    (unwind-protect
         (progn
           (setf (symbol-function 'ssh/packet:send-packet)
                 (lambda (stream payload)
                   (declare (ignore stream payload))
                   0)
                 (symbol-function 'ssh/packet:recv-packet)
                 (lambda (stream)
                   (declare (ignore stream))
                   (pop incoming)))
           (fail (ssh/transport:transport-send
                  transport
                  (ssh/tests:octets ssh/constants::+msg-ignore+ 1))
                 'ssh/transport:transport-error))
      (setf (symbol-function 'ssh/packet:send-packet) original-send
            (symbol-function 'ssh/packet:recv-packet) original-recv))))
