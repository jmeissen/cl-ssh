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
    (setf (ssh/algorithms::kexinit-encryption-algorithms-c2s server-kexinit)
          (list ssh/constants:+cipher-aes256-ctr+)
          (ssh/algorithms::kexinit-encryption-algorithms-s2c server-kexinit)
          (list ssh/constants:+cipher-aes256-ctr+)
          (ssh/algorithms::kexinit-mac-algorithms-c2s server-kexinit)
          (list ssh/constants:+mac-hmac-sha2-512+)
          (ssh/algorithms::kexinit-mac-algorithms-s2c server-kexinit)
          (list ssh/constants:+mac-hmac-sha2-512+))
    (let ((negotiated (ssh/algorithms:negotiate-algorithms server-kexinit)))
      (is string= ssh/constants:+mac-hmac-sha2-512+
          (ssh/algorithms::negotiated-mac-c2s negotiated))
      (is string= ssh/constants:+mac-hmac-sha2-512+
          (ssh/algorithms::negotiated-mac-s2c negotiated)))))

(define-test kexinit-advertises-openssh-and-rfc5647-gcm
  :parent (:ssh/tests ssh/tests)
  (let* ((payload (ssh/algorithms:kexinit-payload))
         (kexinit (ssh/algorithms:parse-kexinit payload)))
    (dolist (algorithm
             (list ssh/constants:+cipher-aes256-gcm-openssh+
                   ssh/constants:+cipher-aes128-gcm-openssh+
                   ssh/constants:+aead-aes256-gcm+
                   ssh/constants:+aead-aes128-gcm+))
      (true (member algorithm
                    (ssh/algorithms::kexinit-encryption-algorithms-c2s kexinit)
                    :test #'string=)))
    (dolist (algorithm
             (list ssh/constants:+aead-aes256-gcm+
                   ssh/constants:+aead-aes128-gcm+))
      (true (member algorithm
                    (ssh/algorithms::kexinit-mac-algorithms-c2s kexinit)
                    :test #'string=)))))

(define-test negotiate-openssh-gcm-uses-implicit-authentication
  :parent (:ssh/tests ssh/tests)
  (let* ((payload (ssh/algorithms:kexinit-payload))
         (server-kexinit (ssh/algorithms:parse-kexinit payload)))
    (setf (ssh/algorithms::kexinit-encryption-algorithms-c2s server-kexinit)
          (list ssh/constants:+cipher-aes256-gcm-openssh+)
          (ssh/algorithms::kexinit-encryption-algorithms-s2c server-kexinit)
          (list ssh/constants:+cipher-aes256-gcm-openssh+)
          (ssh/algorithms::kexinit-mac-algorithms-c2s server-kexinit)
          (list ssh/constants:+mac-hmac-sha2-256+)
          (ssh/algorithms::kexinit-mac-algorithms-s2c server-kexinit)
          (list ssh/constants:+mac-hmac-sha2-256+))
    (let ((negotiated (ssh/algorithms:negotiate-algorithms server-kexinit)))
      (is string= ssh/constants:+cipher-aes256-gcm-openssh+
          (ssh/algorithms::negotiated-cipher-c2s negotiated))
      (false (ssh/algorithms::negotiated-mac-c2s negotiated))
      (false (ssh/algorithms::negotiated-mac-s2c negotiated)))))

(define-test negotiate-rfc5647-gcm-requires-the-matching-mac-name
  :parent (:ssh/tests ssh/tests)
  (let* ((payload (ssh/algorithms:kexinit-payload))
         (server-kexinit (ssh/algorithms:parse-kexinit payload)))
    (setf (ssh/algorithms::kexinit-encryption-algorithms-c2s server-kexinit)
          (list ssh/constants:+aead-aes128-gcm+)
          (ssh/algorithms::kexinit-encryption-algorithms-s2c server-kexinit)
          (list ssh/constants:+aead-aes128-gcm+)
          (ssh/algorithms::kexinit-mac-algorithms-c2s server-kexinit)
          (list ssh/constants:+aead-aes128-gcm+)
          (ssh/algorithms::kexinit-mac-algorithms-s2c server-kexinit)
          (list ssh/constants:+aead-aes128-gcm+))
    (let ((negotiated (ssh/algorithms:negotiate-algorithms server-kexinit)))
      (is string= ssh/constants:+aead-aes128-gcm+
          (ssh/algorithms::negotiated-mac-c2s negotiated)))
    (setf (ssh/algorithms::kexinit-mac-algorithms-c2s server-kexinit)
          (list ssh/constants:+mac-hmac-sha2-256+))
    (fail (ssh/algorithms:negotiate-algorithms server-kexinit)
        'error)))

(define-test gcm-algorithm-metadata-matches-the-ssh-profiles
  :parent (:ssh/tests ssh/tests)
  (dolist (algorithm
           (list ssh/constants:+cipher-aes128-gcm-openssh+
                 ssh/constants:+aead-aes128-gcm+))
    (is = 16 (ssh/transport::cipher-key-length algorithm))
    (is = 12 (ssh/transport::cipher-iv-length algorithm))
    (is = 16 (ssh/transport::cipher-block-size algorithm)))
  (dolist (algorithm
           (list ssh/constants:+cipher-aes256-gcm-openssh+
                 ssh/constants:+aead-aes256-gcm+))
    (is = 32 (ssh/transport::cipher-key-length algorithm))
    (is = 12 (ssh/transport::cipher-iv-length algorithm))
    (is = 16 (ssh/transport::cipher-block-size algorithm)))
  (is = 0 (ssh/transport::mac-key-length nil))
  (is = 0 (ssh/transport::mac-key-length ssh/constants:+aead-aes128-gcm+))
  (is = 0 (ssh/transport::mac-key-length ssh/constants:+aead-aes256-gcm+)))

(define-test gcm-kex-key-installation-is-directional-and-resets-the-iv
  :parent (:ssh/tests ssh/tests)
  (let* ((ps (ssh/packet:make-packet-stream (make-input-stream "")))
         (result (dummy-kex-result (ssh/tests:octets 9 8 7)))
         (negotiated
           (ssh/algorithms::make-negotiated
            :cipher-c2s ssh/constants:+cipher-aes256-gcm-openssh+
            :cipher-s2c ssh/constants:+aead-aes128-gcm+
            :mac-c2s nil
            :mac-s2c ssh/constants:+aead-aes128-gcm+)))
    (ssh/transport::install-kex-result-keys ps result negotiated :out)
    (of-type 'ssh/packet::gcm-protection
             (ssh/packet::packet-stream-protection-out ps))
    (of-type 'ssh/packet::classic-protection
             (ssh/packet::packet-stream-protection-in ps))
    (is = 32
        (length
         (ssh/packet::gcm-protection-key
          (ssh/packet::packet-stream-protection-out ps))))
    (is = 12
        (length
         (ssh/packet::gcm-protection-iv
          (ssh/packet::packet-stream-protection-out ps))))
    (ssh/packet::reserve-gcm-iv
     (ssh/packet::packet-stream-protection-out ps))
    (ssh/transport::install-kex-result-keys ps result negotiated :out)
    (is equalp
        (make-array 12 :element-type '(unsigned-byte 8) :initial-element 1)
        (ssh/packet::gcm-protection-iv
         (ssh/packet::packet-stream-protection-out ps)))
    (ssh/transport::install-kex-result-keys ps result negotiated :in)
    (of-type 'ssh/packet::gcm-protection
             (ssh/packet::packet-stream-protection-in ps))
    (is = 16
        (length
         (ssh/packet::gcm-protection-key
          (ssh/packet::packet-stream-protection-in ps))))))

(define-test kexinit-advertises-ext-info-c
  :parent (:ssh/tests ssh/tests)
  (let* ((payload (ssh/algorithms:kexinit-payload))
         (kexinit (ssh/algorithms:parse-kexinit payload))
         (algs (ssh/algorithms::kexinit-kex-algorithms kexinit)))
    (true (member ssh/constants::+ext-info-c+ algs :test #'string=))
    (false (member ssh/constants::+ext-info-s+ algs :test #'string=))))

(define-test newkeys-installation-replaces-directional-compression-contexts
  :parent (:ssh/tests ssh/tests)
  (let* ((ps (ssh/packet:make-packet-stream (make-input-stream "")))
         (result (dummy-kex-result (ssh/tests:octets 1 2 3)))
         (negotiated
           (ssh/algorithms::make-negotiated
            :cipher-c2s ssh/constants:+cipher-aes128-ctr+
            :cipher-s2c ssh/constants:+cipher-aes128-ctr+
            :mac-c2s ssh/constants:+mac-hmac-sha2-256+
            :mac-s2c ssh/constants:+mac-hmac-sha2-256+
            :compression-c2s ssh/constants:+compression-zlib+
            :compression-s2c ssh/constants:+compression-none+)))
    (ssh/transport::install-kex-result-keys ps result negotiated :out)
    (let ((first (ssh/packet:packet-stream-compression-out ps)))
      (is string= "zlib" (ssh/compression:compressor-algorithm first))
      (ssh/compression:compress-payload first (ssh/tests:octets 94 1 2 3))
      (ssh/transport::install-kex-result-keys ps result negotiated :out)
      (false (eq first (ssh/packet:packet-stream-compression-out ps))))
    (ssh/transport::install-kex-result-keys ps result negotiated :in)
    (is string= "none"
        (ssh/compression:decompressor-algorithm
         (ssh/packet:packet-stream-compression-in ps)))))

(define-test openssh-zlib-is-deferred-until-userauth-success
  :parent (:ssh/tests ssh/tests)
  (let* ((ps (ssh/packet:make-packet-stream (make-input-stream "")))
         (result (dummy-kex-result (ssh/tests:octets 1 2 3)))
         (algorithm ssh/constants:+compression-zlib-openssh+)
         (negotiated
           (ssh/algorithms::make-negotiated
            :cipher-c2s ssh/constants:+cipher-aes128-ctr+
            :cipher-s2c ssh/constants:+cipher-aes128-ctr+
            :mac-c2s ssh/constants:+mac-hmac-sha2-256+
            :mac-s2c ssh/constants:+mac-hmac-sha2-256+
            :compression-c2s algorithm
            :compression-s2c algorithm))
         (transport
           (ssh/transport::make-transport
            :packet-stream ps
            :negotiated-compression-c2s algorithm
            :negotiated-compression-s2c algorithm)))
    (ssh/transport::install-kex-result-keys ps result negotiated :out)
    (ssh/transport::install-kex-result-keys ps result negotiated :in)
    (is string= "none"
        (ssh/compression:compressor-algorithm
         (ssh/packet:packet-stream-compression-out ps)))
    (is string= "none"
        (ssh/compression:decompressor-algorithm
         (ssh/packet:packet-stream-compression-in ps)))
    (ssh/transport::note-userauth-success transport)
    (is string= algorithm
        (ssh/compression:compressor-algorithm
         (ssh/packet:packet-stream-compression-out ps)))
    (is string= algorithm
        (ssh/compression:decompressor-algorithm
         (ssh/packet:packet-stream-compression-in ps)))
    (false (ssh/transport::transport-delayed-compression-triggered-p
            transport))))

(define-test decompression-errors-send-compression-disconnect
  :parent (:ssh/tests ssh/tests)
  (let* ((ps (ssh/packet:make-packet-stream (make-input-stream "")))
         (transport (ssh/transport::make-transport :packet-stream ps))
         (sent-payload nil)
         (original-recv (symbol-function 'ssh/packet:recv-packet))
         (original-send (symbol-function 'ssh/packet:send-packet)))
    (unwind-protect
         (progn
           (setf (symbol-function 'ssh/packet:recv-packet)
                 (lambda (packet-stream)
                   (declare (ignore packet-stream))
                   (error 'ssh/compression:compression-error
                          :message "malformed zlib stream"))
                 (symbol-function 'ssh/packet:send-packet)
                 (lambda (packet-stream payload)
                   (declare (ignore packet-stream))
                   (setf sent-payload payload)
                   0))
           (fail (ssh/transport::recv-transport-packet transport)
               'ssh/compression:compression-error)
           (true sent-payload)
           (let ((buffer (ssh/buffer:make-read-buffer sent-payload)))
             (is = ssh/constants:+msg-disconnect+
                 (ssh/buffer:read-byte* buffer))
             (is = ssh/constants:+disconnect-compression-error+
                 (ssh/buffer:read-uint32 buffer))))
      (setf (symbol-function 'ssh/packet:recv-packet) original-recv
            (symbol-function 'ssh/packet:send-packet) original-send))))

(define-test kexinit-advertises-directional-compression-lists
  :parent (:ssh/tests ssh/tests)
  (let* ((payload
           (ssh/algorithms:kexinit-payload
            :compression-algorithms-c2s '("none")
            :compression-algorithms-s2c '("zlib" "none")))
         (kexinit (ssh/algorithms:parse-kexinit payload)))
    (is equal '("none")
        (ssh/algorithms:kexinit-compression-algorithms-c2s kexinit))
    (is equal '("zlib" "none")
        (ssh/algorithms:kexinit-compression-algorithms-s2c kexinit))))

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
  (let ((payload (ext-info-payload (list (coerce '(255) '(vector (unsigned-byte 8)))
                                         (ssh/tests:octets 1 2 3)))))
    (fail (ssh/transport::parse-ext-info-payload payload)
        'ssh/transport:transport-error)))

(define-test ext-info-server-sig-algs-is-us-ascii-name-list
  :parent (:ssh/tests ssh/tests)
  (let ((payload (ext-info-payload (list "server-sig-algs"
                                         (ssh/tests:octets 115 115 104 255)))))
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
    (false (ssh/transport::transport-server-sig-algs transport))))

(define-test delay-compression-value-roundtrips-binary-name-lists
  :parent (:ssh/tests ssh/tests)
  (multiple-value-bind (c2s s2c)
      (ssh/transport::parse-delay-compression-value
       (ssh/transport::make-delay-compression-value
        '("zlib" "none") '("none")))
    (is equal '("zlib" "none") c2s)
    (is equal '("none") s2c)))

(define-test delay-compression-requires-both-parties-and-uses-client-order
  :parent (:ssh/tests ssh/tests)
  (let* ((transport
           (ssh/transport::make-transport
            :client-delay-compression-sent-p t
            :client-delay-compression-c2s '("zlib" "none")
            :client-delay-compression-s2c '("zlib" "none")))
         (delay-value
           (ssh/transport::make-delay-compression-value
            '("none" "zlib") '("zlib" "none"))))
    (ssh/transport::process-ext-info
     transport
     (ext-info-payload
      (list ssh/constants:+extension-delay-compression+ delay-value)))
    (is string= "zlib"
        (ssh/transport::transport-delayed-compression-c2s transport))
    (is string= "zlib"
        (ssh/transport::transport-delayed-compression-s2c transport))
    ;; A later EXT_INFO replaces the earlier one and removes the negotiation.
    (ssh/transport::process-ext-info transport (ext-info-payload))
    (false (ssh/transport::transport-delayed-compression-c2s transport))
    (false (ssh/transport::transport-delayed-compression-s2c transport))))

(define-test delayed-compression-without-common-algorithm-fails
  :parent (:ssh/tests ssh/tests)
  (let* ((ps (ssh/packet:make-packet-stream (make-input-stream "")))
         (transport
           (ssh/transport::make-transport
            :packet-stream ps
            :client-delay-compression-sent-p t
            :client-delay-compression-c2s '("zlib")
            :client-delay-compression-s2c '("zlib")))
         (sent-payload nil)
         (original-send (symbol-function 'ssh/packet:send-packet)))
    (unwind-protect
         (progn
           (setf (symbol-function 'ssh/packet:send-packet)
                 (lambda (packet-stream payload)
                   (declare (ignore packet-stream))
                   (setf sent-payload payload)
                   0))
           (fail
               (ssh/transport::process-ext-info
                transport
                (ext-info-payload
                 (list ssh/constants:+extension-delay-compression+
                       (ssh/transport::make-delay-compression-value
                        '("none") '("none")))))
               'ssh/transport:transport-error)
           (let ((buffer (ssh/buffer:make-read-buffer sent-payload)))
             (is = ssh/constants:+msg-disconnect+
                 (ssh/buffer:read-byte* buffer))
             (is = ssh/constants:+disconnect-key-exchange-failed+
                 (ssh/buffer:read-uint32 buffer))))
      (setf (symbol-function 'ssh/packet:send-packet) original-send))))

(define-test client-delay-compression-ext-info-is-a-complete-packet
  :parent (:ssh/tests ssh/tests)
  (let* ((pipe (ssh/tests/packet::make-pipe))
         (sender (ssh/packet:make-packet-stream pipe))
         (receiver (ssh/packet:make-packet-stream pipe))
         (transport
           (ssh/transport::make-transport
            :packet-stream sender
            :compression-policy :delayed
            :server-ext-info-s-p t)))
    (ssh/transport::send-client-delay-compression-ext-info transport)
    (let* ((payload (ssh/packet:recv-packet receiver))
           (extensions (ssh/transport::parse-ext-info-payload payload))
           (entry (assoc ssh/constants:+extension-delay-compression+
                         extensions
                         :test #'string=)))
      (is = ssh/constants:+msg-ext-info+ (aref payload 0))
      (true entry)
      (multiple-value-bind (c2s s2c)
          (ssh/transport::parse-delay-compression-value (cdr entry))
        (true (member ssh/constants:+compression-zlib+ c2s :test #'string=))
        (true (member ssh/constants:+compression-zlib+ s2c :test #'string=))
        (false (member ssh/constants:+compression-zlib-openssh+
                       c2s :test #'string=))
        (false (member ssh/constants:+compression-zlib-openssh+
                       s2c :test #'string=)))
      (true (ssh/transport::transport-client-delay-compression-sent-p
             transport)))))

(define-test userauth-success-triggers-directional-delayed-compression
  :parent (:ssh/tests ssh/tests)
  (let* ((pipe (ssh/tests/packet::make-pipe))
         (sender (ssh/packet:make-packet-stream pipe))
         (receiver (ssh/packet:make-packet-stream pipe))
         (transport
           (ssh/transport::make-transport
            :packet-stream sender
            :delayed-compression-c2s "zlib"
            :delayed-compression-s2c "zlib")))
    (ssh/transport::note-userauth-success transport)
    ;; NEWCOMPRESS itself uses the old outbound algorithm.
    (is equalp (ssh/tests:octets ssh/constants:+msg-newcompress+)
        (ssh/packet:recv-packet receiver))
    (is string= "zlib"
        (ssh/compression:compressor-algorithm
         (ssh/packet:packet-stream-compression-out sender)))
    (is string= "zlib"
        (ssh/compression:decompressor-algorithm
         (ssh/packet:packet-stream-compression-in sender)))
    (true (ssh/transport::transport-authentication-complete-p transport))
    (true (ssh/transport::transport-delayed-compression-triggered-p transport))))

(define-test server-kexinit-rejects-wrong-role-ext-info-c
  :parent (:ssh/tests ssh/tests)
  (let* ((payload (ssh/algorithms:kexinit-payload :include-ext-info-c-p nil))
         (kexinit (ssh/algorithms:parse-kexinit payload)))
    (setf (ssh/algorithms::kexinit-kex-algorithms kexinit)
          (append (ssh/algorithms::kexinit-kex-algorithms kexinit)
                  (list ssh/constants::+ext-info-c+)))
    (fail (ssh/transport::validate-server-kexinit kexinit)
        'ssh/transport::transport-error)))

(define-test strict-kex-negotiates-only-initial-mutual-support
  :parent (:ssh/tests ssh/tests)
  (let ((client (ssh/algorithms:parse-kexinit
                 (ssh/algorithms:kexinit-payload)))
        (server (ssh/algorithms:parse-kexinit (rekey-kexinit-payload))))
    (true (member "kex-strict-c-v00@openssh.com"
                  (ssh/algorithms:kexinit-kex-algorithms client) :test #'string=))
    (false (member "kex-strict-c-v00@openssh.com"
                   (ssh/algorithms:kexinit-kex-algorithms server) :test #'string=))
    (dolist (server-support '(nil t))
      (dolist (client-support '(nil t))
        (let ((transport (make-rekey-test-transport :session-id nil)))
          (setf (ssh/packet:packet-stream-packets-in
                 (ssh/transport:transport-packet-stream transport)) 1
                (ssh/algorithms:kexinit-kex-algorithms client)
                (when client-support '("kex-strict-c-v00@openssh.com"))
                (ssh/algorithms:kexinit-kex-algorithms server)
                (when server-support '("kex-strict-s-v00@openssh.com")))
          (ssh/transport::negotiate-strict-kex transport client server)
          (is eq (and client-support server-support)
              (ssh/transport::transport-strict-kex-p transport))
          ;; Rekey cannot enable or disable the initial decision.
          (setf (ssh/transport:transport-session-id transport) (ssh/tests:octets 1)
                (ssh/algorithms:kexinit-kex-algorithms client)
                '("kex-strict-c-v00@openssh.com")
                (ssh/algorithms:kexinit-kex-algorithms server)
                (unless server-support '("kex-strict-s-v00@openssh.com")))
          (ssh/transport::negotiate-strict-kex transport client server)
          (is eq (and client-support server-support)
              (ssh/transport::transport-strict-kex-p transport)))))))

(define-test strict-kex-rejects-preceding-packets-even-after-sequence-wrap
  :parent (:ssh/tests ssh/tests)
  (dolist (count (list 2 (1+ (ash 1 32))))
    (let* ((transport (make-rekey-test-transport :session-id nil))
           (client (ssh/algorithms:parse-kexinit
                    (ssh/algorithms:kexinit-payload)))
           (server (ssh/algorithms:parse-kexinit (rekey-kexinit-payload))))
      (setf (ssh/packet:packet-stream-packets-in
             (ssh/transport:transport-packet-stream transport)) count
            (ssh/algorithms:kexinit-kex-algorithms server)
            '("kex-strict-s-v00@openssh.com"))
      (fail (ssh/transport::negotiate-strict-kex transport client server)
            'transport-error))))

(define-test initial-kex-rejects-non-kex-and-duplicate-messages
  :parent (:ssh/tests ssh/tests)
  ;; OpenSSH strict dispatch rejects these at each handshake boundary.
  (dolist (message '(2 4 6 20 21))
    (dolist (kex '(ssh/kex:perform-kex-curve25519 ssh/kex:perform-kex-dh-group14))
      (fail (ssh/tests/kex::call-kex-with-reply
             (symbol-function kex) (ssh/tests:octets message)
             (lambda (&rest args) (declare (ignore args))))
            'ssh/packet:ssh-protocol-error))))

(define-test initial-kex-rejects-unexpected-packets-at-kexinit-and-newkeys
  :parent (:ssh/tests ssh/tests)
  (dolist (boundary '(:kexinit :newkeys))
    (dolist (payload (append (mapcar #'ssh/tests:octets '(2 4 6 99))
                            (when (eq boundary :newkeys)
                              (list (rekey-kexinit-payload)
                                    (ssh/tests:octets 21 0)))))
      (let* ((incoming (ssh/tests/packet::make-pipe))
             (outgoing (ssh/tests/packet::make-pipe))
             (packets (ssh/packet:make-packet-stream
                       (make-two-way-stream incoming outgoing)))
             (peer (ssh/packet:make-packet-stream incoming))
             (transport (ssh/transport::make-transport :packet-stream packets))
             (client (ssh/algorithms:kexinit-payload))
             (server (let ((ssh/algorithms::+kex-extension-markers+
                            '("kex-strict-s-v00@openssh.com")))
                       (ssh/algorithms:kexinit-payload)))
             (original (symbol-function 'ssh/kex:perform-kex-curve25519)))
        (ssh/packet:send-packet peer payload)
        (unwind-protect
             (progn
               (setf (symbol-function 'ssh/kex:perform-kex-curve25519)
                     (lambda (&rest args)
                       (declare (ignore args))
                       (dummy-kex-result (ssh/tests:octets 9))))
               (if (eq boundary :kexinit)
                   (fail (ssh/transport::perform-initial-key-exchange transport)
                         'transport-error)
                   (progn
                     (setf (ssh/packet:packet-stream-packets-in packets) 1)
                     (fail (ssh/transport::perform-negotiated-key-exchange
                            transport client server)
                           'transport-error))))
          (setf (symbol-function 'ssh/kex:perform-kex-curve25519) original))))))

(define-test strict-kex-resets-sequences-after-newkeys-in-each-direction
  :parent (:ssh/tests ssh/tests)
  (dolist (strict '(nil t))
    (dolist (initial '(nil t))
      (let* ((incoming (ssh/tests/packet::make-pipe))
             (outgoing (ssh/tests/packet::make-pipe))
             (packets (ssh/packet:make-packet-stream
                       (make-two-way-stream incoming outgoing)))
             (peer (ssh/packet:make-packet-stream incoming))
             (transport (ssh/transport::make-transport
                         :packet-stream packets :strict-kex-p (and strict (not initial))
                         :session-id (unless initial (ssh/tests:octets 9))))
             (client (ssh/algorithms:kexinit-payload
                      :include-ext-info-c-p (and initial strict)))
             (server (let ((ssh/algorithms::+kex-extension-markers+
                            '("kex-strict-s-v00@openssh.com")))
                       (ssh/algorithms:kexinit-payload :include-ext-info-c-p initial)))
             (original (symbol-function 'ssh/kex:perform-kex-curve25519)))
        (setf (ssh/packet:packet-stream-seq-in packets) (if initial 1 7)
              (ssh/packet:packet-stream-seq-out packets) (if initial 1 11)
              (ssh/packet:packet-stream-packets-in packets) 1
              (ssh/packet:packet-stream-packets-out packets) 1)
        (ssh/packet:send-packet peer (ssh/tests:octets 21))
        (unwind-protect
             (progn
               ;; Isolate the NEWKEYS boundary; packet framing and key installation run.
               (setf (symbol-function 'ssh/kex:perform-kex-curve25519)
                     (lambda (&rest args)
                       (declare (ignore args))
                       (dummy-kex-result (ssh/tests:octets 9))))
               (ssh/transport::perform-negotiated-key-exchange transport client server)
               (is = (if strict 0 (if initial 2 8))
                   (ssh/packet:packet-stream-seq-in packets))
               (is = (if strict 0 (if initial 2 12))
                   (ssh/packet:packet-stream-seq-out packets))
               (is = 2 (ssh/packet:packet-stream-packets-in packets))
               (is = 2 (ssh/packet:packet-stream-packets-out packets)))
          (setf (symbol-function 'ssh/kex:perform-kex-curve25519) original))))))

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

(define-test delayed-compression-blocks-client-rekey-until-authentication
  :parent (:ssh/tests ssh/tests)
  (let* ((transport (make-rekey-test-transport))
         (ps (ssh/transport:transport-packet-stream transport)))
    (setf (ssh/transport::transport-compression-policy transport) :delayed
          (ssh/transport::transport-rekey-packet-limit transport) 1
          (ssh/packet:packet-stream-packets-out ps) 1)
    (false (ssh/transport::transport-rekey-needed-p transport))
    (setf (ssh/transport::transport-authentication-complete-p transport) t)
    (true (ssh/transport::transport-rekey-needed-p transport))))

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

(define-test transport-recv-step-yields-after-control-messages
  :parent (:ssh/tests ssh/tests)
  (let* ((transport (ssh/transport::make-transport))
         (application-packet (ssh/tests:octets ssh/constants:+msg-service-accept+))
         (control-packets
           (list (ssh/tests:octets ssh/constants:+msg-ignore+ 0 0 0 0)
                 (ssh/tests:octets ssh/constants:+msg-debug+ 0 0 0 0 0 0 0 0 0)
                 (ext-info-payload '("server-sig-algs" "rsa-sha2-512")))))
    (dolist (packet (append control-packets (list application-packet)))
      (ssh/transport::enqueue-pending-packet transport packet))
    (loop for remaining downfrom 3 to 1
          do (false (ssh/transport::transport-recv-step transport))
             (is = remaining (ssh/transport::transport-pending-packet-count transport)))
    (is equal '("rsa-sha2-512")
        (ssh/transport::transport-server-sig-algs transport))
    (is equalp application-packet (ssh/transport::transport-recv-step transport))
    (is = 0 (ssh/transport::transport-pending-packet-count transport))
    ;; Blocking callers must still skip all transport-only messages.
    (dolist (packet (append control-packets (list application-packet)))
      (ssh/transport::enqueue-pending-packet transport packet))
    (is equalp application-packet
        (ssh/transport::transport-recv-skipping-global
         transport ssh/constants:+msg-service-accept+))))

(define-test transport-recv-step-yields-after-rekey
  :parent (:ssh/tests ssh/tests)
  (dolist (client-initiated-p '(nil t))
    (let* ((transport (make-rekey-test-transport))
           (session-id (ssh/transport::transport-session-id transport))
           (packet-stream (ssh/transport::transport-packet-stream transport))
           (incoming (list (rekey-kexinit-payload)
                           (ssh/tests:octets ssh/constants:+msg-newkeys+)))
           (sent nil)
           (original-send (symbol-function 'ssh/packet:send-packet))
           (original-recv (symbol-function 'ssh/packet:recv-packet))
           (original-curve (symbol-function 'ssh/kex:perform-kex-curve25519)))
      (setf (ssh/transport::transport-rekey-seconds-limit transport) nil)
      (when client-initiated-p
        (setf (ssh/transport::transport-rekey-packet-limit transport) 1
              (ssh/packet:packet-stream-packets-out packet-stream) 1))
      (unwind-protect
           (progn
             (setf (symbol-function 'ssh/packet:send-packet)
                   (lambda (stream payload)
                     (declare (ignore stream))
                     (push (aref payload 0) sent)
                     0)
                   (symbol-function 'ssh/packet:recv-packet)
                   (lambda (stream)
                     (declare (ignore stream))
                     (or (pop incoming)
                         (error "Receive tried to read beyond the rekey exchange")))
                   (symbol-function 'ssh/kex:perform-kex-curve25519)
                   (lambda (&rest args)
                     (declare (ignore args))
                     (dummy-kex-result session-id)))
             (false (ssh/transport::transport-recv-step transport))
             (false incoming)
             (is equal (list ssh/constants:+msg-kexinit+ ssh/constants:+msg-newkeys+)
                 (reverse sent))
             (is equalp session-id (ssh/transport::transport-session-id transport)))
        (setf (symbol-function 'ssh/packet:send-packet) original-send
              (symbol-function 'ssh/packet:recv-packet) original-recv
              (symbol-function 'ssh/kex:perform-kex-curve25519) original-curve)))))

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
