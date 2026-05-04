;;;; Tests for ssh/kex — key exchange and key derivation.

(defpackage :ssh/tests/kex
  (:use :cl :parachute)
  (:import-from :ssh/tests #:octets)
  (:import-from :ssh/kex
                #:kex-result
                #:kex-result-iv-c2s #:kex-result-iv-s2c
                #:kex-result-key-c2s #:kex-result-key-s2c
                #:kex-result-mac-c2s #:kex-result-mac-s2c
                #:kex-result-session-id))

(in-package :ssh/tests/kex)

(defun reverse-octets (v)   (ssh/kex::reverse-octets v))
(defun curve25519->integer (le) (ssh/kex::curve25519-bytes->mpint-integer le))
(defun derive-key (k h letter sid n) (ssh/kex::derive-key k h letter sid n))

;;; ---- reverse-octets ----------------------------------------------------

(define-test reverse-octets-empty
  :parent (:ssh/tests ssh/tests)
  (is equalp (octets) (reverse-octets (octets))))

(define-test reverse-octets-single
  :parent (:ssh/tests ssh/tests)
  (is equalp (octets 42) (reverse-octets (octets 42))))

(define-test reverse-octets-multiple
  :parent (:ssh/tests ssh/tests)
  (is equalp (octets 3 2 1) (reverse-octets (octets 1 2 3)))
  (is equalp (octets 4 3 2 1) (reverse-octets (octets 1 2 3 4))))

;;; ---- curve25519-bytes->mpint-integer ------------------------------------

(define-test curve25519-le-to-integer-zero
  :parent (:ssh/tests ssh/tests)
  (let ((zero (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (is = 0 (curve25519->integer zero))))

;;; NOTE: curve25519-bytes->mpint-integer uses OpenSSH convention — the raw
;;; X25519 output bytes are treated as big-endian WITHOUT reversal, matching
;;; sshbuf_put_bignum2_bytes.  So byte[0] is the MOST significant byte.

(define-test curve25519-raw-byte0-is-msb
  :parent (:ssh/tests ssh/tests)
  "byte[0] = 1, all others 0 → integer = 2^(31*8) = 2^248 (MSB position)."
  (let ((v (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref v 0) 1)
    (is = (expt 2 248) (curve25519->integer v))))

(define-test curve25519-raw-byte31-is-lsb
  :parent (:ssh/tests ssh/tests)
  "byte[31] = 1, all others 0 → integer = 1 (LSB position)."
  (let ((v (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref v 31) 1)
    (is = 1 (curve25519->integer v))))

(define-test curve25519-le-to-integer-big
  :parent (:ssh/tests ssh/tests)
  (let ((v (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xFF)))
    (is = (1- (expt 2 256)) (curve25519->integer v))))

;;; ---- key derivation (RFC 4253 §7.2) ------------------------------------

(defparameter *test-k* 1)

(defparameter *test-h*
  (ironclad:digest-sequence :sha256
                            (map '(vector (unsigned-byte 8)) #'char-code "test-exchange-hash")))

(define-test key-derivation-lengths
  :parent (:ssh/tests ssh/tests)
  (dolist (n '(16 32 64))
    (let ((key (derive-key *test-k* *test-h* #\A *test-h* n)))
      (is = n (length key)
          (format nil "derive-key with n=~D returned wrong length" n)))))

(define-test key-derivation-distinct-letters
  :parent (:ssh/tests ssh/tests)
  (let ((keys (loop for letter in '(#\A #\B #\C #\D #\E #\F)
                    collect (derive-key *test-k* *test-h* letter *test-h* 32))))
    (loop for (a . rest) on keys
          do (loop for b in rest
                   do (false (equalp a b))))))

(define-test key-derivation-deterministic
  :parent (:ssh/tests ssh/tests)
  (let ((k1 (derive-key *test-k* *test-h* #\C *test-h* 16))
        (k2 (derive-key *test-k* *test-h* #\C *test-h* 16)))
    (is equalp k1 k2)))

(define-test key-derivation-extension
  :parent (:ssh/tests ssh/tests)
  ;; First 32 bytes of a 64-byte key must equal the standalone 32-byte key
  (let ((short (derive-key *test-k* *test-h* #\E *test-h* 32))
        (long  (derive-key *test-k* *test-h* #\E *test-h* 64)))
    (is equalp short (subseq long 0 32))))

;;; ---- Curve25519 structural tests ---------------------------------------

(define-test curve25519-keygen-produces-32-bytes
  :parent (:ssh/tests ssh/tests)
  (multiple-value-bind (priv pub)
      (ironclad:generate-key-pair :curve25519)
    (declare (ignore priv))
    (is = 32 (length (ironclad:curve25519-key-y pub)))))

(define-test curve25519-dh-produces-32-bytes
  :parent (:ssh/tests ssh/tests)
  (multiple-value-bind (priv-a pub-a)
      (ironclad:generate-key-pair :curve25519)
    (declare (ignore pub-a))
    (multiple-value-bind (priv-b pub-b)
        (ironclad:generate-key-pair :curve25519)
      (declare (ignore priv-b))
      (is = 32 (length (ironclad:diffie-hellman priv-a pub-b))))))

(define-test curve25519-dh-is-symmetric
  :parent (:ssh/tests ssh/tests)
  (multiple-value-bind (priv-a pub-a)
      (ironclad:generate-key-pair :curve25519)
    (multiple-value-bind (priv-b pub-b)
        (ironclad:generate-key-pair :curve25519)
      (is equalp
          (ironclad:diffie-hellman priv-a pub-b)
          (ironclad:diffie-hellman priv-b pub-a)))))

(define-test curve25519-shared-secret-as-integer-is-nonnegative
  :parent (:ssh/tests ssh/tests)
  (multiple-value-bind (priv-a pub-a)
      (ironclad:generate-key-pair :curve25519)
    (declare (ignore pub-a))
    (multiple-value-bind (priv-b pub-b)
        (ironclad:generate-key-pair :curve25519)
      (declare (ignore priv-b))
      (let* ((shared (ironclad:diffie-hellman priv-a pub-b))
             (k      (curve25519->integer shared)))
        (true (>= k 0))))))
