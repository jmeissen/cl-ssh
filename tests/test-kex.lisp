;;;; Tests for ssh/kex — key exchange and key derivation.

(defpackage :ssh/tests/kex
  (:use :cl :parachute)
  (:import-from :ssh/tests #:octets)
  (:import-from :ssh/kex
                #:kex-result
                #:kex-result-iv-c2s #:kex-result-iv-s2c
                #:kex-result-key-c2s #:kex-result-key-s2c
                #:kex-result-mac-c2s #:kex-result-mac-s2c
                #:kex-result-session-id
                #:perform-kex-curve25519
                #:perform-kex-dh-group14))

(in-package :ssh/tests/kex)

(defun reverse-octets (v)   (ssh/kex::reverse-octets v))
(defun curve25519->integer (le) (ssh/kex::curve25519-bytes->mpint-integer le))
(defun derive-key (k h letter sid n) (ssh/kex::derive-key k h letter sid n))

(defparameter *test-v-c* (map '(vector (unsigned-byte 8)) #'char-code "SSH-2.0-test-client"))
(defparameter *test-v-s* (map '(vector (unsigned-byte 8)) #'char-code "SSH-2.0-test-server"))
(defparameter *test-i-c* (octets 20 1 2 3 4))
(defparameter *test-i-s* (octets 20 5 6 7 8))

(defun ecdh-reply (q-s)
  (let ((buf (ssh/buffer:make-write-buffer)))
    (ssh/buffer:write-byte* buf 31)
    (ssh/buffer:write-string* buf (octets 1 2 3))
    (ssh/buffer:write-string* buf q-s)
    (ssh/buffer:write-string* buf (octets 4 5 6))
    (ssh/buffer:buffer-to-octets buf)))

(defun dh-reply (f)
  (let ((buf (ssh/buffer:make-write-buffer)))
    (ssh/buffer:write-byte* buf 31)
    (ssh/buffer:write-string* buf (octets 1 2 3))
    (ssh/buffer:write-mpint buf f)
    (ssh/buffer:write-string* buf (octets 4 5 6))
    (ssh/buffer:buffer-to-octets buf)))

(defun call-kex-with-reply (function reply key-verifier)
  (let ((orig-send (symbol-function 'ssh/packet:send-packet))
        (orig-recv (symbol-function 'ssh/packet:recv-packet)))
    (unwind-protect
         (progn
           (setf (symbol-function 'ssh/packet:send-packet)
                 (lambda (&rest args)
                   (declare (ignore args))
                   0))
           (setf (symbol-function 'ssh/packet:recv-packet)
                 (lambda (&rest args)
                   (declare (ignore args))
                   reply))
           (funcall function nil
                    *test-v-c* *test-v-s* *test-i-c* *test-i-s* nil
                    key-verifier))
      (setf (symbol-function 'ssh/packet:send-packet) orig-send)
      (setf (symbol-function 'ssh/packet:recv-packet) orig-recv))))

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

;;; ---- KEX protocol rejection paths ----------------------------------------

(define-test curve25519-kex-rejects-short-server-public-key
  :parent (:ssh/tests ssh/tests)
  "RFC 8731 requires received Curve25519 public keys to be exactly 32 bytes."
  (let ((called-verifier nil))
    (fail (call-kex-with-reply
           #'perform-kex-curve25519
           (ecdh-reply (octets 1 2 3))
           (lambda (&rest args)
             (declare (ignore args))
             (setf called-verifier t)))
          'ssh/packet:ssh-protocol-error)
    (false called-verifier)))

(define-test curve25519-kex-rejects-all-zero-shared-secret
  :parent (:ssh/tests ssh/tests)
  "RFC 8731 requires aborting when X25519 produces an all-zero shared secret."
  (let ((called-verifier nil)
        (orig-dh (symbol-function 'ironclad:diffie-hellman))
        (server-public (make-array 32 :element-type '(unsigned-byte 8)
                                      :initial-element 0)))
    (setf (aref server-public 0) 9)
    (unwind-protect
         (progn
           (setf (symbol-function 'ironclad:diffie-hellman)
                 (lambda (&rest args)
                   (declare (ignore args))
                   (make-array 32 :element-type '(unsigned-byte 8)
                                  :initial-element 0)))
           (fail (call-kex-with-reply
                  #'perform-kex-curve25519
                  (ecdh-reply server-public)
                  (lambda (&rest args)
                    (declare (ignore args))
                    (setf called-verifier t)))
                 'ssh/packet:ssh-protocol-error))
      (setf (symbol-function 'ironclad:diffie-hellman) orig-dh))
    (false called-verifier)))

(define-test dh-kex-verifier-error-cannot-be-skipped
  :parent (:ssh/tests ssh/tests)
  "A host-key verifier error must abort KEX; no restart may bypass it."
  (let ((result
          (handler-case
              (handler-bind
                  ((error (lambda (e)
                            (declare (ignore e))
                            (let ((restart (find-restart 'ssh/kex::skip-host-key-verification)))
                              (when restart
                                (invoke-restart restart))))))
                (call-kex-with-reply
                 #'perform-kex-dh-group14
                 (dh-reply 2)
                 (lambda (&rest args)
                   (declare (ignore args))
                   (error "verifier failed")))
                :unexpected-success)
            (simple-error () :verifier-error)
            (error () :other-error))))
    (is eq :verifier-error result)))
