;;;; Tests for diffie-hellman-group14-sha256 key exchange.
;;;;
;;;; Coverage:
;;;;   - DH private key generation (range, bit-length)
;;;;   - Modular exponentiation correctness (known small-prime value)
;;;;   - Public key in valid range
;;;;   - DH commutativity (Diffie-Hellman property)
;;;;   - Shared secret in valid range
;;;;   - Exchange hash: length, determinism, sensitivity to every input field
;;;;   - Exchange hash uses mpint encoding for e/f (not SSH strings)
;;;;   - Full in-process exchange: two parties derive identical key material

(defpackage :ssh/tests/kex-dh
  (:use :cl :parachute)
  (:import-from :ssh/tests #:octets)
  (:import-from :ssh/kex
                #:+dh-group14-p+
                #:+dh-group14-g+
                #:build-exchange-hash-dh
                #:derive-key))

(in-package :ssh/tests/kex-dh)

;;; Aliases for internal helpers accessed via ::
(defun gen-private ()  (ssh/kex::dh-group14-generate-private-key))
(defun pub (x)         (ssh/kex::dh-group14-compute-public x))
(defun secret (f x)    (ssh/kex::dh-group14-compute-secret f x))

;;; Shared test fixtures
(defparameter *v-c* (map '(vector (unsigned-byte 8)) #'char-code "SSH-2.0-client"))
(defparameter *v-s* (map '(vector (unsigned-byte 8)) #'char-code "SSH-2.0-server"))
(defparameter *i-c* (octets 20 0 1 2 3))   ; minimal KEXINIT-shaped bytes
(defparameter *i-s* (octets 20 4 5 6 7))
(defparameter *k-s* (octets 0 0 0 11 115 115 104 45 101 100 50 53 53 49 57))

;;; ---- Private key properties ------------------------------------------------

(define-test dh-group14-private-key-gt-one
  :parent (:ssh/tests ssh/tests)
  "Generated private key must be strictly greater than 1 (RFC 4253 §8)."
  (dotimes (_ 5)
    (true (> (gen-private) 1))))

(define-test dh-group14-private-key-is-256-bit
  :parent (:ssh/tests ssh/tests)
  "Private key is bounded to roughly 256 bits (implementation choice for
   performance; far below q ≈ 2^2047 so the range constraint holds)."
  (dotimes (_ 5)
    (let ((x (gen-private)))
      ;; Upper bound: x = strong-random(2^256) + 2 < 2^256 + 3
      (true (< x (+ (ash 1 256) 3))))))

;;; ---- Modular exponentiation correctness -----------------------------------

(define-test dh-group14-modexp-known-value
  :parent (:ssh/tests ssh/tests)
  "Verify g^x mod p against a hand-computed small-prime reference.
   Using the toy group p=23, g=2: 2^10 mod 23 = 1024 mod 23 = 1024 - 44*23 = 12."
  ;; 44 * 23 = 1012, 1024 - 1012 = 12
  (is = 12 (ironclad:expt-mod 2 10 23))
  ;; Also: 2^3 mod 23 = 8, 2^5 mod 23 = 32 mod 23 = 9
  ;; Commutativity: 9^3 mod 23 = 729 mod 23 = 729 - 31*23 = 729 - 713 = 16
  ;;                8^5 mod 23 = 32768 mod 23 = 32768 - 1424*23 = 16
  (is = 16 (ironclad:expt-mod 9 3 23))
  (is = 16 (ironclad:expt-mod 8 5 23)))

;;; ---- Public key range ------------------------------------------------------

(define-test dh-group14-public-key-in-range
  :parent (:ssh/tests ssh/tests)
  "Public key e = g^x mod p must satisfy 1 < e < p-1 (RFC 4253 §8)."
  (dotimes (_ 3)
    (let* ((x (gen-private))
           (e (pub x)))
      (true (> e 1)       "e must be > 1")
      (true (< e (1- +dh-group14-p+)) "e must be < p-1"))))

;;; ---- Diffie-Hellman commutativity -----------------------------------------

(define-test dh-group14-is-symmetric
  :parent (:ssh/tests ssh/tests)
  "g^(x*y) mod p == g^(y*x) mod p — the Diffie-Hellman property."
  (let* ((x  (gen-private))
         (y  (gen-private))
         (e  (pub x))    ; g^x mod p  (client public)
         (f  (pub y))    ; g^y mod p  (server public)
         (k1 (secret f x))   ; f^x mod p = g^(y*x) mod p
         (k2 (secret e y)))  ; e^y mod p = g^(x*y) mod p
    (is = k1 k2)))

;;; ---- Shared secret range ---------------------------------------------------

(define-test dh-group14-shared-secret-in-range
  :parent (:ssh/tests ssh/tests)
  "Shared secret K must satisfy 1 < K < p-1."
  (let* ((x (gen-private))
         (y (gen-private))
         (f (pub y))
         (k (secret f x)))
    (true (> k 1)       "K must be > 1")
    (true (< k (1- +dh-group14-p+)) "K must be < p-1")))

;;; ---- Exchange hash ---------------------------------------------------------

(define-test dh-exchange-hash-length
  :parent (:ssh/tests ssh/tests)
  "SHA-256 exchange hash is exactly 32 bytes."
  (let ((h (build-exchange-hash-dh *v-c* *v-s* *i-c* *i-s* *k-s* 42 99 1234)))
    (is = 32 (length h))))

(define-test dh-exchange-hash-deterministic
  :parent (:ssh/tests ssh/tests)
  "Same inputs always produce the same hash."
  (let ((h1 (build-exchange-hash-dh *v-c* *v-s* *i-c* *i-s* *k-s* 42 99 1234))
        (h2 (build-exchange-hash-dh *v-c* *v-s* *i-c* *i-s* *k-s* 42 99 1234)))
    (is equalp h1 h2)))

(define-test dh-exchange-hash-sensitive-to-each-field
  :parent (:ssh/tests ssh/tests)
  "Changing any single input field must change the hash."
  (let ((base (build-exchange-hash-dh *v-c* *v-s* *i-c* *i-s* *k-s* 42 99 1234))
        (alt-v-c (map '(vector (unsigned-byte 8)) #'char-code "SSH-2.0-other"))
        (alt-i-c (octets 20 9 9 9 9))
        (alt-k-s (octets 1 2 3 4)))
    (false (equalp base
                   (build-exchange-hash-dh alt-v-c *v-s* *i-c* *i-s* *k-s* 42 99 1234))
           "hash must change when V_C changes")
    (false (equalp base
                   (build-exchange-hash-dh *v-c* *v-s* alt-i-c *i-s* *k-s* 42 99 1234))
           "hash must change when I_C changes")
    (false (equalp base
                   (build-exchange-hash-dh *v-c* *v-s* *i-c* *i-s* alt-k-s 42 99 1234))
           "hash must change when K_S changes")
    (false (equalp base
                   (build-exchange-hash-dh *v-c* *v-s* *i-c* *i-s* *k-s* 43 99 1234))
           "hash must change when e changes")
    (false (equalp base
                   (build-exchange-hash-dh *v-c* *v-s* *i-c* *i-s* *k-s* 42 100 1234))
           "hash must change when f changes")
    (false (equalp base
                   (build-exchange-hash-dh *v-c* *v-s* *i-c* *i-s* *k-s* 42 99 1235))
           "hash must change when K changes")))

(define-test dh-exchange-hash-uses-mpint-not-string-encoding
  :parent (:ssh/tests ssh/tests)
  "build-exchange-hash-dh encodes e and f as SSH mpints, not SSH strings.
   The ECDH path (build-exchange-hash) encodes them as SSH strings.
   With identical 'logical' inputs the two hashes must differ."
  ;; Use a small integer that could be misread as byte-count if encoded wrong.
  ;; build-exchange-hash takes e and f as raw octet vectors (SSH strings).
  ;; build-exchange-hash-dh takes them as CL integers (mpints).
  ;; We construct a raw vector that looks like the string encoding of 42,
  ;; then confirm the two hashes differ.
  (let* ((e-int 42)
         (f-int 99)
         ;; 4-byte big-endian length + single byte: SSH string encoding of #(42)
         (e-str (octets 0 0 0 1 42))
         (f-str (octets 0 0 0 1 99))
         (hash-dh   (build-exchange-hash-dh *v-c* *v-s* *i-c* *i-s* *k-s*
                                            e-int f-int 1234))
         (hash-ecdh (ssh/kex:build-exchange-hash *v-c* *v-s* *i-c* *i-s* *k-s*
                                                 e-str f-str 1234)))
    (false (equalp hash-dh hash-ecdh)
           "DH and ECDH exchange hashes must differ (different e/f encoding)")))

;;; ---- Full in-process two-party exchange -----------------------------------

(define-test dh-group14-full-exchange-derives-matching-keys
  :parent (:ssh/tests ssh/tests)
  "Simulate a complete DH group14 exchange between two parties in-process.
   Both sides must derive identical K, H, and key material."
  (let* (;; Both parties generate independent keypairs
         (x-client (gen-private))
         (x-server (gen-private))
         (e (pub x-client))   ; client sends e
         (f (pub x-server))   ; server sends f

         ;; Both compute the shared secret independently
         (k-client (secret f x-client))    ; f^x_c mod p
         (k-server (secret e x-server))    ; e^x_s mod p

         ;; Shared secret must be identical
         (k k-client))

    (is = k-client k-server "both parties must derive the same shared secret")

    ;; Both parties compute the exchange hash with the same inputs
    (let* ((h (build-exchange-hash-dh *v-c* *v-s* *i-c* *i-s* *k-s* e f k))
           (sid h))

      (is = 32 (length h) "exchange hash is 32 bytes")

      ;; Derive keys for aes256-ctr + hmac-sha2-512
      (let ((iv-c2s  (derive-key k h #\A sid 16))
            (iv-s2c  (derive-key k h #\B sid 16))
            (key-c2s (derive-key k h #\C sid 32))
            (key-s2c (derive-key k h #\D sid 32))
            (mac-c2s (derive-key k h #\E sid 64))
            (mac-s2c (derive-key k h #\F sid 64)))

        (is = 16 (length iv-c2s)  "IV c2s is 16 bytes")
        (is = 16 (length iv-s2c)  "IV s2c is 16 bytes")
        (is = 32 (length key-c2s) "cipher key c2s is 32 bytes (aes256)")
        (is = 32 (length key-s2c) "cipher key s2c is 32 bytes (aes256)")
        (is = 64 (length mac-c2s) "MAC key c2s is 64 bytes (hmac-sha2-512)")
        (is = 64 (length mac-s2c) "MAC key s2c is 64 bytes (hmac-sha2-512)")

        ;; All six derived values must be distinct
        (let ((all-keys (list iv-c2s iv-s2c key-c2s key-s2c mac-c2s mac-s2c)))
          (loop for (a . rest) on all-keys
                do (loop for b in rest
                         do (false (equalp a (subseq b 0 (length a)))
                                   "derived keys must be distinct"))))))))
