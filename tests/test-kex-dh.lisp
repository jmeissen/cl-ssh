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
                #:build-exchange-hash-dh))

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
  ;; Exercise our DH helpers with a hand-computed toy group.
  (let ((+dh-group14-p+ 23)
        (+dh-group14-g+ 2))
    (is = 12 (pub 10))
    (is = 16 (secret 9 3))
    (is = 16 (secret 8 5))))

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
  ;; Independently hashed RFC 4253 transcript. Positive E, F and K all need
  ;; mpint sign padding: 00 80, 00 ff and 00 80 00 respectively.
  (is equalp
      (ironclad:hex-string-to-byte-array
       "de491f369f05d5880a0e176ea7479c28597242e2699f62c8b677a26481de6db3")
      (build-exchange-hash-dh *v-c* *v-s* *i-c* *i-s* *k-s* #x80 #xff #x8000)))

;;; ---- Full in-process two-party exchange -----------------------------------

(define-test dh-group14-exchanges-signed-packets-on-rekey
  :parent (:ssh/tests ssh/tests)
  ;; Independent RFC 4253 vectors: x = 127, y = 255, fixture Ed25519 host key.
  ;; The public mpints need leading zero bytes; the original session ID is retained.
  ;; Intercept the external RNG call: ECL can compile calls to the
  ;; same-file private-key helper directly, bypassing SYMBOL-FUNCTION.
  ;; The real helper adds 2, so this still exercises private exponent 127.
  (ssh/tests/kex::check-kex-wire-exchange
   #'ssh/kex:perform-kex-dh-group14 'ironclad:strong-random '(125)
   #'ssh/buffer:write-mpint (ash 1 255) (octets 9 8 7)
   "1e000000110080000000000000000000000000000000"
   "23f0281bdc1a443e7545375435ad66496179d3bb4a608ee56fcd8760347b72e5"
   '("5aa3bf79a7c3bf134eee84f6"
     "86c56e3a1225bbce39486a25"
     "38d17a30300a0ccce3131459fb69ea8bb6863756e665179bd20eefa9bdad6a10"
     "b1583ba2776fd53e39e1d75271da3bb908e7c7366d7db2ef0ddc783f57a4e420"
     "a96abc111cfcc8733e6fc33c424e424526fad41f49be93239fec6d46f4f268031522f4b76ef03b851766a8716b5fd5f3fde75a8eb1fcc4ef03cf322ccc5c3e6a"
     "e10a3ecc064c62106ea6969f689cfe55a94b3fe1a1bab09df02747b2713bddf3c585396736736f3636abeac4d0cbc72e0614379ae7bc63c65c82beb333410d15")))
