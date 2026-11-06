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

(defun check-kex-wire-exchange (function key-generator key-values
                                write-public server-public session-id
                                expected-init expected-hash expected-keys)
  (let* ((incoming (ssh/tests/packet::make-pipe))
         (outgoing (ssh/tests/packet::make-pipe))
         (packets (ssh/packet:make-packet-stream (make-two-way-stream incoming outgoing)))
         (host-key (ssh/keys:load-private-key
                    (asdf:system-relative-pathname :ssh "tests/fixtures/keys/id_ed25519_nopass")))
         (host-buffer (ssh/buffer:make-write-buffer))
         (reply (ssh/buffer:make-write-buffer))
         (hash (ironclad:hex-string-to-byte-array expected-hash))
         (original-generator (symbol-function key-generator)))
    (ssh/buffer:write-string* host-buffer "ssh-ed25519")
    (ssh/buffer:write-string* host-buffer
                              (ironclad:ed25519-key-y (getf host-key :public-key)))
    (ssh/buffer:write-byte* reply 31)
    (ssh/buffer:write-string* reply (ssh/buffer:buffer-to-octets host-buffer))
    (funcall write-public reply server-public)
    (ssh/buffer:write-string* reply
                              (ssh/keys:sign-auth-data host-key hash :algorithm "ssh-ed25519"))
    (ssh/packet:send-packet (ssh/packet:make-packet-stream incoming)
                            (ssh/buffer:buffer-to-octets reply))
    (unwind-protect
         (progn
           ;; Only randomness is fixed; packet I/O, hashing and signature verification run.
           (setf (symbol-function key-generator)
                 (lambda (&rest args) (declare (ignore args)) (values-list key-values)))
           (let ((result
                   (funcall function packets *test-v-c* *test-v-s* *test-i-c* *test-i-s*
                            session-id
                            (lambda (key hash signature)
                              (ssh/keys:verify-host-key-signature
                               "ssh-ed25519" key hash signature))
                            :iv-length 12 :cipher-key-length 32 :mac-key-length 64)))
             (is equalp (ironclad:hex-string-to-byte-array expected-init)
                 (ssh/packet:recv-packet (ssh/packet:make-packet-stream outgoing)))
             (is equalp hash (ssh/kex:kex-result-exchange-hash result))
             (is equalp (or session-id hash) (kex-result-session-id result))
             (is equalp (mapcar #'ironclad:hex-string-to-byte-array expected-keys)
                 (list (kex-result-iv-c2s result) (kex-result-iv-s2c result)
                       (kex-result-key-c2s result) (kex-result-key-s2c result)
                       (kex-result-mac-c2s result) (kex-result-mac-s2c result)))))
      (setf (symbol-function key-generator) original-generator))))

(define-test curve25519-exchanges-signed-packets
  :parent (:ssh/tests ssh/tests)
  ;; Independent RFC 4253/8731 vectors: client scalar = 32 bytes of 7,
  ;; server scalar = 32 bytes of 11, and the fixture Ed25519 host key.
  (let* ((private (ironclad:make-private-key :curve25519
                    :x (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7)))
         (public (ironclad:make-public-key :curve25519 :y (ironclad:curve25519-key-y private))))
    (check-kex-wire-exchange
     #'perform-kex-curve25519 'ironclad:generate-key-pair (list private public)
     #'ssh/buffer:write-string* (ironclad:hex-string-to-byte-array "73b2d8b76aa9b53660032bc8f5d8bee3a3ae4e3b3a7fd49ade81f7347a34aa68") nil
     "1e0000002013be4feaeaf204c7fd3358fc9c00721881d174278128227ec674f37f7fe97b6d"
     "403b71805c57053ecc240452d131dafb6f102c9a121c8c0fa2c506ba6cbe4102"
     '("5a1a0dd15043e634e50be863"
       "3d3fe51b0a8e2472395f700c"
       "c2fe54f1b9cf74411691eaaac30e843b9f9bffc489aea156b3e3af5fb336ae94"
       "cd200c35c09443a00476f52f76685fa8e5615830cf6629639710832ebaff9615"
       "9325bf15073b8a42b87e52bbb236d5f6279ec7b6d4fb17617410e8367c910c5e2f15838e263a736545c1db6028803c2f66e1dec8854c7c21ec9691c756b4ea0d"
       "2edfc32598b2099c0fc487fef810e34f69a738b0d688f9a144f3ef632e0c933bd9eb506f631c6834c08b64cbb5ff731d666a69e812ffe119649196648984f84d"))))

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
  (dolist (n '(0 16 32 64))
    (let ((key (derive-key *test-k* *test-h* #\A *test-h* n)))
      (is = n (length key)
          (format nil "derive-key with n=~D returned wrong length" n)))))

(define-test key-derivation-known-answers
  :parent (:ssh/tests ssh/tests)
  ;; Independently encoded RFC 4253 §7.2 inputs: K=128 (mpint sign padding),
  ;; H=00..1f, session ID=20..3f. A includes three SHA-256 blocks.
  (let ((hash (map '(vector (unsigned-byte 8)) #'identity
                   (loop for i below 32 collect i)))
        (sid (map '(vector (unsigned-byte 8)) #'identity
                  (loop for i from 32 below 64 collect i))))
    (loop for letter across "ABCDEF"
          for hex in '("007e030594fb564e91eb9b6ade057c62e5cd8533b7f29d312c1a8d47a948a2dab2dab409fbd33d29826449eb1a9a391e9b19c44a1a48a058c19ef460636c5008e24fa8a6b9488965a4893650d217a0bbffd7a2d569d7b179a877ebe2db896cbe"
                       "818d861186a43e0e25da94f7d65fc358d4abf93aabcfd1c5ffcf32999e0eb3e3"
                       "7577515577a761149ea63323aecb15684449ff7683199ab0391f9f8ce39c47d8"
                       "2f68cf2eea01743f9ef86edd565a726cc1add40d0dc25bf69718b41332ab4b8d"
                       "aea9e3697de6ec2d7abccc328b3292e8bf083fb30e7260e75620c113cafe7c3188654c0d3055f3a4f7fc3c3aa1ac934b31997ad9ba161ced88dfb19c757cd461"
                       "1d0dc05a4e65127c9a1778819638136058b6bdf8b2daf7b5edc1caa64d46e59445db749f46c712ca462d7f79e28d773f149f0f2bf0e5ed9e6df7342ad3422483")
          for expected = (ironclad:hex-string-to-byte-array hex)
          do (is equalp expected (derive-key 128 hash letter sid (length expected))))))

;;; ---- Curve25519 structural tests ---------------------------------------

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
