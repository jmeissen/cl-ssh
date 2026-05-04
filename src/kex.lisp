;;;; SSH key exchange — curve25519-sha256 and diffie-hellman-group14-sha256.
;;;;
;;;; curve25519-sha256 (draft-ietf-curdle-ssh-curves):
;;;;   - Sending SSH_MSG_KEX_ECDH_INIT
;;;;   - Receiving SSH_MSG_KEX_ECDH_REPLY
;;;;   - Computing the exchange hash H (SHA-256; e/f as SSH strings)
;;;;   - Deriving six symmetric keys from K and H (RFC 4253 §7.2)
;;;;
;;;; diffie-hellman-group14-sha256 (RFC 4253 §8, RFC 3526 §3):
;;;;   - Sending SSH_MSG_KEXDH_INIT
;;;;   - Receiving SSH_MSG_KEXDH_REPLY
;;;;   - Computing the exchange hash H (SHA-256; e/f as SSH mpints)
;;;;   - Same key derivation as curve25519-sha256
;;;;
;;;; IMPORTANT — byte-order note:
;;;;   Ironclad's ec-encode-scalar for Curve25519 uses :big-endian NIL,
;;;;   so all Curve25519 byte vectors (public keys, shared secret) are
;;;;   little-endian.  They must be reversed before encoding as SSH mpints
;;;;   (which are big-endian two's-complement, RFC 4251 §5).
;;;;
;;;; JOURNALING:
;;;;   The two non-deterministic operations — ephemeral key generation
;;;;   and the network receive of the ECDH reply — are wrapped with
;;;;   jrn:replayed.  When no WITH-JOURNALING is active these are no-ops.
;;;;   When recording they capture the bytes; when replaying they return
;;;;   the captured bytes so tests run offline and deterministically.

(uiop:define-package ssh/kex
  (:use #:cl)
  (:import-from #:ssh/constants
                #:+msg-kex-ecdh-init+
                #:+msg-kex-ecdh-reply+
                #:+msg-newkeys+)
  (:import-from #:ssh/buffer
                #:make-write-buffer #:write-byte* #:write-uint32 #:write-string*
                #:write-mpint #:write-raw-bytes #:buffer-to-octets
                #:make-read-buffer #:read-byte* #:read-uint32 #:read-string*
                #:read-mpint #:read-remaining-bytes)
  (:import-from #:ssh/packet
                #:send-packet #:recv-packet #:ssh-protocol-error)
  (:export
   #:kex-result
   #:kex-result-session-id
   #:kex-result-shared-secret
   #:kex-result-exchange-hash
   #:kex-result-iv-c2s
   #:kex-result-iv-s2c
   #:kex-result-key-c2s
   #:kex-result-key-s2c
   #:kex-result-mac-c2s
   #:kex-result-mac-s2c
   #:perform-kex-curve25519
   #:perform-kex-dh-group14
   ;; Exported for direct testing
   #:build-exchange-hash
   #:build-exchange-hash-dh
   #:reverse-octets
   #:curve25519-bytes->mpint-integer
   #:derive-key
   #:*kex-exchange-data*
   ;; Group 14 parameters (exported for tests)
   #:+dh-group14-p+
   #:+dh-group14-g+))

(in-package #:ssh/kex)

;;;; Result structure

(defstruct kex-result
  "All material produced by a successful key exchange."
  session-id      ; octet vector — fixed for the lifetime of the connection
  shared-secret   ; CL integer K (kept for potential re-exchange)
  exchange-hash   ; octet vector H (= session-id on first exchange)
  iv-c2s iv-s2c
  key-c2s key-s2c
  mac-c2s mac-s2c)

;;;; Byte-order conversion

(defun reverse-octets (octets)
  "Return a fresh octet vector with the bytes of OCTETS in reverse order."
  (let* ((n   (length octets))
         (rev (make-array n :element-type '(unsigned-byte 8))))
    (dotimes (i n rev)
      (setf (aref rev i) (aref octets (- n 1 i))))))

(defun curve25519-bytes->mpint-integer (raw-bytes)
  "Convert the raw X25519 DH output to a CL integer for SSH mpint encoding.

   IMPORTANT — OpenSSH convention:
   OpenSSH passes the X25519 output bytes directly to sshbuf_put_bignum2_bytes
   WITHOUT reversing them, even though RFC 7748 specifies X25519 output in
   little-endian format.  The result is that the LE bytes are treated as a
   big-endian integer for the SSH mpint.  We replicate this behaviour exactly
   so that our exchange hash matches what OpenSSH computes.

   DO NOT add byte reversal here.  'reverse-octets' exists for testing only."
  (let ((n 0))
    (loop for b across raw-bytes          ; no reversal — matches OpenSSH
          do (setf n (logior (ash n 8) b)))
    n))

;;;; Debug hook

(defvar *kex-exchange-data* nil
  "When bound to a non-NIL list, `build-exchange-hash` pushes a plist of all
   hash inputs and the resulting H onto it before returning.
   Bind it in tests: (let ((ssh/kex:*kex-exchange-data* (list))) ...)
   NIL in normal production use.")

;;;; Exchange hash construction (RFC 5656 §4, curve25519-sha256 §3)

(defun build-exchange-hash (v-c v-s i-c i-s k-s q-c q-s k)
  "Compute SHA-256 over the concatenated exchange-hash inputs.

   V-C, V-S  — version strings (without CRLF), as octet vectors
   I-C, I-S  — raw KEXINIT payloads (including the msg-type byte)
   K-S       — server host-key blob (raw bytes of the SSH string value)
   Q-C, Q-S  — ephemeral public keys (32-byte little-endian Curve25519)
   K         — shared secret as a CL integer (big-endian mpint encoding)"
  (let ((buf (make-write-buffer)))
    (write-string* buf v-c)
    (write-string* buf v-s)
    (write-string* buf i-c)
    (write-string* buf i-s)
    (write-string* buf k-s)
    (write-string* buf q-c)
    (write-string* buf q-s)
    (write-mpint   buf k)
    (let ((h (ironclad:digest-sequence :sha256 (buffer-to-octets buf))))
      (when *kex-exchange-data*
        (push (list :v-c v-c :v-s v-s :i-c i-c :i-s i-s
                    :k-s k-s :q-c q-c :q-s q-s :k k :hash h)
              *kex-exchange-data*))
      h)))

;;;; Key derivation (RFC 4253 §7.2)

(defun derive-key (k h letter session-id needed-bytes)
  "Derive NEEDED-BYTES of key material from shared secret K, exchange hash H,
   derivation LETTER (#\\A–#\\F), and SESSION-ID."
  (let* ((k-buf       (make-write-buffer))
         (letter-byte (make-array 1 :element-type '(unsigned-byte 8)
                                    :initial-element (char-code letter))))
    (write-mpint k-buf k)
    (let ((k-bytes (buffer-to-octets k-buf)))
      (labels ((hash (&rest parts)
                 (let ((d (ironclad:make-digest :sha256)))
                   (dolist (p parts)
                     (ironclad:update-digest d p))
                   (ironclad:produce-digest d)))
               (extend (current)
                 (if (>= (length current) needed-bytes)
                     (subseq current 0 needed-bytes)
                     (let ((more (hash k-bytes h current)))
                       (extend (concatenate '(vector (unsigned-byte 8)) current more))))))
        (extend (hash k-bytes h letter-byte session-id))))))

;;;; Main entry point

(defun perform-kex-curve25519 (packet-stream
                                client-version-octets
                                server-version-octets
                                client-kexinit-payload
                                server-kexinit-payload
                                session-id
                                key-verifier
                                &key (iv-length 16)
                                     (cipher-key-length 16)
                                     (mac-key-length 32))
  "Execute the curve25519-sha256 key exchange on PACKET-STREAM.

   CLIENT-VERSION-OCTETS / SERVER-VERSION-OCTETS
     — identification strings without CRLF, as octet vectors.
   CLIENT-KEXINIT-PAYLOAD / SERVER-KEXINIT-PAYLOAD
     — raw bytes of the respective SSH_MSG_KEXINIT messages (msg-type included).
   SESSION-ID
     — NIL on the first exchange (H becomes the session-id);
       on re-exchange pass the original session-id.
   KEY-VERIFIER
     — a function (lambda (host-key-blob exchange-hash signature-blob))
       that must verify the server host-key signature and signal an error
       on failure.

   Returns a KEX-RESULT struct."

  ;; 1. Generate ephemeral Curve25519 keypair.
  ;;    Wrapped in replayed so tests can replay a fixed keypair without
  ;;    network access.  Returns a list (Q_C-bytes private-x-bytes).
  (let* ((kp-bytes (jrn:replayed ("kex/ephemeral")
                     (multiple-value-bind (priv pub)
                         (ironclad:generate-key-pair :curve25519)
                       (list (copy-seq (ironclad:curve25519-key-y pub))
                             (copy-seq (getf (ironclad:destructure-private-key priv) :x))))))
         (q-c      (coerce (first  kp-bytes) '(simple-array (unsigned-byte 8) (*))))
         (priv-x   (coerce (second kp-bytes) '(simple-array (unsigned-byte 8) (*))))
         (priv-key (ironclad:make-private-key :curve25519 :x priv-x :y q-c)))

    ;; 2. Send SSH_MSG_KEX_ECDH_INIT
    (let ((init-buf (make-write-buffer)))
      (write-byte*   init-buf +msg-kex-ecdh-init+)
      (write-string* init-buf q-c)
      (send-packet packet-stream (buffer-to-octets init-buf)))

    ;; 3. Receive SSH_MSG_KEX_ECDH_REPLY.
    ;;    Wrapped in replayed so tests can inject a pre-recorded reply.
    (let* ((reply (jrn:replayed ("kex/ecdh-reply")
                    (recv-packet packet-stream))))
      (unless (= (aref reply 0) +msg-kex-ecdh-reply+)
        (error 'ssh-protocol-error
               :message (format nil "expected ECDH_REPLY (31), got ~D" (aref reply 0))))

      (let* ((rbuf     (make-read-buffer reply :start 1))
             (k-s-blob (read-string* rbuf))  ; server host key blob
             (q-s      (read-string* rbuf))  ; server ephemeral public key (32 bytes LE)
             (sig-blob (read-string* rbuf))) ; signature blob

        ;; 4. Compute shared secret K
        (let* ((server-pub (ironclad:make-public-key :curve25519 :y q-s))
               (shared-le  (ironclad:diffie-hellman priv-key server-pub))
               (k          (curve25519-bytes->mpint-integer shared-le)))

          ;; 5. Compute exchange hash H.
          ;;    checked records H and signals on mismatch during replay,
          ;;    catching any regression in hash computation.
          (let* ((h (jrn:checked ("kex/exchange-hash" :version 1)
                      (build-exchange-hash client-version-octets
                                           server-version-octets
                                           client-kexinit-payload
                                           server-kexinit-payload
                                           k-s-blob q-c q-s k))))

            ;; 6. Verify server host-key signature.
            ;;    The key-verifier is expected to signal on failure.
            ;;    A restart is available to capture the bytes for debugging.
            (restart-case
                (jrn:checked ("kex/verify" :version 1)
                  (funcall key-verifier k-s-blob h sig-blob)
                  t)
              (skip-host-key-verification ()
                :report "Skip host-key signature verification (DANGEROUS — debug only)"
                nil))

            ;; 7. First exchange: H becomes the session identifier
            (let ((sid (or session-id h)))

              ;; 8. Derive six symmetric keys
              (make-kex-result
               :session-id    sid
               :shared-secret k
               :exchange-hash h
               :iv-c2s  (derive-key k h #\A sid iv-length)
               :iv-s2c  (derive-key k h #\B sid iv-length)
               :key-c2s (derive-key k h #\C sid cipher-key-length)
               :key-s2c (derive-key k h #\D sid cipher-key-length)
               :mac-c2s (derive-key k h #\E sid mac-key-length)
               :mac-s2c (derive-key k h #\F sid mac-key-length)))))))))

;;;; -------------------------------------------------------------------------
;;;; DH Group 14 — diffie-hellman-group14-sha256 (RFC 4253 §8, RFC 3526 §3)
;;;; -------------------------------------------------------------------------

;;; RFC 3526 §3 — 2048-bit MODP group 14 prime and generator.
;;; defparameter is correct: bignums are not EQL-comparable across reloads
;;; so defconstant would signal a redefinition error on the second load.
(defparameter +dh-group14-p+
  #xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
  "RFC 3526 §3 — 2048-bit MODP group 14 safe prime.")

(defparameter +dh-group14-g+ 2
  "Generator for RFC 3526 group 14.")

;;;; DH helpers (internal)

(defun dh-group14-generate-private-key ()
  "Generate a 256-bit DH private key x satisfying 1 < x < (p-1)/2.
   A 256-bit key provides ~128-bit security against the 2048-bit group.
   Adding 2 to a uniform [0, 2^256) sample guarantees x > 1 without
   rejection sampling; any 256-bit value + 2 is far below q ≈ 2^2047."
  (+ 2 (ironclad:strong-random (ash 1 256))))

(defun dh-group14-compute-public (x)
  "Compute e = g^x mod p — the client DH public key.
   Uses timing-safe ironclad:expt-mod to protect the private key x."
  (ironclad:expt-mod +dh-group14-g+ x +dh-group14-p+))

(defun dh-group14-compute-secret (f x)
  "Compute K = f^x mod p — the shared DH secret.
   Uses timing-safe ironclad:expt-mod to protect the private key x."
  (ironclad:expt-mod f x +dh-group14-p+))

;;;; Exchange hash for finite-field DH (RFC 4253 §8)

(defun build-exchange-hash-dh (v-c v-s i-c i-s k-s e f k)
  "Compute the SHA-256 exchange hash for diffie-hellman-group14-sha256.

   V-C, V-S  — version strings (without CRLF) as octet vectors
   I-C, I-S  — raw KEXINIT payloads (including msg-type byte)
   K-S       — server host-key blob (raw bytes of the SSH string value)
   E         — client DH public key as a CL integer (encoded as mpint)
   F         — server DH public key as a CL integer (encoded as mpint)
   K         — shared secret as a CL integer (encoded as mpint)

   Key difference from build-exchange-hash: e and f are SSH mpints here,
   not SSH strings.  RFC 4253 §8 specifies this format for classic DH."
  (let ((buf (make-write-buffer)))
    (write-string* buf v-c)
    (write-string* buf v-s)
    (write-string* buf i-c)
    (write-string* buf i-s)
    (write-string* buf k-s)
    (write-mpint   buf e)        ; mpint, not string — differs from ECDH hash
    (write-mpint   buf f)        ; mpint, not string
    (write-mpint   buf k)
    (ironclad:digest-sequence :sha256 (buffer-to-octets buf))))

;;;; Main entry point

(defun perform-kex-dh-group14 (packet-stream
                                client-version-octets
                                server-version-octets
                                client-kexinit-payload
                                server-kexinit-payload
                                session-id
                                key-verifier
                                &key (iv-length 16)
                                     (cipher-key-length 16)
                                     (mac-key-length 32))
  "Execute the diffie-hellman-group14-sha256 key exchange on PACKET-STREAM.

   Parameters and return value are identical to PERFORM-KEX-CURVE25519;
   callers can substitute one for the other based on the negotiated algorithm."

  ;; 1. Generate ephemeral DH keypair.
  ;;    Wrapped in replayed so tests can inject a fixed keypair offline.
  ;;    Returns a list (x e) of CL integers.
  (let* ((kp (jrn:replayed ("kex/dh-group14/keypair")
               (let ((x (dh-group14-generate-private-key)))
                 (list x (dh-group14-compute-public x)))))
         (x  (first  kp))   ; private key — never sent on the wire
         (e  (second kp)))  ; public key  — sent as mpint in KEXDH_INIT

    ;; 2. Send SSH_MSG_KEXDH_INIT (msg type 30, same byte as KEX_ECDH_INIT)
    (let ((init-buf (make-write-buffer)))
      (write-byte*  init-buf +msg-kex-ecdh-init+)
      (write-mpint  init-buf e)
      (send-packet packet-stream (buffer-to-octets init-buf)))

    ;; 3. Receive SSH_MSG_KEXDH_REPLY (msg type 31).
    ;;    Wrapped in replayed so tests can inject a pre-recorded reply.
    (let* ((reply (jrn:replayed ("kex/dh-group14/reply")
                    (recv-packet packet-stream))))
      (unless (= (aref reply 0) +msg-kex-ecdh-reply+)
        (error 'ssh-protocol-error
               :message (format nil "expected KEXDH_REPLY (31), got ~D"
                                (aref reply 0))))

      (let* ((rbuf     (make-read-buffer reply :start 1))
             (k-s-blob (read-string* rbuf))  ; server host-key blob
             (f        (read-mpint   rbuf))  ; server DH public key (mpint)
             (sig-blob (read-string* rbuf))) ; signature blob

        ;; 4. Validate f: RFC 4253 §8 requires 1 < f < p-1.
        (unless (and (> f 1) (< f (1- +dh-group14-p+)))
          (error 'ssh-protocol-error
                 :message "server DH public key f is out of valid range"))

        ;; 5. Compute shared secret K = f^x mod p.
        (let* ((k (dh-group14-compute-secret f x)))

          ;; 6. Compute exchange hash H.
          (let* ((h (jrn:checked ("kex/dh-group14/exchange-hash" :version 1)
                      (build-exchange-hash-dh client-version-octets
                                              server-version-octets
                                              client-kexinit-payload
                                              server-kexinit-payload
                                              k-s-blob e f k))))

            ;; 7. Verify server host-key signature.
            (restart-case
                (jrn:checked ("kex/dh-group14/verify" :version 1)
                  (funcall key-verifier k-s-blob h sig-blob)
                  t)
              (skip-host-key-verification ()
                :report "Skip host-key signature verification (DANGEROUS — debug only)"
                nil))

            ;; 8. First exchange: H becomes the session identifier.
            (let ((sid (or session-id h)))

              ;; 9. Derive six symmetric keys (RFC 4253 §7.2).
              (make-kex-result
               :session-id    sid
               :shared-secret k
               :exchange-hash h
               :iv-c2s  (derive-key k h #\A sid iv-length)
               :iv-s2c  (derive-key k h #\B sid iv-length)
               :key-c2s (derive-key k h #\C sid cipher-key-length)
               :key-s2c (derive-key k h #\D sid cipher-key-length)
               :mac-c2s (derive-key k h #\E sid mac-key-length)
               :mac-s2c (derive-key k h #\F sid mac-key-length)))))))))
