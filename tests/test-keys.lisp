;;;; Tests for ssh/keys — private key loading with and without passphrases.
;;;;
;;;; Fixtures (all under tests/fixtures/keys/):
;;;;
;;;;   id_ed25519_nopass       — Ed25519, unencrypted
;;;;   id_ed25519_aes256ctr    — Ed25519, aes256-ctr, passphrase "correct horse battery staple"
;;;;   id_ed25519_aes128cbc    — Ed25519, aes128-cbc, passphrase "correct horse battery staple"
;;;;   id_rsa_nopass           — RSA-2048, unencrypted
;;;;   id_rsa_aes256ctr        — RSA-2048, aes256-ctr, passphrase "correct horse battery staple"
;;;;
;;;; Test coverage:
;;;;   - Unencrypted Ed25519 and RSA keys still load correctly (regression guard)
;;;;   - Encrypted Ed25519 loads with correct passphrase (aes256-ctr and aes128-cbc)
;;;;   - Encrypted RSA loads with correct passphrase (aes256-ctr)
;;;;   - Wrong passphrase → KEY-ERROR (check1/check2 mismatch)
;;;;   - No passphrase → KEY-NEEDS-PASSPHRASE condition
;;;;   - SUPPLY-PASSPHRASE restart delivers the key without re-reading the file
;;;;   - Loaded key has the expected :type field
;;;;   - Ed25519 sign + verify round-trip with a passphrase-loaded key
;;;;   - RSA sign + verify round-trip with a passphrase-loaded key

(defpackage :ssh/tests/keys
  (:use :cl :parachute)
  (:import-from :ssh/keys
                #:load-private-key
                #:sign-auth-data
                #:verify-host-key-signature
                #:key-error
                #:key-needs-passphrase))

(in-package :ssh/tests/keys)

;;;; Helpers

(defparameter +passphrase+ "correct horse battery staple"
  "Passphrase used when generating all encrypted test fixtures.")

(defun fixture (filename)
  "Return the pathname for FILENAME inside tests/fixtures/keys/."
  (asdf:system-relative-pathname :ssh
                                 (concatenate 'string "tests/fixtures/keys/" filename)))

(defun key-type (key-info)
  (getf key-info :type))

(defun private-key (key-info)
  (getf key-info :private-key))

(defun public-key (key-info)
  (getf key-info :public-key))

(defun host-key-blob (wire-key-type public-key)
  "Build a server host-key blob with WIRE-KEY-TYPE as the embedded key type."
  (let ((buf (ssh/buffer:make-write-buffer)))
    (ssh/buffer:write-string* buf wire-key-type)
    (cond
      ((string= wire-key-type "ssh-ed25519")
       (ssh/buffer:write-string* buf (ironclad:ed25519-key-y public-key)))
      ((or (string= wire-key-type "ssh-rsa")
           (string= wire-key-type "rsa-sha2-256")
           (string= wire-key-type "rsa-sha2-512"))
       (ssh/buffer:write-mpint buf (ironclad:rsa-key-exponent public-key))
       (ssh/buffer:write-mpint buf (ironclad:rsa-key-modulus public-key)))
      (t
       (error "unsupported test key type: ~S" wire-key-type)))
    (ssh/buffer:buffer-to-octets buf)))

;;;; ---- Unencrypted keys (regression guard) --------------------------------

(define-test load-ed25519-nopass
  :parent (:ssh/tests ssh/tests)
  "Unencrypted Ed25519 key loads without passphrase."
  (let ((k (load-private-key (fixture "id_ed25519_nopass"))))
    (is string= "ssh-ed25519" (key-type k))
    (true (private-key k))
    (true (public-key k))))

(define-test load-rsa-nopass
  :parent (:ssh/tests ssh/tests)
  "Unencrypted RSA key loads without passphrase."
  (let ((k (load-private-key (fixture "id_rsa_nopass"))))
    (is string= "rsa-sha2-256" (key-type k))
    (true (private-key k))
    (true (public-key k))))

;;;; ---- Encrypted keys with correct passphrase -----------------------------

(define-test load-ed25519-aes256-ctr
  :parent (:ssh/tests ssh/tests)
  "Ed25519 key encrypted with aes256-ctr decrypts with correct passphrase."
  (let ((k (load-private-key (fixture "id_ed25519_aes256ctr")
                             :passphrase +passphrase+)))
    (is string= "ssh-ed25519" (key-type k))
    (true (private-key k))
    (true (public-key k))))

(define-test load-ed25519-aes128-cbc
  :parent (:ssh/tests ssh/tests)
  "Ed25519 key encrypted with aes128-cbc decrypts with correct passphrase."
  (let ((k (load-private-key (fixture "id_ed25519_aes128cbc")
                             :passphrase +passphrase+)))
    (is string= "ssh-ed25519" (key-type k))
    (true (private-key k))
    (true (public-key k))))

(define-test load-rsa-aes256-ctr
  :parent (:ssh/tests ssh/tests)
  "RSA key encrypted with aes256-ctr decrypts with correct passphrase."
  (let ((k (load-private-key (fixture "id_rsa_aes256ctr")
                             :passphrase +passphrase+)))
    (is string= "rsa-sha2-256" (key-type k))
    (true (private-key k))
    (true (public-key k))))

;;;; ---- Wrong passphrase ---------------------------------------------------

(define-test wrong-passphrase-ed25519
  :parent (:ssh/tests ssh/tests)
  "A wrong passphrase produces KEY-ERROR (check1/check2 mismatch)."
  (fail (load-private-key (fixture "id_ed25519_aes256ctr")
                          :passphrase "this is definitely wrong")
        'key-error))

(define-test wrong-passphrase-rsa
  :parent (:ssh/tests ssh/tests)
  "A wrong passphrase on an RSA key produces KEY-ERROR."
  (fail (load-private-key (fixture "id_rsa_aes256ctr")
                          :passphrase "wrong")
        'key-error))

;;;; ---- No passphrase supplied ---------------------------------------------

(define-test no-passphrase-signals-condition
  :parent (:ssh/tests ssh/tests)
  "Loading an encrypted key without a passphrase signals KEY-NEEDS-PASSPHRASE."
  (fail (load-private-key (fixture "id_ed25519_aes256ctr"))
        'key-needs-passphrase))

(define-test no-passphrase-condition-carries-path
  :parent (:ssh/tests ssh/tests)
  "The KEY-NEEDS-PASSPHRASE condition carries the key file path."
  (let ((path (fixture "id_ed25519_aes256ctr")))
    (handler-case
        (progn (load-private-key path) (fail "Expected KEY-NEEDS-PASSPHRASE"))
      (key-needs-passphrase (c)
        (is equal path (ssh/keys:key-needs-passphrase-path c))))))

;;;; ---- SUPPLY-PASSPHRASE restart -----------------------------------------

(define-test supply-passphrase-restart-ed25519
  :parent (:ssh/tests ssh/tests)
  "Invoking SUPPLY-PASSPHRASE restart yields a valid key without re-reading the file."
  (let ((k (handler-bind
               ((key-needs-passphrase
                  (lambda (c)
                    (declare (ignore c))
                    (invoke-restart 'ssh/keys::supply-passphrase +passphrase+))))
             (load-private-key (fixture "id_ed25519_aes256ctr")))))
    (is string= "ssh-ed25519" (key-type k))
    (true (private-key k))))

(define-test supply-passphrase-restart-rsa
  :parent (:ssh/tests ssh/tests)
  "SUPPLY-PASSPHRASE restart works for an encrypted RSA key."
  (let ((k (handler-bind
               ((key-needs-passphrase
                  (lambda (c)
                    (declare (ignore c))
                    (invoke-restart 'ssh/keys::supply-passphrase +passphrase+))))
             (load-private-key (fixture "id_rsa_aes256ctr")))))
    (is string= "rsa-sha2-256" (key-type k))
    (true (private-key k))))

;;;; ---- Sign + verify round-trip ------------------------------------------

(define-test ed25519-sign-verify-nopass
  :parent (:ssh/tests ssh/tests)
  "Ed25519 sign/verify round-trip for an unencrypted key."
  (let* ((k        (load-private-key (fixture "id_ed25519_nopass")))
         (message  (map '(vector (unsigned-byte 8)) #'char-code "hello ssh"))
         (sig-blob (sign-auth-data k message))
         ;; sig-blob is: uint32(algo-len) algo uint32(sig-len) sig
         ;; Strip the outer string framing to get the raw 64-byte Ed25519 signature
         (sig-buf  (ssh/buffer:make-read-buffer sig-blob))
         (_algo    (ssh/buffer:read-string* sig-buf))
         (raw-sig  (ssh/buffer:read-string* sig-buf)))
    (declare (ignore _algo))
    (true (ironclad:verify-signature (public-key k) message raw-sig))))

(define-test ed25519-sign-verify-passphrase
  :parent (:ssh/tests ssh/tests)
  "Ed25519 sign/verify round-trip for a passphrase-protected key (aes256-ctr)."
  (let* ((k        (load-private-key (fixture "id_ed25519_aes256ctr")
                                     :passphrase +passphrase+))
         (message  (map '(vector (unsigned-byte 8)) #'char-code "hello encrypted ssh"))
         (sig-blob (sign-auth-data k message))
         (sig-buf  (ssh/buffer:make-read-buffer sig-blob))
         (_algo    (ssh/buffer:read-string* sig-buf))
         (raw-sig  (ssh/buffer:read-string* sig-buf)))
    (declare (ignore _algo))
    (true (ironclad:verify-signature (public-key k) message raw-sig))))

(define-test ed25519-sign-verify-aes128-cbc
  :parent (:ssh/tests ssh/tests)
  "Ed25519 sign/verify round-trip for a passphrase-protected key (aes128-cbc)."
  (let* ((k        (load-private-key (fixture "id_ed25519_aes128cbc")
                                     :passphrase +passphrase+))
         (message  (map '(vector (unsigned-byte 8)) #'char-code "aes128-cbc test"))
         (sig-blob (sign-auth-data k message))
         (sig-buf  (ssh/buffer:make-read-buffer sig-blob))
         (_algo    (ssh/buffer:read-string* sig-buf))
         (raw-sig  (ssh/buffer:read-string* sig-buf)))
    (declare (ignore _algo))
    (true (ironclad:verify-signature (public-key k) message raw-sig))))

(define-test rsa-sign-verify-passphrase
  :parent (:ssh/tests ssh/tests)
  "RSA sign/verify round-trip for a passphrase-protected key (aes256-ctr)."
  (let* ((k           (load-private-key (fixture "id_rsa_aes256ctr")
                                        :passphrase +passphrase+))
         (message     (map '(vector (unsigned-byte 8)) #'char-code "rsa passphrase test"))
         (sig-blob    (sign-auth-data k message))
         (sig-buf     (ssh/buffer:make-read-buffer sig-blob))
         (algo        (map 'string #'code-char (ssh/buffer:read-string* sig-buf)))
         (raw-sig     (ssh/buffer:read-string* sig-buf))
         (digest-name (if (string= algo "rsa-sha2-512") :sha512 :sha256)))
    (true (ssh/keys::rsa-pkcs1-verify (public-key k) message raw-sig digest-name))))

;;;; ---- Host-key signature verification -------------------------------------

(define-test verify-host-key-signature-ed25519-valid
  :parent (:ssh/tests ssh/tests)
  "A matching negotiated Ed25519 algorithm, key blob, and signature is accepted."
  (let* ((k (load-private-key (fixture "id_ed25519_nopass")))
         (h (map '(vector (unsigned-byte 8)) #'char-code "host key exchange hash"))
         (key-blob (host-key-blob "ssh-ed25519" (public-key k)))
         (sig-blob (sign-auth-data k h)))
    (true (progn
            (verify-host-key-signature "ssh-ed25519" key-blob h sig-blob)
            t))))

(define-test verify-host-key-signature-rsa-sha2-valid
  :parent (:ssh/tests ssh/tests)
  "rsa-sha2-* signatures use the RFC 8332 ssh-rsa public key wire format."
  (let* ((k (load-private-key (fixture "id_rsa_nopass")))
         (h (map '(vector (unsigned-byte 8)) #'char-code "rsa host key exchange hash"))
         (key-blob (host-key-blob "ssh-rsa" (public-key k)))
         (sig-blob (sign-auth-data k h)))
    (true (progn
            (verify-host-key-signature "rsa-sha2-256" key-blob h sig-blob)
            t))))

(define-test verify-host-key-signature-rejects-algorithm-mismatch
  :parent (:ssh/tests ssh/tests)
  "The server-controlled signature algorithm must match negotiation."
  (let* ((k (load-private-key (fixture "id_ed25519_nopass")))
         (h (map '(vector (unsigned-byte 8)) #'char-code "mismatch hash"))
         (key-blob (host-key-blob "ssh-ed25519" (public-key k)))
         (sig-blob (sign-auth-data k h)))
    (fail (verify-host-key-signature "rsa-sha2-256" key-blob h sig-blob)
          'key-error)))

(define-test verify-host-key-signature-rejects-ed25519-key-type-mismatch
  :parent (:ssh/tests ssh/tests)
  "Negotiated Ed25519 cannot be satisfied by an RSA host-key blob."
  (let* ((ed (load-private-key (fixture "id_ed25519_nopass")))
         (rsa (load-private-key (fixture "id_rsa_nopass")))
         (h (map '(vector (unsigned-byte 8)) #'char-code "ed key type mismatch"))
         (key-blob (host-key-blob "ssh-rsa" (public-key rsa)))
         (sig-blob (sign-auth-data ed h)))
    (fail (verify-host-key-signature "ssh-ed25519" key-blob h sig-blob)
          'key-error)))

(define-test verify-host-key-signature-rejects-rsa-sha2-key-format-name
  :parent (:ssh/tests ssh/tests)
  "RFC 8332 rsa-sha2-* host keys must carry the ssh-rsa public key format name."
  (let* ((k (load-private-key (fixture "id_rsa_nopass")))
         (h (map '(vector (unsigned-byte 8)) #'char-code "rsa key type mismatch"))
         (key-blob (host-key-blob "rsa-sha2-256" (public-key k)))
         (sig-blob (sign-auth-data k h)))
    (fail (verify-host-key-signature "rsa-sha2-256" key-blob h sig-blob)
          'key-error)))
