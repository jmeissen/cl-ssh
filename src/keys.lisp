;;;; SSH public-key formats, parsing, and signature verification.
;;;;
;;;; Supported host-key types:
;;;;   ssh-ed25519       — Ed25519 (RFC 8709)
;;;;   rsa-sha2-256      — RSA with SHA-256 (RFC 8332)
;;;;   rsa-sha2-512      — RSA with SHA-512 (RFC 8332)
;;;;
;;;; RSA signature verification uses EMSA-PKCS1-v1_5 (PKCS #1 v2.2).
;;;; Ironclad's verify-signature for RSA performs a raw RSA operation
;;;; (sig^e mod n == msg), so we must build the DER-encoded EM manually
;;;; and pass it as the message.
;;;;
;;;; User private key loading:
;;;;   OpenSSH new format  ("-----BEGIN OPENSSH PRIVATE KEY-----")
;;;;     Unencrypted (cipher "none") and passphrase-protected keys are
;;;;     both supported.  Supported ciphers: aes128-ctr, aes256-ctr,
;;;;     aes128-cbc, aes256-cbc.  KDF: bcrypt (via Ironclad bcrypt-pbkdf).
;;;;   PEM PKCS#8 / PKCS#1 (standard RSA PEM) — not yet supported.

(uiop:define-package ssh/keys
  (:use #:cl)
  (:import-from #:ssh/constants
                #:+host-key-ed25519+
                #:+host-key-rsa-sha2-256+
                #:+host-key-rsa-sha2-512+)
  (:import-from #:ssh/buffer
                #:make-read-buffer
                #:read-byte*
                #:read-uint32
                #:read-string*
                #:read-mpint
                #:read-remaining-bytes
                #:make-write-buffer
                #:write-string*
                #:write-mpint
                #:write-uint32
                #:write-byte*
                #:write-raw-bytes
                #:buffer-to-octets
                #:utf-8-to-octets)
  (:export
   ;; Host key verification (called by kex layer)
   #:verify-host-key-signature
   ;; Public key wire-format parsing
   #:parse-public-key-blob
   ;; Public key fingerprint (SHA-256 base64, matches ssh-keygen output)
   #:public-key-fingerprint
   ;; User private key loading
   #:load-private-key
   ;; Signing (for publickey auth)
   #:sign-auth-data
   ;; Conditions
   #:key-error
   #:key-needs-passphrase
   #:key-needs-passphrase-path))

(in-package #:ssh/keys)

;;;; Conditions

(define-condition key-error (error)
  ((message :initarg :message :reader key-error-message))
  (:report (lambda (c s)
             (format s "SSH key error: ~A" (key-error-message c)))))

(define-condition key-needs-passphrase (key-error)
  ((path :initarg :path :reader key-needs-passphrase-path
         :initform nil))
  (:report (lambda (c s)
             (if (key-needs-passphrase-path c)
                 (format s "SSH key error: passphrase required for ~A"
                         (key-needs-passphrase-path c))
                 (format s "SSH key error: passphrase required for encrypted key"))))
  (:documentation
   "Signalled when an encrypted key is loaded without a passphrase.
    The restart SUPPLY-PASSPHRASE is available; invoke it with a string
    to retry decryption without re-reading the file."))

;;;; DER prefixes for PKCS1v1.5 (EMSA-PKCS1-v1_5, RFC 8017 §9.2 Note 1)

(defparameter +sha256-der-prefix+
  (coerce '(#x30 #x31 #x30 #x0d #x06 #x09
            #x60 #x86 #x48 #x01 #x65 #x03 #x04 #x02 #x01
            #x05 #x00 #x04 #x20)
          '(vector (unsigned-byte 8)))
  "DER AlgorithmIdentifier prefix for SHA-256 (19 bytes).")

(defparameter +sha512-der-prefix+
  (coerce '(#x30 #x51 #x30 #x0d #x06 #x09
            #x60 #x86 #x48 #x01 #x65 #x03 #x04 #x02 #x03
            #x05 #x00 #x04 #x40)
          '(vector (unsigned-byte 8)))
  "DER AlgorithmIdentifier prefix for SHA-512 (19 bytes).")

;;;; RSA PKCS1v1.5 verification

(defun rsa-pkcs1-verify (rsa-pub-key message sig-bytes digest-name)
  "Verify PKCS1v1.5 signature SIG-BYTES over MESSAGE using RSA-PUB-KEY.
   DIGEST-NAME is :sha256 or :sha512.

   Strategy: build the EMSA-PKCS1-v1_5 encoded message EM and delegate
   to Ironclad's verify-signature, which performs sig^e mod n == EM."
  (let* ((h       (ironclad:digest-sequence digest-name message))
         (prefix  (ecase digest-name
                    (:sha256 +sha256-der-prefix+)
                    (:sha512 +sha512-der-prefix+)))
         (t-bytes (concatenate '(vector (unsigned-byte 8)) prefix h))
         ;; Key size in bytes — inferred from signature length which OpenSSH
         ;; always pads to exactly ceil(|n| / 8) bytes.
         (k       (length sig-bytes))
         (ps-len  (- k (length t-bytes) 3)))
    (when (< ps-len 8)
      (error 'key-error :message "RSA key too small or malformed signature"))
    (let* ((ps (make-array ps-len :element-type '(unsigned-byte 8)
                                  :initial-element #xff))
           (em (concatenate '(vector (unsigned-byte 8))
                            #(0 1) ps #(0) t-bytes)))
      (ironclad:verify-signature rsa-pub-key em sig-bytes))))

;;;; Public key blob parsing

(defun parse-public-key-blob (blob)
  "Parse an SSH public key BLOB (the inner bytes, without length prefix).
   Returns a list (:type <string> :key <ironclad-key>)."
  (let* ((buf      (make-read-buffer blob))
         (key-type (map 'string #'code-char (read-string* buf))))
    (cond
      ((string= key-type +host-key-ed25519+)
       (let ((pk-bytes (read-string* buf)))
         (list :type key-type
               :key  (ironclad:make-public-key :ed25519 :y pk-bytes))))

      ((or (string= key-type "ssh-rsa")
           (string= key-type +host-key-rsa-sha2-256+)
           (string= key-type +host-key-rsa-sha2-512+))
       ;; Wire format: string(key-type) mpint(e) mpint(n)
       (let ((e (read-mpint buf))
             (n (read-mpint buf)))
         (list :type key-type
               :key  (ironclad:make-public-key :rsa :e e :n n))))

      (t
       (error 'key-error
              :message (format nil "unsupported host key type: ~S" key-type))))))

;;;; Signature blob parsing

(defun parse-signature-blob (blob)
  "Parse an SSH signature BLOB.
   Returns a list (:algorithm <string> :bytes <octet-vector>)."
  (let* ((buf       (make-read-buffer blob))
         (algo      (map 'string #'code-char (read-string* buf)))
         (sig-bytes (read-string* buf)))
    (list :algorithm algo :bytes sig-bytes)))

;;;; Host key fingerprint (SHA-256, base64 — matches ssh-keygen -l output)

(defun public-key-fingerprint (blob)
  "Return the SHA-256 fingerprint of the host key BLOB as a string of
   the form \"SHA256:<base64>\" (matching OpenSSH's ssh-keygen -l -E sha256)."
  (let* ((hash    (ironclad:digest-sequence :sha256 blob))
         (b64     (with-output-to-string (s)
                    (loop with table =
                          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                          for i from 0 below (length hash) by 3
                          for remaining = (- (length hash) i)
                          for b0 = (aref hash i)
                          for b1 = (if (> remaining 1) (aref hash (+ i 1)) 0)
                          for b2 = (if (> remaining 2) (aref hash (+ i 2)) 0)
                          do (write-char (char table (ash b0 -2)) s)
                             (write-char (char table (logior (ash (logand b0 3) 4)
                                                             (ash b1 -4))) s)
                             (if (> remaining 1)
                                 (write-char (char table (logior (ash (logand b1 15) 2)
                                                                 (ash b2 -6))) s)
                                 (write-char #\= s))
                             (if (> remaining 2)
                                 (write-char (char table (logand b2 63)) s)
                                 (write-char #\= s))))))
    (format nil "SHA256:~A" b64)))

;;;; Host key signature verification (entry point called from kex.lisp)

(defun verify-host-key-signature (sig-algorithm host-key-blob exchange-hash sig-blob)
  "Verify the server's host-key signature over EXCHANGE-HASH.

   SIG-ALGORITHM   — the negotiated host-key algorithm string
   HOST-KEY-BLOB   — raw bytes of the server's public key blob
   EXCHANGE-HASH   — the computed H from kex.lisp
   SIG-BLOB        — raw bytes of the signature blob

   On failure, signals KEY-ERROR.  The restart SHOW-VERIFICATION-DATA
   is available to inspect the raw bytes before unwinding."
  (let* ((key-info  (parse-public-key-blob host-key-blob))
         (key       (getf key-info :key))
         (key-type  (getf key-info :type))
         (sig-info  (parse-signature-blob sig-blob))
         (sig-algo  (getf sig-info :algorithm))
         (sig-bytes (getf sig-info :bytes)))
    (flet ((fail (msg)
             (restart-case
                 (error 'key-error :message msg)
               (show-verification-data ()
                 :report "Print raw verification bytes to *error-output* and re-signal"
                 (flet ((hex (v &optional (n (length v)))
                          (with-output-to-string (s)
                            (loop for i below (min n (length v))
                                  do (format s "~2,'0x " (aref v i))))))
                   (format *error-output*
                           "~&--- verification failure ---~%~
                            sig-algo     : ~S~%~
                            key-blob     : ~A (~D bytes)~%~
                            exchange-hash: ~A~%~
                            sig-bytes    : ~A (~D bytes)~%~
                            ---~%"
                           sig-algo
                           (hex host-key-blob 16) (length host-key-blob)
                           (hex exchange-hash)
                           (hex sig-bytes 16)     (length sig-bytes))
                   (finish-output *error-output*))
                 (error 'key-error :message msg))))
           (compatible-key-type-p ()
             (cond
               ((string= sig-algorithm +host-key-ed25519+)
                (string= key-type +host-key-ed25519+))
               ((or (string= sig-algorithm +host-key-rsa-sha2-256+)
                    (string= sig-algorithm +host-key-rsa-sha2-512+))
                ;; RFC 8332 reuses the "ssh-rsa" public key format for
                ;; rsa-sha2-* host-key algorithms.
                (string= key-type "ssh-rsa"))
               (t nil))))
      (unless (string= sig-algo sig-algorithm)
        (error 'key-error
               :message (format nil "signature algorithm mismatch: negotiated ~S, received ~S"
                                sig-algorithm sig-algo)))
      (unless (compatible-key-type-p)
        (error 'key-error
               :message (format nil "host key type ~S is not compatible with negotiated algorithm ~S"
                                key-type sig-algorithm)))
      (cond
        ;; Ed25519
        ((string= sig-algorithm +host-key-ed25519+)
         (unless (ironclad:verify-signature key exchange-hash sig-bytes)
           (fail "Ed25519 host key signature verification failed")))

        ;; RSA-SHA256
        ((string= sig-algorithm +host-key-rsa-sha2-256+)
         (unless (rsa-pkcs1-verify key exchange-hash sig-bytes :sha256)
           (fail "rsa-sha2-256 host key signature verification failed")))

        ;; RSA-SHA512
        ((string= sig-algorithm +host-key-rsa-sha2-512+)
         (unless (rsa-pkcs1-verify key exchange-hash sig-bytes :sha512)
           (fail "rsa-sha2-512 host key signature verification failed")))

        (t
         (error 'key-error
                :message (format nil "unsupported signature algorithm: ~S" sig-algorithm)))))))

;;;; Passphrase-protected key decryption helpers

;;; OpenSSH uses a custom bcrypt-based PBKDF (bcrypt_pbkdf from OpenBSD)
;;; together with a symmetric cipher to protect private key material.
;;; Ironclad v0.61+ provides the bcrypt-pbkdf KDF natively.
;;;
;;; Supported ciphers (cipher-name → key bytes, IV bytes):
;;;   aes128-ctr  16  16
;;;   aes256-ctr  32  16   ← most common for modern OpenSSH keys
;;;   aes128-cbc  16  16
;;;   aes256-cbc  32  16
;;;
;;; chacha20-poly1305@openssh.com is not yet supported (AEAD, different framing).

(defun openssh-cipher-key-iv-lengths (cipher-name)
  "Return (values KEY-LENGTH IV-LENGTH) for a supported OpenSSH cipher name.
   Signals KEY-ERROR for unknown or unsupported ciphers."
  (cond
    ((string= cipher-name "aes128-ctr") (values 16 16))
    ((string= cipher-name "aes256-ctr") (values 32 16))
    ((string= cipher-name "aes128-cbc") (values 16 16))
    ((string= cipher-name "aes256-cbc") (values 32 16))
    (t (error 'key-error
              :message (format nil
                               "unsupported OpenSSH private-key cipher: ~S ~
                                (supported: aes128-ctr, aes256-ctr, aes128-cbc, aes256-cbc)"
                               cipher-name)))))

(defun bcrypt-pbkdf-derive (passphrase-octets salt rounds total-bytes)
  "Derive TOTAL-BYTES of key material from PASSPHRASE-OCTETS using
   OpenSSH's bcrypt_pbkdf (salt bytes SALT, ROUNDS iterations).
   Uses Ironclad's built-in :bcrypt-pbkdf KDF."
  (let ((kdf (ironclad:make-kdf :bcrypt-pbkdf)))
    (ironclad:derive-key kdf passphrase-octets salt rounds total-bytes)))

(defun decrypt-openssh-private-section (ciphertext cipher-name key iv)
  "Return a freshly-allocated decrypted copy of CIPHERTEXT using CIPHER-NAME,
   KEY, and IV.  Supports aes{128,256}-{ctr,cbc}."
  (let ((plaintext (copy-seq ciphertext)))
    (cond
      ((or (string= cipher-name "aes128-ctr")
           (string= cipher-name "aes256-ctr"))
       (let ((cipher (ironclad:make-cipher :aes :key key :mode :ctr
                                           :initialization-vector iv)))
         (ironclad:decrypt-in-place cipher plaintext)))
      ((or (string= cipher-name "aes128-cbc")
           (string= cipher-name "aes256-cbc"))
       (let ((cipher (ironclad:make-cipher :aes :key key :mode :cbc
                                           :initialization-vector iv)))
         (ironclad:decrypt-in-place cipher plaintext)))
      (t
       (error 'key-error
              :message (format nil "unsupported cipher in decrypt: ~S" cipher-name))))
    plaintext))

;;;; User private key loading — OpenSSH new format

;;; The OpenSSH private key format is:
;;;   "openssh-key-v1\0"
;;;   string  cipher-name    ("none" for unencrypted)
;;;   string  kdf-name       ("none" for unencrypted)
;;;   string  kdf-options    (empty for "none")
;;;   uint32  num-keys       (1 for a single key)
;;;   string  public-key     (wire-format public key blob)
;;;   string  private-keys   (contains: uint32 check1, uint32 check2,
;;;                                      <private key data>, string comment,
;;;                                      padding bytes)

(defparameter +openssh-key-magic+
  (coerce (mapcar #'char-code (coerce "openssh-key-v1" 'list))
          '(vector (unsigned-byte 8))))

(defun base64-decode (string)
  "Decode a base64 STRING (standard alphabet) to a simple octet vector."
  (let* ((clean  (remove-if (lambda (c) (member c '(#\Newline #\Return #\Space #\Tab)))
                             string))
         (len    (length clean))
         (table  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
         (output (make-array (* 3 (ceiling len 4)) :element-type '(unsigned-byte 8)
                                                   :fill-pointer 0)))
    (flet ((decode-char (c)
             (if (char= c #\=)
                 0
                 (let ((pos (position c table)))
                   (unless pos
                     (error 'key-error :message (format nil "invalid base64 character ~S" c)))
                   pos))))
      (loop for i from 0 below len by 4
            for c0 = (decode-char (char clean i))
            for c1 = (decode-char (char clean (+ i 1)))
            for c2 = (if (< (+ i 2) len) (decode-char (char clean (+ i 2))) 0)
            for c3 = (if (< (+ i 3) len) (decode-char (char clean (+ i 3))) 0)
            do (vector-push (logior (ash c0 2) (ash c1 -4)) output)
               (unless (and (< (+ i 2) len) (char= (char clean (+ i 2)) #\=))
                 (vector-push (logior (ash (logand c1 15) 4) (ash c2 -2)) output))
               (unless (and (< (+ i 3) len) (char= (char clean (+ i 3)) #\=))
                 (vector-push (logior (ash (logand c2 3) 6) c3) output))))
    (let ((result (make-array (length output) :element-type '(unsigned-byte 8))))
      (replace result output)
      result)))

(defun parse-openssh-private-key (pem-string &key passphrase path)
  "Parse an OpenSSH new-format private key from PEM-STRING.
   Returns a list (:type <string> :private-key <ironclad-key> :public-key <ironclad-key>).

   For encrypted keys, PASSPHRASE must be a string containing the passphrase.
   When an encrypted key is encountered without a passphrase, signals
   KEY-NEEDS-PASSPHRASE with a SUPPLY-PASSPHRASE restart available.
   PATH is used solely for error reporting."
  (let* (;; Extract base64 between the PEM headers
         (b64-start (+ (search "-----BEGIN OPENSSH PRIVATE KEY-----" pem-string)
                       (length "-----BEGIN OPENSSH PRIVATE KEY-----")))
         (b64-end   (search "-----END OPENSSH PRIVATE KEY-----" pem-string))
         (b64       (subseq pem-string b64-start b64-end))
         (raw       (base64-decode b64))
         (buf       (make-read-buffer raw)))
    ;; Check magic: "openssh-key-v1\0"
    (let ((magic (ssh/buffer:read-raw-bytes buf (1+ (length +openssh-key-magic+)))))
      (unless (and (= (length magic) (1+ (length +openssh-key-magic+)))
                   (loop for i below (length +openssh-key-magic+)
                         always (= (aref magic i) (aref +openssh-key-magic+ i)))
                   (= (aref magic (length +openssh-key-magic+)) 0))
        (error 'key-error :message "not an OpenSSH private key (bad magic)")))
    ;; Cipher, KDF, kdf-options
    (let* ((cipher-name  (map 'string #'code-char (read-string* buf)))
           (kdf-name     (map 'string #'code-char (read-string* buf)))
           (kdf-options  (read-string* buf))   ; raw bytes; non-empty when kdf != "none"
           (encrypted-p  (not (string= cipher-name "none"))))
      ;; Validate KDF when the key is encrypted
      (when (and encrypted-p (not (string= kdf-name "bcrypt")))
        (error 'key-error
               :message (format nil "unsupported KDF in OpenSSH private key: ~S ~
                                     (only \"bcrypt\" is supported)" kdf-name)))
      ;; If encrypted and no passphrase supplied, signal with a restart
      (when (and encrypted-p (null passphrase))
        (restart-case
            (error 'key-needs-passphrase :path path)
          (supply-passphrase (p)
            :report "Supply the passphrase for this key"
            :interactive (lambda ()
                           (format *query-io* "Passphrase: ")
                           (finish-output *query-io*)
                           (list (read-line *query-io*)))
            (setf passphrase p))))
      ;; num-keys
      (let ((nkeys (read-uint32 buf)))
        (unless (= nkeys 1)
          (error 'key-error :message "only single-key OpenSSH files are supported")))
      ;; Public key blob (wire format)
      (let* ((pub-blob     (read-string* buf))
             (enc-section  (read-string* buf))
             ;; Decrypt the private section when needed
             (priv-section
               (if (not encrypted-p)
                   enc-section
                   ;; Parse kdf-options: string(salt) uint32(rounds)
                   (let* ((opt-buf (make-read-buffer kdf-options))
                          (salt    (read-string* opt-buf))
                          (rounds  (read-uint32 opt-buf)))
                     (multiple-value-bind (key-len iv-len)
                         (openssh-cipher-key-iv-lengths cipher-name)
                       (let* ((key-mat (bcrypt-pbkdf-derive
                                        (utf-8-to-octets passphrase)
                                        salt rounds (+ key-len iv-len)))
                              (key (subseq key-mat 0 key-len))
                              (iv  (subseq key-mat key-len (+ key-len iv-len))))
                         (decrypt-openssh-private-section
                          enc-section cipher-name key iv))))))
             (pbuf (make-read-buffer priv-section)))
        (declare (ignore pub-blob))
        ;; check1, check2 (random uint32 pair; mismatch means wrong passphrase)
        (let ((check1 (read-uint32 pbuf))
              (check2 (read-uint32 pbuf)))
          (unless (= check1 check2)
            (error 'key-error
                   :message "OpenSSH private key check values mismatch — wrong passphrase or corrupt file")))
        ;; Key type string followed by key-type-specific fields
        (let ((key-type (map 'string #'code-char (read-string* pbuf))))
          (cond
            ((string= key-type +host-key-ed25519+)
             ;; Ed25519: string(public-key 32B) string(private-key 64B: seed||pub)
             (let* ((pk-bytes (read-string* pbuf))
                    (sk-full  (read-string* pbuf)) ; 64 bytes: seed (32) || public (32)
                    (sk-bytes (subseq sk-full 0 32)))
               (list :type        key-type
                     :public-key  (ironclad:make-public-key  :ed25519 :y pk-bytes)
                     :private-key (ironclad:make-private-key :ed25519 :x sk-bytes :y pk-bytes))))

            ((or (string= key-type "ssh-rsa")
                 (string= key-type +host-key-rsa-sha2-256+)
                 (string= key-type +host-key-rsa-sha2-512+))
             ;; RSA: mpint(n) mpint(e) mpint(d) mpint(iqmp) mpint(p) mpint(q)
             (let* ((n    (read-mpint pbuf))
                    (e    (read-mpint pbuf))
                    (d    (read-mpint pbuf))
                    (_    (read-mpint pbuf))  ; iqmp (not needed by Ironclad)
                    (p    (read-mpint pbuf))
                    (q    (read-mpint pbuf)))
               (declare (ignore _))
               (list :type        (if (string= key-type "ssh-rsa") +host-key-rsa-sha2-256+ key-type)
                     :public-key  (ironclad:make-public-key  :rsa :e e :n n)
                     :private-key (ironclad:make-private-key :rsa :d d :n n :p p :q q))))

            (t
             (error 'key-error
                    :message (format nil "unsupported key type in OpenSSH file: ~S" key-type)))))))))

(defun load-private-key (path &key passphrase)
  "Load a private key from PATH.
   Supports OpenSSH new-format keys (ed25519 and RSA), both unencrypted
   and passphrase-protected.

   PASSPHRASE — a string; required for encrypted keys.  When an encrypted
   key is encountered and PASSPHRASE is NIL, the condition KEY-NEEDS-PASSPHRASE
   is signalled.  The restart SUPPLY-PASSPHRASE (string) is available.

   Returns a list (:type <string> :private-key <ironclad-key> :public-key <ironclad-key>)."
  (let ((contents (uiop:read-file-string path)))
    (cond
      ((search "BEGIN OPENSSH PRIVATE KEY" contents)
       (parse-openssh-private-key contents :passphrase passphrase :path path))
      (t
       (error 'key-error
              :message (format nil "unrecognised private key format in ~A" path))))))

;;;; Signing for publickey authentication

(defun sign-auth-data (key-info auth-data)
  "Sign AUTH-DATA using the private key in KEY-INFO (as returned by LOAD-PRIVATE-KEY).
   Returns a signature blob: string(algorithm) string(raw-signature)."
  (let* ((key-type    (getf key-info :type))
         (private-key (getf key-info :private-key))
         (sig-buf     (make-write-buffer)))
    (cond
      ((string= key-type +host-key-ed25519+)
       (let ((sig (ironclad:sign-message private-key auth-data)))
         (write-string* sig-buf +host-key-ed25519+)
         (write-string* sig-buf sig)))

      ((or (string= key-type +host-key-rsa-sha2-256+)
           (string= key-type +host-key-rsa-sha2-512+))
       ;; Build PKCS1v1.5 EM and sign it
       (let* ((digest-name (if (string= key-type +host-key-rsa-sha2-256+) :sha256 :sha512))
              (prefix      (if (eq digest-name :sha256)
                               +sha256-der-prefix+ +sha512-der-prefix+))
              (h           (ironclad:digest-sequence digest-name auth-data))
              (t-bytes     (concatenate '(vector (unsigned-byte 8)) prefix h))
              (n           (ironclad:rsa-key-modulus private-key))
              (k           (ceiling (integer-length n) 8))
              (ps-len      (- k (length t-bytes) 3))
              (ps          (make-array ps-len :element-type '(unsigned-byte 8)
                                              :initial-element #xff))
              (em          (concatenate '(vector (unsigned-byte 8))
                                        #(0 1) ps #(0) t-bytes))
              (sig         (ironclad:sign-message private-key em)))
         (write-string* sig-buf key-type)
         (write-string* sig-buf sig)))

      (t
       (error 'key-error
              :message (format nil "cannot sign with key type ~S" key-type))))
    (buffer-to-octets sig-buf)))
