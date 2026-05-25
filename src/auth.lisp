;;;; SSH user authentication — RFC 4252.
;;;;
;;;; Supported methods:
;;;;   none             — probe for allowed methods
;;;;   password         — plaintext password inside the encrypted transport
;;;;   publickey        — sign an auth-data blob with the user's private key
;;;;
;;;; keyboard-interactive is not yet implemented.
;;;;
;;;; Usage:
;;;;   (authenticate transport username :password "secret")
;;;;   (authenticate transport username :identity "/path/to/id_ed25519")

(uiop:define-package ssh/auth
  (:use #:cl)
  (:import-from #:ssh/constants
                #:+msg-userauth-request+
                #:+msg-userauth-failure+
                #:+msg-userauth-success+
                #:+msg-userauth-banner+
                #:+msg-userauth-pk-ok+
                #:+service-connection+
                #:+auth-none+
                #:+auth-password+
                #:+auth-publickey+
                #:+host-key-ed25519+
                #:+host-key-rsa-sha2-256+
                #:+host-key-rsa-sha2-512+)
  (:import-from #:ssh/buffer
                #:make-write-buffer
                #:write-byte*
                #:write-boolean
                #:write-string*
                #:write-raw-bytes
                #:buffer-to-octets
                #:make-read-buffer
                #:read-byte*
                #:read-string*
                #:read-boolean
                #:utf-8-to-octets)
  (:import-from #:ssh/transport
                #:transport
                #:transport-send
                #:transport-recv
                #:transport-session-id)
  (:import-from #:ssh/keys
                #:load-private-key
                #:sign-auth-data)
  (:export
   #:authenticate
   #:auth-error))

(in-package #:ssh/auth)

;;;; Condition

(define-condition auth-error (error)
  ((message :initarg :message :reader auth-error-message))
  (:report (lambda (c s)
             (format s "SSH authentication error: ~A" (auth-error-message c)))))

;;;; Internal helpers

(defun recv-auth-response (transport)
  "Wait for an auth response, skipping banners.
   Returns the full payload (type byte included)."
  (loop
    (let ((pkt (transport-recv transport)))
      (case (aref pkt 0)
        (#.+msg-userauth-banner+
         ;; Print banner to *standard-output* and continue waiting
         (let* ((buf  (make-read-buffer pkt :start 1))
                (text (map 'string #'code-char (read-string* buf))))
           (write-string text *standard-output*)
           (force-output *standard-output*)))
        (otherwise
         (return pkt))))))

(defun parse-failure (payload)
  "Parse SSH_MSG_USERAUTH_FAILURE and return (values allowed-methods partial-success)."
  (let* ((buf     (make-read-buffer payload :start 1))
         (methods (let ((raw (read-string* buf)))
                    (if (zerop (length raw))
                        '()
                        (let ((csv (map 'string #'code-char raw)))
                          (loop for start = 0 then (1+ end)
                                for end   = (position #\, csv :start start)
                                collect (subseq csv start end)
                                while end)))))
         (partial (read-boolean buf)))
    (values methods partial)))

(defun rsa-key-type-p (key-type)
  (or (string= key-type "ssh-rsa")
      (string= key-type +host-key-rsa-sha2-256+)
      (string= key-type +host-key-rsa-sha2-512+)))

(defun public-key-format-name (key-type)
  (if (rsa-key-type-p key-type)
      "ssh-rsa"
      key-type))

(defun select-publickey-signature-algorithm (transport key-info)
  "Select the best client-auth signature algorithm for KEY-INFO.

   RSA keys use server-sig-algs when available and otherwise fall back to the
   legacy ssh-rsa signature.

   Returns the algorithm name string to place in SSH_MSG_USERAUTH_REQUEST."
  (let ((key-type (getf key-info :type)))
    (cond
      ((string= key-type +host-key-ed25519+)
       key-type)
      ((rsa-key-type-p key-type)
       (let ((server-sig-algs (ssh/transport::transport-server-sig-algs transport)))
         (cond
           ((null server-sig-algs)
             "ssh-rsa")
           ((member +host-key-rsa-sha2-512+ server-sig-algs :test #'string=)
            +host-key-rsa-sha2-512+)
           ((member +host-key-rsa-sha2-256+ server-sig-algs :test #'string=)
            +host-key-rsa-sha2-256+)
           ((member "ssh-rsa" server-sig-algs :test #'string=)
            "ssh-rsa")
           (t
            (error 'auth-error
                   :message (format nil
                                    "server-sig-algs does not permit RSA authentication; server allows: ~{~A~^, ~}"
                                    server-sig-algs))))))
      (t
       (error 'auth-error
               :message (format nil "unsupported public key type: ~S" key-type))))))

;;;; Auth method implementations

(defun try-none (transport username)
  "Send a 'none' auth request and return the list of allowed methods on failure,
   or :success if the server (unusually) accepts it."
  (let ((buf (make-write-buffer)))
    (write-byte*   buf +msg-userauth-request+)
    (write-string* buf username)
    (write-string* buf +service-connection+)
    (write-string* buf +auth-none+)
    (transport-send transport (buffer-to-octets buf)))
  (let ((reply (recv-auth-response transport)))
    (case (aref reply 0)
      (#.+msg-userauth-success+ :success)
      (#.+msg-userauth-failure+
       (multiple-value-bind (methods _) (parse-failure reply)
         (declare (ignore _))
         methods))
      (t (error 'auth-error
                :message (format nil "unexpected message ~D during none auth"
                                 (aref reply 0)))))))

(defun try-password (transport username password)
  "Attempt password authentication (RFC 4252 §8)."
  (let ((buf (make-write-buffer)))
    (write-byte*   buf +msg-userauth-request+)
    (write-string* buf username)
    (write-string* buf +service-connection+)
    (write-string* buf +auth-password+)
    (write-boolean buf nil)           ; FALSE — not a password-change request
    (write-string* buf (utf-8-to-octets password))
    (transport-send transport (buffer-to-octets buf)))
  (let ((reply (recv-auth-response transport)))
    (case (aref reply 0)
      (#.+msg-userauth-success+ t)
      (#.+msg-userauth-failure+
       (multiple-value-bind (methods partial) (parse-failure reply)
         (declare (ignore partial))
         (error 'auth-error
                :message (format nil "password authentication failed; server allows: ~{~A~^, ~}"
                                 methods))))
      (t (error 'auth-error
                :message (format nil "unexpected message ~D during password auth"
                                 (aref reply 0)))))))

(defun probe-publickey (transport username key-info)
  "Send a publickey probe (no signature) to check whether the server will
   accept this key.  Returns T if the key is acceptable."
  (let* ((key-type   (getf key-info :type))
         (algorithm  (select-publickey-signature-algorithm transport key-info))
         (public-key (getf key-info :public-key))
         ;; Build the public key blob
         (pk-buf     (make-write-buffer)))
    ;; Encode the public key in SSH wire format
    (write-string* pk-buf (public-key-format-name key-type))
    (encode-public-key-into pk-buf key-type public-key)
    (let* ((pk-blob (buffer-to-octets pk-buf))
            (req-buf (make-write-buffer)))
      (write-byte*   req-buf +msg-userauth-request+)
      (write-string* req-buf username)
      (write-string* req-buf +service-connection+)
      (write-string* req-buf +auth-publickey+)
      (write-boolean req-buf nil)         ; FALSE — probe, no signature
      (write-string* req-buf algorithm)
      (write-string* req-buf pk-blob)
      (transport-send transport (buffer-to-octets req-buf)))
    (let ((reply (recv-auth-response transport)))
      (case (aref reply 0)
        (#.+msg-userauth-pk-ok+  t)
        (#.+msg-userauth-failure+ nil)
        (t nil)))))

(defun encode-public-key-into (buf key-type public-key)
  "Write the inner public-key fields into BUF for the given KEY-TYPE.
   (The key-type string itself is written by the caller.)"
  (cond
    ((string= key-type "ssh-ed25519")
     (let ((y (ironclad:ed25519-key-y public-key)))
       (write-string* buf y)))
    ((or (string= key-type "rsa-sha2-256")
         (string= key-type "rsa-sha2-512")
         (string= key-type "ssh-rsa"))
     ;; RSA wire format: string(key-type) mpint(e) mpint(n)
     ;; The key-type string is already written by the caller; here we add e and n.
     (let ((e (ironclad:rsa-key-exponent public-key))
           (n (ironclad:rsa-key-modulus  public-key)))
       (ssh/buffer:write-mpint buf e)
       (ssh/buffer:write-mpint buf n)))
    (t
     (error 'auth-error :message (format nil "unsupported public key type: ~S" key-type)))))

(defun try-publickey (transport username key-info)
  "Attempt public-key authentication (RFC 4252 §7)."
  (let* ((key-type   (getf key-info :type))
         (algorithm  (select-publickey-signature-algorithm transport key-info))
         (public-key (getf key-info :public-key))
         (session-id (transport-session-id transport))
         (pk-buf     (make-write-buffer)))
    (write-string* pk-buf (public-key-format-name key-type))
    (encode-public-key-into pk-buf key-type public-key)
    (let* ((pk-blob (buffer-to-octets pk-buf))
           (sign-buf (make-write-buffer)))
      ;; string(session-id) byte(50) string(username) string(service)
      ;; string("publickey") bool(true) string(algo) string(pk-blob)
      (write-string* sign-buf session-id)
      (write-byte* sign-buf +msg-userauth-request+)
      (write-string* sign-buf username)
      (write-string* sign-buf +service-connection+)
      (write-string* sign-buf +auth-publickey+)
      (write-boolean sign-buf t)
      (write-string* sign-buf algorithm)
      (write-string* sign-buf pk-blob)
      (let* ((auth-data (buffer-to-octets sign-buf))
             (sig-blob  (sign-auth-data key-info auth-data :algorithm algorithm))
             (req-buf   (make-write-buffer)))
        (write-byte*   req-buf +msg-userauth-request+)
        (write-string* req-buf username)
        (write-string* req-buf +service-connection+)
        (write-string* req-buf +auth-publickey+)
        (write-boolean req-buf t)
        (write-string* req-buf algorithm)
        (write-string* req-buf pk-blob)
        (write-string* req-buf sig-blob)
        (transport-send transport (buffer-to-octets req-buf))))
    (let ((reply (recv-auth-response transport)))
      (case (aref reply 0)
        (#.+msg-userauth-success+ t)
        (#.+msg-userauth-failure+
         (multiple-value-bind (methods partial) (parse-failure reply)
           (declare (ignore partial))
           (error 'auth-error
                  :message (format nil
                                   "publickey authentication failed; server allows: ~{~A~^, ~}"
                                   methods))))
        (t (error 'auth-error
                  :message (format nil "unexpected message ~D during publickey auth"
                                   (aref reply 0))))))))

;;;; Public entry point

(defun authenticate (transport username &key password identity passphrase)
  "Authenticate USERNAME on TRANSPORT.

   Exactly one of PASSWORD or IDENTITY must be supplied.

   PASSWORD    — a string; uses the 'password' auth method.
   IDENTITY    — a pathname or namestring to a private key file;
                 uses the 'publickey' auth method.
   PASSPHRASE  — a string; passphrase for an encrypted private key.
                 Required when IDENTITY points to a passphrase-protected key.

   Signals AUTH-ERROR on failure."
  (cond
    (password
     (try-password transport username password))
    (identity
     (let ((key-info (load-private-key identity :passphrase passphrase)))
       (try-publickey transport username key-info)))
    (t
     ;; Fall back to probing with 'none' to get the method list
     (let ((methods (try-none transport username)))
       (if (eq methods :success)
           t
           (error 'auth-error
                  :message (format nil "no authentication method supplied; server offers: ~{~A~^, ~}"
                                   methods)))))))
