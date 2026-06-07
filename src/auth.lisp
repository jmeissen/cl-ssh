;;;; SSH user authentication — RFC 4252.
;;;;
;;;; Supported methods:
;;;;   none             — probe for allowed methods
;;;;   password         — plaintext password inside the encrypted transport
;;;;   publickey        — sign an auth-data blob with the user's private key
;;;;
;;;; keyboard-interactive (RFC 4256) is supported via callback.
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
                #:+msg-userauth-info-request+
                #:+msg-userauth-info-response+
                #:+service-connection+
                #:+auth-none+
                #:+auth-password+
                #:+auth-publickey+
                #:+auth-keyboard-interactive+
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
                #:read-uint32
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
   #:make-keyboard-interactive-cli-callback
   #:auth-error
   #:auth-partial-success
   #:auth-partial-success-allowed-methods
   #:auth-partial-success-attempted-method
   #:auth-partial-success-partial-success-p))

(in-package #:ssh/auth)

;;;; Condition

(define-condition auth-error (error)
  ((message :initarg :message :reader auth-error-message))
  (:report (lambda (c s)
             (format s "SSH authentication error: ~A" (auth-error-message c)))))

(define-condition auth-partial-success (condition)
  ((attempted-method :initarg :attempted-method
                     :reader auth-partial-success-attempted-method)
   (allowed-methods :initarg :allowed-methods
                    :reader auth-partial-success-allowed-methods)
   (partial-success-p :initarg :partial-success-p
                      :reader auth-partial-success-partial-success-p))
  (:report (lambda (c s)
             (format s "SSH authentication partially succeeded after ~A; server allows: ~{~A~^, ~}"
                     (auth-partial-success-attempted-method c)
                     (auth-partial-success-allowed-methods c)))))

;;;; Internal helpers

(defun recv-auth-response (transport)
  "Wait for an auth response, skipping banners.
   Returns the full payload (type byte included)."
  (loop
    (let ((pkt (transport-recv transport)))
      (case (aref pkt 0)
        (#.+msg-userauth-banner+
         ;; Display a filtered banner and continue waiting.
         (let* ((buf  (make-read-buffer pkt :start 1))
                (text (filter-control-characters
                       (octets-to-utf-8-string (read-string* buf)))))
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

(defun normalize-submethods (submethods)
  "Normalize RFC 4256 SUBMETHODS into a comma-separated string."
  (cond
    ((null submethods) "")
    ((stringp submethods) submethods)
    ((listp submethods)
     (unless (every #'stringp submethods)
       (error 'auth-error :message "keyboard-interactive submethods must be strings"))
     (if submethods
         (format nil "~{~A~^,~}" submethods)
         ""))
    (t
      (error 'auth-error :message "keyboard-interactive submethods must be NIL, a string, or a list of strings"))))

(defun octets-to-utf-8-string (octets)
  "Decode OCTETS as UTF-8 text."
  (babel:octets-to-string octets :encoding :utf-8))

(defun filter-control-characters (text)
  "Replace control characters in TEXT with safe caret sequences."
  (with-output-to-string (out)
    (loop for ch across text
          for code = (char-code ch)
          do (cond
               ((or (char= ch #\Tab)
                    (char= ch #\Return)
                    (char= ch #\Newline))
                (write-char ch out))
               ((<= code 31)
                (write-char #\^ out)
                (write-char (code-char (+ 64 code)) out))
               ((= code 127)
                (write-char #\^ out)
                (write-char #\? out))
               (t
                (write-char ch out))))))

(defun normalize-auth-method-name (method)
  (etypecase method
    (string method)
    (symbol (string-downcase (symbol-name method)))))

(defun auth-method-allowed-p (method allowed-methods)
  (member (normalize-auth-method-name method) allowed-methods :test #'string=))

(defun signal-auth-partial-success (attempted-method allowed-methods continuation)
  (restart-case
      (progn
        (signal 'auth-partial-success
                :attempted-method attempted-method
                :allowed-methods allowed-methods
                :partial-success-p t)
        (error 'auth-error
               :message (format nil
                                "~A authentication partially succeeded; server allows: ~{~A~^, ~}"
                                attempted-method
                                allowed-methods)))
    (continue-authentication (method &rest args)
      :report (lambda (s)
                (format s "Continue authentication with one of: ~{~A~^, ~}"
                        allowed-methods))
      (let ((method-name (normalize-auth-method-name method)))
        (unless (auth-method-allowed-p method-name allowed-methods)
          (error 'auth-error
                 :message (format nil
                                  "server does not allow authentication method ~S; allowed: ~{~A~^, ~}"
                                  method-name
                                  allowed-methods)))
        (funcall continuation method-name args)))))

(defun parse-keyboard-interactive-info-request (payload)
  "Parse SSH_MSG_USERAUTH_INFO_REQUEST payload.

   Returns NAME, INSTRUCTION, LANGUAGE-TAG, and PROMPTS.
   PROMPTS is a list of (:PROMPT <string> :ECHO <boolean>) plists."
  (unless (= (aref payload 0) +msg-userauth-info-request+)
    (error 'auth-error
           :message (format nil "unexpected message ~D while parsing keyboard-interactive info request"
                            (aref payload 0))))
  (let* ((buf (make-read-buffer payload :start 1))
         (name (octets-to-utf-8-string (read-string* buf)))
         (instruction (octets-to-utf-8-string (read-string* buf)))
         (language-tag (octets-to-utf-8-string (read-string* buf)))
         (num-prompts (read-uint32 buf))
         (prompts '()))
    (loop repeat num-prompts
          do (let ((prompt (octets-to-utf-8-string (read-string* buf)))
                    (echo (read-boolean buf)))
                (push (list :prompt prompt :echo echo) prompts)))
    (values name instruction language-tag (nreverse prompts))))

(defun encode-keyboard-interactive-info-response (responses)
  "Encode SSH_MSG_USERAUTH_INFO_RESPONSE with RESPONSES.

   RESPONSES must be a list of strings.

   Returns the encoded packet payload octet vector."
  (unless (listp responses)
    (error 'auth-error :message "keyboard-interactive callback must return a list of strings"))
  (unless (every #'stringp responses)
    (error 'auth-error :message "keyboard-interactive callback responses must be strings"))
  (let ((buf (make-write-buffer)))
    (write-byte* buf +msg-userauth-info-response+)
    (ssh/buffer:write-uint32 buf (length responses))
    (dolist (response responses)
      (write-string* buf (utf-8-to-octets response)))
    (buffer-to-octets buf)))

(defun make-keyboard-interactive-cli-callback (&key
                                                 (input *standard-input*)
                                                 (output *standard-output*)
                                                 (reader #'read-line)
                                                 no-echo-reader
                                                 (display-name-p t)
                                                 (display-instruction-p t)
                                                 (prompt-suffix " ")
                                                 (no-echo-suffix " [hidden] "))
  "Build a keyboard-interactive callback that reads answers from INPUT.

INPUT is the stream passed to the response reader.
OUTPUT is the stream that receives the server-supplied name, instruction, and prompt text.
READER is a callable for prompts whose :ECHO flag is true.
NO-ECHO-READER is a callable for prompts whose :ECHO flag is false.
 If NO-ECHO-READER is NIL, READER is used for both prompt kinds.
DISPLAY-NAME-P controls whether NAME is printed when it is non-empty.
DISPLAY-INSTRUCTION-P controls whether INSTRUCTION is printed when it is non-empty.
PROMPT-SUFFIX is appended after echoed prompts.
NO-ECHO-SUFFIX is appended after prompts whose :ECHO flag is false.

Returns a function of (name instruction language-tag prompts) that returns a list of response strings."
  (let ((silent-reader (or no-echo-reader reader)))
    (lambda (name instruction language-tag prompts)
      (declare (ignore language-tag))
      (when (and display-name-p (plusp (length name)))
        (format output "~A~%" name))
      (when (and display-instruction-p (plusp (length instruction)))
        (format output "~A~%" instruction))
      (loop for prompt in prompts
            collect (let* ((prompt-text (getf prompt :prompt))
                           (echo-p (getf prompt :echo))
                           (suffix (if echo-p prompt-suffix no-echo-suffix))
                           (prompt-reader (if echo-p reader silent-reader)))
                      (format output "~A~A" prompt-text suffix)
                      (finish-output output)
                      (multiple-value-bind (response eof-p)
                          (funcall prompt-reader input)
                        (declare (ignore eof-p))
                        response))))))

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
         (handle-auth-failure +auth-password+ methods partial
                              (lambda (method args)
                                (continue-authentication-with-method transport username method args methods)))))
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
           (handle-auth-failure +auth-publickey+ methods partial
                                (lambda (method args)
                                  (continue-authentication-with-method transport username method args methods)))))
        (t (error 'auth-error
                  :message (format nil "unexpected message ~D during publickey auth"
                                   (aref reply 0))))))))

(defun try-keyboard-interactive (transport username callback &key submethods)
  "Attempt keyboard-interactive authentication (RFC 4256)."
  (unless callback
    (error 'auth-error :message "keyboard-interactive authentication requires a callback"))
  (unless (functionp callback)
    (error 'auth-error :message "keyboard-interactive callback must be a function"))
  (let ((request-buf (make-write-buffer)))
    (write-byte* request-buf +msg-userauth-request+)
    (write-string* request-buf username)
    (write-string* request-buf +service-connection+)
    (write-string* request-buf +auth-keyboard-interactive+)
    (write-string* request-buf "")
    (write-string* request-buf (normalize-submethods submethods))
    (transport-send transport (buffer-to-octets request-buf)))
  (loop
    (let ((reply (recv-auth-response transport)))
      (case (aref reply 0)
        (#.+msg-userauth-success+
         (return t))
        (#.+msg-userauth-failure+
         (multiple-value-bind (methods partial) (parse-failure reply)
           (handle-auth-failure +auth-keyboard-interactive+ methods partial
                                (lambda (method args)
                                  (continue-authentication-with-method transport username method args methods)))))
        (#.+msg-userauth-info-request+
         (multiple-value-bind (name instruction language-tag prompts)
             (parse-keyboard-interactive-info-request reply)
           (let* ((responses (funcall callback name instruction language-tag prompts))
                  (prompt-count (length prompts)))
             (unless (listp responses)
               (error 'auth-error :message "keyboard-interactive callback must return a list of strings"))
             (unless (= (length responses) prompt-count)
               (error 'auth-error
                      :message (format nil
                                       "keyboard-interactive callback returned ~D responses for ~D prompts"
                                       (length responses)
                                       prompt-count)))
             (transport-send transport
                             (encode-keyboard-interactive-info-response responses)))))
        (t
         (error 'auth-error
                :message (format nil "unexpected message ~D during keyboard-interactive auth"
                                 (aref reply 0))))))))

(defun handle-auth-failure (attempted-method allowed-methods partial continuation)
  (if partial
      (signal-auth-partial-success attempted-method allowed-methods continuation)
      (error 'auth-error
             :message (format nil "~A authentication failed; server allows: ~{~A~^, ~}"
                              attempted-method
                              allowed-methods))))

(defun continue-authentication-with-method (transport username method args allowed-methods)
  (let ((method-name (normalize-auth-method-name method)))
    (unless (auth-method-allowed-p method-name allowed-methods)
      (error 'auth-error
             :message (format nil
                              "server does not allow authentication method ~S; allowed: ~{~A~^, ~}"
                              method-name
                              allowed-methods)))
    (cond
      ((string= method-name +auth-password+)
       (destructuring-bind (password &rest rest) args
         (when rest
           (error 'auth-error
                  :message "password continuation takes exactly one argument"))
         (try-password transport username password)))
      ((string= method-name +auth-publickey+)
       (destructuring-bind (identity &optional passphrase &rest rest) args
         (when rest
           (error 'auth-error
                  :message "publickey continuation takes identity and optional passphrase"))
         (let ((key-info (load-private-key identity :passphrase passphrase)))
           (try-publickey transport username key-info))))
      ((string= method-name +auth-keyboard-interactive+)
       (destructuring-bind (callback &optional submethods &rest rest) args
         (when rest
           (error 'auth-error
                  :message "keyboard-interactive continuation takes callback and optional submethods"))
         (try-keyboard-interactive transport username callback :submethods submethods)))
      (t
       (error 'auth-error
              :message (format nil "unsupported authentication method: ~S" method-name))))))

;;;; Public entry point

(defun authenticate (transport username
                     &key password
                       identity
                       passphrase
                       keyboard-interactive-callback
                       keyboard-interactive-submethods)
  "Authenticate USERNAME on TRANSPORT.

Authentication methods are tried in this priority order:
1. PASSWORD
2. IDENTITY
3. KEYBOARD-INTERACTIVE-CALLBACK
4. 'none' probe (for method discovery only)

PASSWORD — a string; uses the 'password' auth method.
IDENTITY — a pathname or namestring to a private key file;
 uses the 'publickey' auth method.
PASSPHRASE — a string; passphrase for an encrypted private key.
 Required when IDENTITY points to a passphrase-protected key.

KEYBOARD-INTERACTIVE-CALLBACK — function used by keyboard-interactive auth.
 Called as (fn name instruction language-tag prompts).
NAME is the server-supplied authentication name string.
INSTRUCTION is the server-supplied instruction string.
LANGUAGE-TAG is the server-supplied language tag string.
PROMPTS is a list of plists; each plist contains :PROMPT, the text to display,
 and :ECHO, a boolean indicating whether typed input should be echoed.
The callback must return a list of response strings, one per prompt, in order.

KEYBOARD-INTERACTIVE-SUBMETHODS — NIL, a comma-separated string, or a list of
 submethod strings.

Returns T on success, signals AUTH-PARTIAL-SUCCESS when the server accepts the
current method but requires continuation, or signals AUTH-ERROR on failure."
  (cond
    (password
     (try-password transport username password))
    (identity
     (let ((key-info (load-private-key identity :passphrase passphrase)))
       (try-publickey transport username key-info)))
    (keyboard-interactive-callback
     (try-keyboard-interactive transport username keyboard-interactive-callback
                               :submethods keyboard-interactive-submethods))
    (keyboard-interactive-submethods
     (error 'auth-error
            :message "keyboard-interactive submethods were provided without a callback"))
    (t
     ;; Fall back to probing with 'none' to get the method list
     (let ((methods (try-none transport username)))
       (if (eq methods :success)
           t
           (error 'auth-error
                  :message (format nil "no authentication method supplied; server offers: ~{~A~^, ~}"
                                   methods)))))))
