;;;; cl-ssh public API.
;;;;
;;;; This is the single package callers interact with.  The nickname :ssh
;;;; means (ssh:connect ...) works without a use-package.
;;;;
;;;; Typical usage:
;;;;
;;;;   ;; Preferred — WITH-CONNECTION guarantees disconnect on exit or error
;;;;   (ssh:with-connection (client "myserver")
;;;;     (multiple-value-bind (out err code)
;;;;         (ssh:run-command client "uname -a")
;;;;       (format t "~A" out)))
;;;;
;;;;   ;; Explicit password authentication
;;;;   (ssh:with-connection (client "example.com" :username "alice"
;;;;                                              :password "secret")
;;;;     ...)
;;;;
;;;;   ;; Explicit public-key authentication
;;;;   (ssh:with-connection (client "example.com" :username "alice"
;;;;                                              :identity "~/.ssh/id_ed25519")
;;;;     (multiple-value-bind (stream channel)
;;;;         (ssh:open-shell client :pty t)
;;;;       ...))

(uiop:define-package ssh/ssh
  (:nicknames #:ssh)
  (:use #:cl)
  (:import-from #:ssh/sftp
                #:sftp-session
                #:sftp-handle
                #:sftp-handle-kind
                #:sftp-handle-open-p
                #:close-sftp
                #:sftp-session-extensions
                #:sftp-session-limits
                #:sftp-extension-p
                #:sftp-diagnostics
                #:sftp-open-file
                #:sftp-close-handle
                #:sftp-read-at
                #:sftp-write-at
                #:sftp-open-directory
                #:sftp-read-directory
                #:sftp-list-directory
                #:sftp-stat
                #:sftp-lstat
                #:sftp-fstat
                #:sftp-setstat
                #:sftp-fsetstat
                #:sftp-mkdir
                #:sftp-rmdir
                #:sftp-remove
                #:sftp-rename
                #:sftp-realpath
                #:sftp-readlink
                #:sftp-symlink
                #:sftp-posix-rename
                #:sftp-fsync)
  (:import-from #:ssh/sftp/codec
                #:sftp-error
                #:sftp-protocol-error
                #:sftp-status-error
                #:sftp-unsupported-error
                #:sftp-no-progress-error
                #:sftp-error-message
                #:sftp-error-operation
                #:sftp-error-path
                #:sftp-error-request-id
                #:sftp-error-code
                #:sftp-error-server-message
                #:sftp-error-language
                #:sftp-error-cause
                #:sftp-attributes
                #:make-sftp-attributes
                #:sftp-attributes-size
                #:sftp-attributes-uid
                #:sftp-attributes-gid
                #:sftp-attributes-permissions
                #:sftp-attributes-atime
                #:sftp-attributes-mtime
                #:sftp-attributes-extended
                #:sftp-entry
                #:sftp-entry-filename
                #:sftp-entry-longname
                #:sftp-entry-attributes
                #:sftp-name-string)
  (:import-from #:ssh/sftp/stream
                #:sftp-file-stream
                #:open-sftp-file
                #:with-open-sftp-file
                #:sftp-download
                #:sftp-upload)
  (:import-from #:ssh/config
                #:*default-config-path*
                #:resolve-host
                #:ssh-config-hostname
                #:ssh-config-port
                #:ssh-config-user
                #:ssh-config-identity-files
                #:ssh-config-strict-host-checking
                #:ssh-config-known-hosts-file
                #:ssh-config-rekey-byte-limit
                #:ssh-config-rekey-seconds-limit)
  (:import-from #:ssh/transport
                #:connect-transport
                #:transport-disconnect
                #:transport-error)
  (:import-from #:ssh/auth
                #:authenticate
                #:make-keyboard-interactive-cli-callback
                #:auth-error
                #:auth-partial-success
                #:auth-partial-success-allowed-methods
                #:auth-partial-success-attempted-method
                #:auth-partial-success-partial-success-p)
  (:import-from #:ssh/session
                #:ssh-channel-stream
                #:ssh-channel-stream-channel
                #:shell-write-line
                #:shell-read-line
                #:shell-read-until
                #:shell-stream-closed)
  (:import-from #:ssh/connection
                #:make-connection
                #:connection-close
                #:channel-stdout-buffer
                #:channel-stderr-buffer
                #:channel-exit-status)
  (:import-from #:ssh/known-hosts
                #:normalize-host-key-policy
                #:host-key-revoked-error
                #:host-key-revoked-error-hostname
                #:host-key-revoked-error-received-fingerprint
                #:unknown-host-key-error
                #:unknown-host-key-error-hostname
                #:unknown-host-key-error-key-type
                #:unknown-host-key-error-received-fingerprint
                #:host-key-changed-error)
  (:import-from #:ssh/keys
                #:key-error
                #:key-needs-passphrase
                #:key-needs-passphrase-path
                #:load-private-key
                #:public-key-fingerprint)
  (:import-from #:ssh/packet
                #:ssh-protocol-error)
  (:export
   ;; Connection lifecycle
   #:connect
   #:disconnect
   #:with-connection
   #:*default-config-path*
   ;; Command execution and file-copy conveniences
   #:run-command #:cmd #:scp
   ;; Interactive shell
   #:open-shell
   #:with-open-shell
   #:shell-write-line
   #:shell-read-line
   #:shell-read-until
   ;; Subsystem
   #:open-subsystem
   ;; SFTP v3
   #:open-sftp #:with-sftp
   #:sftp-session
   #:sftp-handle
   #:sftp-handle-kind
   #:sftp-handle-open-p
   #:close-sftp
   #:sftp-session-extensions
   #:sftp-session-limits
   #:sftp-extension-p
   #:sftp-diagnostics
   #:sftp-open-file
   #:sftp-close-handle
   #:sftp-read-at
   #:sftp-write-at
   #:sftp-open-directory
   #:sftp-read-directory
   #:sftp-list-directory
   #:sftp-stat
   #:sftp-lstat
   #:sftp-fstat
   #:sftp-setstat
   #:sftp-fsetstat
   #:sftp-mkdir
   #:sftp-rmdir
   #:sftp-remove
   #:sftp-rename
   #:sftp-realpath
   #:sftp-readlink
   #:sftp-symlink
   #:sftp-posix-rename
   #:sftp-fsync
   #:sftp-error
   #:sftp-protocol-error
   #:sftp-status-error
   #:sftp-unsupported-error
   #:sftp-no-progress-error
   #:sftp-error-message
   #:sftp-error-operation
   #:sftp-error-path
   #:sftp-error-request-id
   #:sftp-error-code
   #:sftp-error-server-message
   #:sftp-error-language
   #:sftp-error-cause
   #:sftp-attributes
   #:make-sftp-attributes
   #:sftp-attributes-size
   #:sftp-attributes-uid
   #:sftp-attributes-gid
   #:sftp-attributes-permissions
   #:sftp-attributes-atime
   #:sftp-attributes-mtime
   #:sftp-attributes-extended
   #:sftp-entry
   #:sftp-entry-filename
   #:sftp-entry-longname
   #:sftp-entry-attributes
   #:sftp-name-string
   #:sftp-file-stream
   #:open-sftp-file
   #:with-open-sftp-file
   #:sftp-download
   #:sftp-upload
   ;; Gray stream type (for typecase etc.)
   #:ssh-channel-stream
   #:ssh-channel-stream-channel
   ;; Channel introspection
   #:channel-stdout-buffer
   #:channel-stderr-buffer
   #:channel-exit-status
   ;; Key utilities
   #:load-private-key
   #:public-key-fingerprint
   ;; Keyboard-interactive helper
   #:make-keyboard-interactive-cli-callback
   ;; Conditions
   #:transport-error
   #:auth-error
   #:auth-partial-success
   #:auth-partial-success-allowed-methods
   #:auth-partial-success-attempted-method
   #:auth-partial-success-partial-success-p
   #:key-error
   #:key-needs-passphrase
   #:key-needs-passphrase-path
   #:unknown-host-key-error
   #:unknown-host-key-error-hostname
   #:unknown-host-key-error-key-type
   #:unknown-host-key-error-received-fingerprint
   #:host-key-changed-error
   #:host-key-revoked-error
   #:host-key-revoked-error-hostname
   #:host-key-revoked-error-received-fingerprint
   #:ssh-protocol-error
   #:shell-stream-closed))

(in-package #:ssh/ssh)

(defun decode-destination-component (text)
  (let ((octets (make-array 0 :element-type '(unsigned-byte 8)
                            :adjustable t :fill-pointer 0)))
    (loop for i from 0 below (length text)
          for ch = (char text i)
          do (cond
               ((char= ch #\%)
                (unless (< (+ i 2) (length text))
                  (error "Incomplete escape in URI component."))
                (let ((high (digit-char-p (char text (1+ i)) 16))
                      (low (digit-char-p (char text (+ i 2)) 16)))
                  (unless (and high low)
                    (error "Invalid escape in URI component."))
                  (let ((byte (+ (* high 16) low)))
                    (when (zerop byte)
                      (error "NUL is not allowed in URI components."))
                    (vector-push-extend byte octets)))
                (incf i 2))
               ;; Match OpenSSH's urldecode, including its treatment of plus.
               ((char= ch #\+) (vector-push-extend 32 octets))
               (t
                (loop for byte across (babel:string-to-octets (string ch) :encoding :utf-8)
                      do (vector-push-extend byte octets)))))
    (babel:octets-to-string octets :encoding :utf-8)))

(defun parse-destination-port (text)
  (unless (and (plusp (length text))
               (every (lambda (ch) (find ch "0123456789")) text))
    (error "SSH URI port must be a decimal integer."))
  (let ((port (parse-integer text)))
    (unless (<= 1 port 65535)
      (error "SSH URI port must be between 1 and 65535."))
    port))

(defun parse-ssh-uri-destination (destination)
  (let* ((authority (subseq destination 6))
         (at (position #\@ authority))
         (user nil)
         (port nil))
    (when (find-if (lambda (ch) (find ch "?#")) authority)
      (error "SSH destinations do not support queries or fragments."))
    (when (and at (position #\/ authority :end at))
      (error "SSH destinations do not support paths."))
    (when at
      (let* ((info (subseq authority 0 at))
             (semicolon (position #\; info))
             (name (subseq info 0 semicolon)))
        ;; OpenSSH currently ignores optional connection parameters.
        (when (zerop (length name))
          (error "SSH URI username must not be empty."))
        (setf user (decode-destination-component name)
              authority (subseq authority (1+ at)))))
    (let ((slash (position #\/ authority)))
      (when slash
        (unless (= slash (1- (length authority)))
          (error "SSH destinations do not support paths."))
        (setf authority (subseq authority 0 slash))))
    (when (zerop (length authority))
      (error "SSH destination hostname must not be empty."))
    (let ((host
            (if (char= (char authority 0) #\[)
                (let ((close (position #\] authority)))
                  (unless close
                    (error "Missing closing bracket in SSH URI hostname."))
                  (when (< (1+ close) (length authority))
                    (unless (char= (char authority (1+ close)) #\:)
                      (error "Unexpected text after bracketed SSH URI hostname."))
                    (setf port (parse-destination-port (subseq authority (+ close 2)))))
                  (subseq authority 1 close))
                (let ((colon (position #\: authority)))
                  (when colon
                    (setf port (parse-destination-port (subseq authority (1+ colon)))))
                  (subseq authority 0 colon)))))
      (values host user port))))

(defun parse-destination (destination)
  (check-type destination string)
  (when (find (code-char 0) destination)
    (error "NUL is not allowed in SSH destinations."))
  (multiple-value-bind (host user port)
      (if (and (>= (length destination) 6)
               (string= "ssh://" destination :end2 6))
          (parse-ssh-uri-destination destination)
          (progn
            (when (search "://" destination)
              (error "Unsupported SSH destination scheme."))
            (when (find-if (lambda (ch) (find ch "/?#")) destination)
              (error "SSH destinations do not support paths, queries, or fragments."))
            (let ((at (position #\@ destination :from-end t)))
              (when (and at (zerop at))
                (error "SSH destination username must not be empty."))
              (values (subseq destination (if at (1+ at) 0))
                      (when at (subseq destination 0 at))
                      nil))))
    (unless (and (plusp (length host))
                 (notany (lambda (ch)
                           (or (find ch "@/[]?#")
                               (<= (char-code ch) 32)
                               (= (char-code ch) 127)))
                         host))
      (error "Invalid SSH destination hostname."))
    ;; A single colon is an unsupported bare host:port, while multiple colons
    ;; allow unbracketed IPv6 addresses in the ordinary hostname form.
    (when (and (= 1 (count #\: host)) (null port))
      (error "Use ssh://host:port to specify an SSH destination port."))
    (values host user port)))

(defun effective-rekey-limit (explicit-value config-value)
  (if (eq explicit-value :unset)
      config-value
      explicit-value))

(defstruct (client (:constructor %make-client))
  "Opaque handle returned by CONNECT and accepted by all other functions."
  transport
  connection)

(defun connect (host
                &key port
                  username
                  password
                  identity
                  passphrase
                  keyboard-interactive-callback
                  keyboard-interactive-submethods
                  known-hosts-path
                  config-path
                  (strict-host-checking :unset)
                  (compression :none)
                  (rekey-byte-limit :unset)
                  (rekey-seconds-limit :unset))
  "Connect to HOST and authenticate, transparently honoring ~/.ssh/config.

HOST is a hostname, IP address, config alias, user@host, or ssh://[user@]host[:port].
IPv6 addresses in URIs must be bracketed. Paths, queries, and fragments are rejected.
PORT overrides the destination port, then falls back to config Port or 22.
USERNAME overrides the destination user, then falls back to config User or the local user.
PASSWORD enables password authentication when supplied.
IDENTITY is a private-key pathname and falls back to the first IdentityFile.
PASSPHRASE is the string used to decrypt an encrypted private key.

KEYBOARD-INTERACTIVE-CALLBACK handles RFC 4256 prompts.
KEYBOARD-INTERACTIVE-SUBMETHODS is NIL, a comma-separated string, or a list of
 submethod strings.

CONFIG-PATH overrides the default ~/.ssh/config path.
KNOWN-HOSTS-PATH overrides UserKnownHostsFile or the default known_hosts path.
STRICT-HOST-CHECKING accepts :YES/T to reject unknown and changed keys,
 :ACCEPT-NEW to record only unknown keys, or :NO/NIL to accept and update keys.
 :UNSET uses SSH configuration, with missing, default, or ask values treated as
 :YES.
COMPRESSION is :NONE, :ZLIB for RFC 4253 zlib with OpenSSH delayed-zlib
 compatibility, or :DELAYED for RFC 8308 compression after authentication.
REKEY-BYTE-LIMIT is a positive integer byte count, NIL to disable the byte limit,
 :DEFAULT for the library default, or :UNSET to use RekeyLimit/defaults.
REKEY-SECONDS-LIMIT is a positive integer second count, NIL to disable the time
 limit, :DEFAULT for the library default, or :UNSET to use RekeyLimit/defaults.

Returns a CLIENT handle."
  ;; Resolve ~/.ssh/config settings for this host alias
  (let* ((destination (multiple-value-list (parse-destination host)))
         (host (first destination))
         (cfg (apply #'resolve-host host `(,@(when config-path `(:config-path ,config-path)))))
         (effective-host (or (ssh-config-hostname cfg) host))
         (effective-port (or port (third destination) (ssh-config-port cfg) 22))
         (effective-user (or username (second destination) (ssh-config-user cfg) (get-current-username)))
         (effective-id (or identity (first (ssh-config-identity-files cfg))))
         (effective-khp (or known-hosts-path (ssh-config-known-hosts-file cfg)))
         (effective-strict
           (normalize-host-key-policy
            (if (eq strict-host-checking :unset)
                (ssh-config-strict-host-checking cfg)
                strict-host-checking)))
         (effective-rekey-byte-limit
           (effective-rekey-limit rekey-byte-limit
                                  (ssh-config-rekey-byte-limit cfg)))
         (effective-rekey-seconds-limit
           (effective-rekey-limit rekey-seconds-limit
                                  (ssh-config-rekey-seconds-limit cfg)))
         (transport (connect-transport effective-host
                                       :port effective-port
                                       :known-hosts-path effective-khp
                                       :strict-host-checking effective-strict
                                       :compression compression
                                       :rekey-byte-limit effective-rekey-byte-limit
                                       :rekey-seconds-limit effective-rekey-seconds-limit)))
    (let ((connection nil) (transferred-p nil))
      (unwind-protect
           (progn
             (authenticate transport effective-user
                           :password password
                           :identity (when effective-id (pathname effective-id))
                           :passphrase passphrase
                           :keyboard-interactive-callback keyboard-interactive-callback
                           :keyboard-interactive-submethods keyboard-interactive-submethods)
             (setf connection (make-connection transport))
             (prog1 (%make-client :transport transport :connection connection)
               (setf transferred-p t)))
        (unless transferred-p
          (ignore-errors
           (if connection (connection-close connection)
               (transport-disconnect transport))))))))

(defun disconnect (client &optional (reason "normal closure"))
  "Gracefully stop a client's dispatcher and SSH transport.
CLIENT is the handle returned by CONNECT.
REASON is the disconnect description sent to the server.
Returns true after the connection has stopped."
  (connection-close (client-connection client) reason))

(defmacro with-connection ((var host &rest connect-args) &body body)
  "Connect to HOST, bind the resulting client to VAR, evaluate BODY, then
disconnect unconditionally — even when BODY signals a condition.

All keyword arguments accepted by CONNECT may be passed after HOST:

  (ssh:with-connection (client \"myserver\")
    (ssh:run-command client \"uname -a\"))

  (ssh:with-connection (client \"example.com\" :username \"bob\" :password \"secret\")
    (ssh:run-command client \"whoami\"))

The connection is always closed when control leaves the form, whether by a
normal return, a non-local exit, or an unhandled condition.  Any error raised
by DISCONNECT itself is suppressed so it does not shadow a condition from BODY."
  `(let ((,var (connect ,host ,@connect-args)))
     (unwind-protect
          (progn ,@body)
       (ignore-errors (disconnect ,var)))))

(defun run-command (client command &key environment)
  "Execute a command on a new channel of a shared SSH client.
CLIENT is the handle returned by CONNECT.
COMMAND is the command string passed to the server.
ENVIRONMENT is an association list of variable names and values.
Returns stdout text, stderr text, and the remote exit status."
  (ssh/session:run-command (client-connection client) command
                           :environment environment))

(defun open-shell (client &key pty (pty-term "xterm") (pty-cols 80) (pty-rows 24)
                            environment capture-output)
  "Open a full-duplex interactive shell on a shared SSH client.
CLIENT is the handle returned by CONNECT.
PTY controls whether a pseudo-terminal is requested.
PTY-TERM is the terminal type name.
PTY-COLS and PTY-ROWS are the initial terminal dimensions.
ENVIRONMENT is an association list of variable names and values.
CAPTURE-OUTPUT retains complete history; the default reclaims consumed bytes.
Returns a bidirectional stdout stream, its channel, and a stderr input stream."
  (ssh/session:open-shell (client-connection client)
                          :pty pty
                          :pty-term pty-term
                          :pty-cols pty-cols
                          :pty-rows pty-rows
                          :environment environment :capture-output capture-output))

(defmacro with-open-shell ((stream client &rest open-shell-args) &body body)
  "Open an interactive shell stream for CLIENT and close it on exit."
  (let ((channel (gensym "CHANNEL")))
    `(multiple-value-bind (,stream ,channel)
         (open-shell ,client ,@open-shell-args)
       (declare (ignore ,channel))
       (unwind-protect
            (progn ,@body)
         (ignore-errors (close ,stream))))))

(defun open-subsystem (client subsystem-name &key capture-output)
  "Open a named subsystem on a shared SSH client.
CLIENT is the handle returned by CONNECT.
SUBSYSTEM-NAME is the remote subsystem name, such as sftp.
CAPTURE-OUTPUT retains complete history; the default reclaims consumed bytes.
Returns a bidirectional stdout stream, its channel, and a stderr input stream."
  (ssh/session:open-subsystem (client-connection client) subsystem-name
                            :capture-output capture-output))

(defun open-sftp (client &key (block-size 32768) (max-pending 16)
                             (max-packet-length 1048576) (symlink-order :auto))
  "Open an SFTP v3 session on a fresh channel of a shared SSH client.
CLIENT is the authenticated handle returned by CONNECT.
BLOCK-SIZE bounds each data request and is clamped to negotiated server limits.
MAX-PENDING bounds outstanding requests and completed but unconsumed replies.
MAX-PACKET-LENGTH bounds a complete received frame, including the four-byte length.
SYMLINK-ORDER is :AUTO, :DRAFT, or :OPENSSH; :AUTO recognizes OpenSSH identification strings.
Returns a ready SFTP-SESSION; the client's other channels remain independent."
  (ssh/sftp:open-sftp-session (client-connection client) :block-size block-size
                            :max-pending max-pending :max-packet-length max-packet-length
                            :symlink-order symlink-order))

(defmacro with-sftp ((session client &rest options) &body body)
  "Evaluate a body with an SFTP session and always release that session.
SESSION names the binding opened from CLIENT with OPTIONS.
BODY supplies the forms to execute; abnormal exits abort unsent session work.
Returns the values of BODY, signaling cleanup errors on otherwise normal exits."
  (let ((normal (gensym "NORMAL")))
    `(let ((,session (open-sftp ,client ,@options)) (,normal nil))
       (unwind-protect
            (multiple-value-prog1 (progn ,@body) (setf ,normal t))
         (if ,normal (close-sftp ,session) (ignore-errors (close-sftp ,session :abort t)))))))

;;;; Internal helpers

(defun parse-scp-endpoint (endpoint)
  (when (pathnamep endpoint)
    (return-from parse-scp-endpoint (values nil nil nil endpoint nil)))
  (check-type endpoint string)
  (when (or (zerop (length endpoint)) (find (code-char 0) endpoint))
    (error "SCP endpoints must be nonempty and contain no NUL."))
  (when (and (>= (length endpoint) 6) (string= "scp://" endpoint :end2 6))
    (let* ((slash (position #\/ endpoint :start 6))
           (authority (subseq endpoint 6 slash))
           (path (if (and slash (< (1+ slash) (length endpoint)))
                     (decode-destination-component (subseq endpoint (1+ slash))) ".")))
      (when (find-if (lambda (ch) (find ch "?#")) endpoint)
        (error "SCP URIs do not support queries or fragments."))
      (multiple-value-bind (host user port)
          (parse-destination (concatenate 'string "ssh://" authority))
        (return-from parse-scp-endpoint (values host user port path t)))))
  (when (search "://" endpoint)
    (error "Use scp:// for SCP URI endpoints."))
  ;; Match OpenSSH colon(): a slash before a colon makes this a local path;
  ;; brackets around an address shield its internal colons.
  (let ((bracketed nil)
        (colon nil))
    (unless (char= (char endpoint 0) #\:)
      (loop for i from 0 below (length endpoint)
            for ch = (char endpoint i)
            do (cond
                 ((char= ch #\/) (return))
                 ((and (char= ch #\[)
                       (or (zerop i) (char= (char endpoint (1- i)) #\@)))
                  (setf bracketed t))
                 ((and bracketed (char= ch #\]))
                  (setf bracketed nil))
                 ((and (char= ch #\:) (not bracketed))
                  (setf colon i) (return)))))
    (unless colon
      (return-from parse-scp-endpoint (values nil nil nil endpoint nil)))
    (let* ((destination (subseq endpoint 0 colon))
           (at (position #\@ destination :from-end t))
           (host (subseq destination (if at (1+ at) 0)))
           (user (when at (subseq destination 0 at)))
           (path (subseq endpoint (1+ colon))))
      (when (and user (zerop (length user)))
        (error "SCP username must not be empty."))
      (when (and (plusp (length host)) (char= (char host 0) #\[)
                 (char= (char host (1- (length host))) #\]))
        (setf host (subseq host 1 (1- (length host)))))
      ;; Reuse SSH destination validation, without decoding shorthand usernames.
      (parse-destination host)
      (values host user nil (if (zerop (length path)) "." path) t))))

(defun scp-path-basename (path)
  (let ((name (if (pathnamep path) (file-namestring path)
                  (subseq path (let ((slash (position #\/ path :from-end t)))
                                 (if slash (1+ slash) 0))))))
    (when (or (zerop (length name)) (member name '("." "..") :test #'string=))
      (error "SCP requires a source filename when copying into a directory."))
    name))

(defun scp-remote-target (session target source)
  (let* ((attributes (handler-case (sftp-stat session target)
                       (sftp-status-error (condition)
                         (unless (= 2 (sftp-error-code condition))
                           (error condition))
                         nil)))
         (permissions (when attributes (sftp-attributes-permissions attributes))))
    (cond
      ((and permissions (= #o040000 (logand #o170000 permissions)))
       (concatenate 'string target
                    (unless (char= (char target (1- (length target))) #\/) "/")
                    (scp-path-basename (pathname source))))
      ((char= (char target (1- (length target))) #\/)
       (error "SCP destination with a trailing slash must be an existing directory."))
      (t target))))

(defun facade-connection-options (options excluded)
  (loop for (key value) on options by #'cddr
        unless (member key excluded) append (list key value)))

(defun scp (source target &rest options
            &key (if-exists :supersede) progress-function &allow-other-keys)
  "Copy one file between the local filesystem and an SSH server using SFTP.
SOURCE and TARGET are local strings/pathnames, user@host:path, or scp:// URIs.
Exactly one endpoint must be remote; an existing target directory keeps the source filename.
IF-EXISTS is :SUPERSEDE (the default) or :ERROR.
PROGRESS-FUNCTION receives transferred bytes and an advisory total or NIL.
OPTIONS forwards all other keywords to CONNECT, overriding endpoint user/port.
Returns the destination path and transferred byte count after successful cleanup."
  (check-type if-exists (member :error :supersede))
  (multiple-value-bind (source-host source-user source-port source-path source-remote)
      (parse-scp-endpoint source)
    (multiple-value-bind (target-host target-user target-port target-path target-remote)
        (parse-scp-endpoint target)
      (when (eq source-remote target-remote)
        (error "SCP requires exactly one remote endpoint."))
      (let* ((upload target-remote)
             (host (if upload target-host source-host))
             (user (if upload target-user source-user))
             (port (if upload target-port source-port))
             (connection-options
               (append (facade-connection-options options
                         '(:if-exists :progress-function :username :port))
                       (list :username (or (getf options :username) user)
                             :port (or (getf options :port) port)))))
        (when (and upload (uiop:directory-exists-p source-path))
          (error "Recursive SCP transfers are not supported."))
        (let ((client (apply #'connect host connection-options)))
          (unwind-protect
               (with-sftp (session client)
                 (if upload
                     (sftp-upload session source-path
                                  (scp-remote-target session target-path source-path)
                                  :if-exists if-exists :progress-function progress-function)
                     (let* ((attributes (sftp-stat session source-path))
                            (permissions (sftp-attributes-permissions attributes))
                            (directory (uiop:directory-exists-p target-path))
                            (local-target
                              (if directory
                                  (merge-pathnames
                                   (pathname (scp-path-basename source-path))
                                   (uiop:ensure-directory-pathname target-path))
                                  target-path)))
                       (when (and permissions (= #o040000 (logand #o170000 permissions)))
                         (error "Recursive SCP transfers are not supported."))
                       (sftp-download session source-path local-target
                                      :if-exists if-exists :progress-function progress-function))))
            (ignore-errors (disconnect client))))))))

(defun cmd (destination command &rest options &key environment &allow-other-keys)
  "Connect to a destination, execute one command, and disconnect.
DESTINATION accepts the same hostname, alias, user@host, or SSH URI as CONNECT.
COMMAND is the command string passed unchanged to the server.
ENVIRONMENT is an association list of remote variable names and values.
OPTIONS forwards all other keywords to CONNECT.
Returns stdout text, stderr text, and the remote exit status."
  (check-type command string)
  (let ((client (apply #'connect destination
                       (facade-connection-options options '(:environment)))))
    (unwind-protect
         (run-command client command :environment environment)
      (ignore-errors (disconnect client)))))

(defun get-current-username ()
  (or (uiop:getenv "USER")
      (uiop:getenv "LOGNAME")
      (uiop:getenv "USERNAME")
      "unknown"))
