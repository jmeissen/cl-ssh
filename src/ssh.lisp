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
  (:import-from #:ssh/config
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
                #:channel-stdout-buffer
                #:channel-stderr-buffer
                #:channel-exit-status)
  (:import-from #:ssh/known-hosts
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
   ;; Command execution
   #:run-command
   ;; Interactive shell
   #:open-shell
   #:with-open-shell
   #:shell-write-line
   #:shell-read-line
   #:shell-read-until
   ;; Subsystem
   #:open-subsystem
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
   #:host-key-changed-error
   #:ssh-protocol-error
   #:shell-stream-closed))

(in-package #:ssh/ssh)

(defun effective-rekey-limit (explicit-value config-value)
  (if (eq explicit-value :unset)
      config-value
      explicit-value))

(defstruct (client (:constructor %make-client))
  "Opaque handle returned by CONNECT and accepted by all other functions."
  transport)

(defun connect (host
                &key port
                  username
                  password
                  identity
                  passphrase
                  keyboard-interactive-callback
                  keyboard-interactive-submethods
                  known-hosts-path
                  (strict-host-checking :unset)
                  (rekey-byte-limit :unset)
                  (rekey-seconds-limit :unset))
  "Connect to HOST and authenticate, transparently honoring ~/.ssh/config.

HOST may be a hostname, IP address, or Host alias from ~/.ssh/config.
PORT is the TCP port number and falls back to Port or 22.
USERNAME is the remote login name and falls back to User or the local user.
PASSWORD enables password authentication when supplied.
IDENTITY is a private-key pathname and falls back to the first IdentityFile.
PASSPHRASE is the string used to decrypt an encrypted private key.

KEYBOARD-INTERACTIVE-CALLBACK handles RFC 4256 prompts.
KEYBOARD-INTERACTIVE-SUBMETHODS is NIL, a comma-separated string, or a list of
 submethod strings.

KNOWN-HOSTS-PATH overrides UserKnownHostsFile or the default known_hosts path.
STRICT-HOST-CHECKING is T to reject changed host keys or NIL to accept and update
 them.
REKEY-BYTE-LIMIT is a positive integer byte count, NIL to disable the byte limit,
 :DEFAULT for the library default, or :UNSET to use RekeyLimit/defaults.
REKEY-SECONDS-LIMIT is a positive integer second count, NIL to disable the time
 limit, :DEFAULT for the library default, or :UNSET to use RekeyLimit/defaults.

Returns a CLIENT handle."
  ;; Resolve ~/.ssh/config settings for this host alias
  (let* ((cfg (resolve-host host))
         (effective-host (or (ssh-config-hostname cfg) host))
         (effective-port (or port (ssh-config-port cfg) 22))
         (effective-user (or username (ssh-config-user cfg) (get-current-username)))
         (effective-id (or identity (first (ssh-config-identity-files cfg))))
         (effective-khp (or known-hosts-path (ssh-config-known-hosts-file cfg)))
         (effective-strict
           (if (eq strict-host-checking :unset)
               ;; No explicit argument — defer to config, defaulting to strict
               (case (ssh-config-strict-host-checking cfg)
                 (:no nil)
                 (:accept-new nil)
                 (otherwise t))
               strict-host-checking))
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
                                       :rekey-byte-limit effective-rekey-byte-limit
                                       :rekey-seconds-limit effective-rekey-seconds-limit)))
    (handler-case
        (progn
          (authenticate transport effective-user
                        :password password
                        :identity (when effective-id (pathname effective-id))
                        :passphrase passphrase
                        :keyboard-interactive-callback keyboard-interactive-callback
                        :keyboard-interactive-submethods keyboard-interactive-submethods)
          (%make-client :transport transport))
      (error (e)
        (ignore-errors (transport-disconnect transport))
        (error e)))))

(defun disconnect (client &optional (reason "normal closure"))
  "Gracefully close the SSH connection."
  (transport-disconnect (client-transport client) reason))

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
  "Execute COMMAND on CLIENT.
   ENVIRONMENT is an alist of (\"NAME\" . \"VALUE\") strings.
   Returns (values stdout-string stderr-string exit-code)."
  (ssh/session:run-command (client-transport client) command
                           :environment environment))

(defun open-shell (client &key pty (pty-term "xterm") (pty-cols 80) (pty-rows 24)
                            environment)
  "Open an interactive shell session on CLIENT.
   PTY — request a pseudo-terminal for terminal-oriented programs.  Leave it NIL
         for scripted reads; PTYs may add prompts, echo, CR/LF translation, and
         terminal control sequences.
   Returns (values bidirectional-stream channel)."
  (ssh/session:open-shell (client-transport client)
                          :pty pty
                          :pty-term pty-term
                          :pty-cols pty-cols
                          :pty-rows pty-rows
                          :environment environment))

(defmacro with-open-shell ((stream client &rest open-shell-args) &body body)
  "Open an interactive shell stream for CLIENT and close it on exit."
  (let ((channel (gensym "CHANNEL")))
    `(multiple-value-bind (,stream ,channel)
         (open-shell ,client ,@open-shell-args)
       (declare (ignore ,channel))
       (unwind-protect
            (progn ,@body)
         (ignore-errors (close ,stream))))))

(defun open-subsystem (client subsystem-name)
  "Open a named subsystem on CLIENT (e.g. \"sftp\").
   Returns (values bidirectional-stream channel)."
  (ssh/session:open-subsystem (client-transport client) subsystem-name))

;;;; Internal helpers

(defun get-current-username ()
  (or (uiop:getenv "USER")
      (uiop:getenv "LOGNAME")
      (uiop:getenv "USERNAME")
      "unknown"))
