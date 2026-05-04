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
                #:ssh-config-known-hosts-file)
  (:import-from #:ssh/transport
                #:connect-transport
                #:transport-disconnect
                #:transport-error)
  (:import-from #:ssh/auth
                #:authenticate
                #:auth-error)
  (:import-from #:ssh/session
                #:ssh-channel-stream
                #:ssh-channel-stream-channel
                #:shell-write-line
                #:shell-read-line
                #:shell-read-until)
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
   ;; Conditions
   #:transport-error
   #:auth-error
   #:key-error
   #:key-needs-passphrase
   #:key-needs-passphrase-path
   #:host-key-changed-error
   #:ssh-protocol-error))

(in-package #:ssh/ssh)

(defstruct (client (:constructor %make-client))
  "Opaque handle returned by CONNECT and accepted by all other functions."
  transport)

(defun connect (host
                &key port
                  username
                  password
                  identity
                  passphrase
                  known-hosts-path
                  (strict-host-checking :unset))
  "Connect to HOST and authenticate, transparently honouring ~/.ssh/config.

   HOST may be a bare hostname/IP or a Host alias defined in ~/.ssh/config.
   When HOST matches an alias, settings from the config file are used as
   defaults; any keyword argument supplied here takes precedence.

   USERNAME    — remote login name.  Falls back to the config User field,
                 then to the current OS user.
   PASSWORD    — use password authentication.
   IDENTITY    — path to a private key file; use public-key authentication.
                 Falls back to the first IdentityFile in the config.
   PASSPHRASE  — passphrase string for a passphrase-protected private key.
                 Supply this together with IDENTITY when the key is encrypted.
                 When omitted and the key is encrypted, KEY-NEEDS-PASSPHRASE
                 is signalled with a SUPPLY-PASSPHRASE restart available.
   KNOWN-HOSTS-PATH      — override the default ~/.ssh/known_hosts path.
   STRICT-HOST-CHECKING  — T to refuse changed host keys (the default),
                           NIL to accept them with a warning.
                           Falls back to StrictHostKeyChecking in the config.

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
         (transport (connect-transport effective-host
                                       :port effective-port
                                       :known-hosts-path effective-khp
                                       :strict-host-checking effective-strict)))
    (handler-case
        (progn
          (authenticate transport effective-user
                        :password password
                        :identity (when effective-id (pathname effective-id))
                        :passphrase passphrase)
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
