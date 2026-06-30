;;;; Integration tests for cl-ssh against a live OpenSSH server.

(defpackage :ssh/integration-tests
  (:use :cl :parachute)
  (:import-from :ssh
                #:connect
                #:disconnect
                #:run-command
                #:open-shell
                #:open-subsystem
                #:with-connection
                #:with-open-shell
                #:shell-write-line
                #:shell-read-until)
  (:import-from :ssh/transport
                #:transport-server-sig-algs))

(in-package :ssh/integration-tests)

(defstruct integration-target
  host
  port
  user
  known-hosts
  password)

(defun fixture-path (filename)
  "Return the pathname for FILENAME inside tests/fixtures/keys/."
  (asdf:system-relative-pathname :ssh
                                 (concatenate 'string "tests/fixtures/keys/" filename)))

(defun fixture-public-key-base64 (filename)
  "Return the base64 payload from FILENAME inside tests/fixtures/keys/."
  (let* ((line (string-trim '(#\Space #\Tab #\Newline #\Return)
                            (uiop:read-file-string (fixture-path filename))))
         (first-space (position #\Space line))
         (second-space (position #\Space line :start (1+ first-space))))
    (subseq line (1+ first-space) second-space)))

(defun write-temp-known-hosts (hostname key-type base64-key)
  "Write one known_hosts entry and return its pathname."
  (let ((path (merge-pathnames
               (format nil "cl-ssh-test-~A.known_hosts" (gensym))
               (uiop:temporary-directory))))
    (with-open-file (f path :direction :output
                            :if-exists :supersede
                            :if-does-not-exist :create)
      (format f "~A ~A ~A~%" hostname key-type base64-key))
    path))

(defun env-value (name)
  (uiop:getenv name))

(defun env-port (name &optional default)
  (let ((value (env-value name)))
    (cond
      (value
       (ignore-errors (parse-integer value :junk-allowed nil)))
      (default
       default))))

(defun integration-target (&optional (port (env-port "SSH_TEST_PORT" 2222)))
  (let* ((known-hosts-path (env-value "SSH_TEST_KNOWN_HOSTS"))
         (known-hosts (and known-hosts-path (probe-file known-hosts-path))))
    (when known-hosts
      (make-integration-target
       :host (or (env-value "SSH_TEST_HOST") "127.0.0.1")
       :port (or port 2222)
       :user (or (env-value "SSH_TEST_USER") "ssh-test")
       :known-hosts known-hosts
       :password (env-value "SSH_TEST_PASSWORD")))))

(defun integration-password ()
  (env-value "SSH_TEST_PASSWORD"))

(defun integration-user ()
  (or (env-value "SSH_TEST_USER") "ssh-test"))

(defun integration-kbdint-port ()
  (env-port "SSH_TEST_KBDINT_PORT"))

(defun integration-partial-success-port ()
  (env-port "SSH_TEST_PARTIAL_SUCCESS_PORT"))

(defun keyboard-interactive-response-callback (response)
  (lambda (name instruction language-tag prompts)
    (declare (ignore name instruction language-tag))
    (mapcar (lambda (prompt)
              (declare (ignore prompt))
              response)
            prompts)))

(defun trim-output (string)
  (string-trim '(#\Space #\Tab #\Newline #\Return) string))

(defun client-transport (client)
  (ssh::client-transport client))

(defun reset-rekey-baseline (transport)
  (let ((packet-stream (ssh/transport:transport-packet-stream transport)))
    (setf (ssh/transport::transport-last-rekey-packets-out transport)
          (ssh/packet:packet-stream-packets-out packet-stream)
          (ssh/transport::transport-last-rekey-packets-in transport)
          (ssh/packet:packet-stream-packets-in packet-stream)
          (ssh/transport::transport-last-rekey-bytes-out transport)
          (ssh/packet:packet-stream-bytes-out packet-stream)
          (ssh/transport::transport-last-rekey-bytes-in transport)
          (ssh/packet:packet-stream-bytes-in packet-stream)
          (ssh/transport::transport-last-rekey-time transport)
          (get-universal-time))))

(defun assert-live-command (client command expected-output)
  (multiple-value-bind (stdout stderr exit-code)
      (run-command client command)
    (is string= expected-output stdout)
    (is string= "" stderr)
    (is = 0 exit-code)))

(defun rsa-live-test (port expected-algorithm)
  (if port
      (let ((target (integration-target port)))
        (if target
            (let* ((transport (ssh/transport::connect-transport
                               (integration-target-host target)
                               :port (integration-target-port target)
                               :known-hosts-path (integration-target-known-hosts target)
                               :strict-host-checking t))
                   (key-info (ssh/keys::load-private-key (fixture-path "id_rsa_nopass"))))
              (unwind-protect
                   (let ((server-sig-algs (transport-server-sig-algs transport)))
                     (true (member expected-algorithm server-sig-algs :test #'string=))
                     (setf (transport-server-sig-algs transport)
                           (list expected-algorithm))
                     (is string= expected-algorithm
                         (ssh/auth::select-publickey-signature-algorithm transport key-info))
                     (ssh/auth::authenticate transport
                                             (integration-target-user target)
                                             :identity (fixture-path "id_rsa_nopass"))
                     (let ((client (ssh::%make-client :transport transport)))
                       (multiple-value-bind (stdout stderr exit-code)
                           (run-command client "whoami")
                         (is string= (integration-user) (trim-output stdout))
                         (is string= "" stderr)
                         (is = 0 exit-code))))
                (ignore-errors (ssh/transport::transport-disconnect transport))))
            (skip "requires SSH_TEST_HOST, SSH_TEST_USER, and SSH_TEST_KNOWN_HOSTS"
                  (true t))))
      (skip "requires an RSA algorithm-specific SSH_TEST_*_PORT"
            (true t))))

(defmacro with-live-client ((client &key identity passphrase password port
                                      keyboard-interactive-callback
                                      keyboard-interactive-submethods)
                            &body body)
  `(let ((target (integration-target ,port)))
     (if target
         (with-connection (,client (integration-target-host target)
                                   :port (integration-target-port target)
                                   :username (integration-target-user target)
                                   :known-hosts-path (integration-target-known-hosts target)
                                   :strict-host-checking t
                                   ,@(when identity `(:identity ,identity))
                                   ,@(when passphrase `(:passphrase ,passphrase))
                                   ,@(when password `(:password ,password))
                                   ,@(when keyboard-interactive-callback
                                       `(:keyboard-interactive-callback ,keyboard-interactive-callback))
                                   ,@(when keyboard-interactive-submethods
                                       `(:keyboard-interactive-submethods ,keyboard-interactive-submethods)))
           ,@body)
         (skip "requires SSH_TEST_HOST, SSH_TEST_PORT, SSH_TEST_USER, and SSH_TEST_KNOWN_HOSTS"
               (true t)))))

(define-test ssh/integration-tests)

(define-test connect-smoke-populates-server-sig-algs
  :parent (:ssh/integration-tests ssh/integration-tests)
  (with-live-client (client :identity (fixture-path "id_ed25519_nopass"))
    (true (transport-server-sig-algs (ssh::client-transport client)))))

(define-test public-key-auth-works-with-rsa-sha2-512
  :parent (:ssh/integration-tests ssh/integration-tests)
  (rsa-live-test (env-port "SSH_TEST_PORT" 2222) "rsa-sha2-512"))

(define-test public-key-auth-works-with-rsa-sha2-256
  :parent (:ssh/integration-tests ssh/integration-tests)
  (rsa-live-test (env-port "SSH_TEST_RSA_SHA2_256_PORT") "rsa-sha2-256"))

(define-test public-key-auth-works-with-ssh-rsa
  :parent (:ssh/integration-tests ssh/integration-tests)
  (rsa-live-test (env-port "SSH_TEST_SSH_RSA_PORT") "ssh-rsa"))

(define-test public-key-auth-works-with-ed25519-passphrase
  :parent (:ssh/integration-tests ssh/integration-tests)
  (with-live-client (client
                     :identity (fixture-path "id_ed25519_aes256ctr")
                     :passphrase "correct horse battery staple")
    (multiple-value-bind (stdout stderr exit-code)
        (run-command client "whoami")
      (is string= (integration-user) (trim-output stdout))
      (is string= "" stderr)
      (is = 0 exit-code))))

(define-test password-auth-works
  :parent (:ssh/integration-tests ssh/integration-tests)
  (let ((password (integration-password)))
    (if password
        (with-live-client (client :password password)
          (multiple-value-bind (stdout stderr exit-code)
              (run-command client "whoami")
            (is string= (integration-user) (trim-output stdout))
            (is string= "" stderr)
            (is = 0 exit-code)))
        (skip "requires SSH_TEST_PASSWORD"
          (true t)))))

(define-test keyboard-interactive-auth-works
  :parent (:ssh/integration-tests ssh/integration-tests)
  (let* ((port (integration-kbdint-port))
         (password (integration-password)))
    (if (and port password)
        (with-live-client (client
                           :port port
                           :keyboard-interactive-callback
                           (keyboard-interactive-response-callback password))
          (multiple-value-bind (stdout stderr exit-code)
              (run-command client "whoami")
            (is string= (integration-user) (trim-output stdout))
            (is string= "" stderr)
            (is = 0 exit-code)))
        (skip "requires SSH_TEST_KBDINT_PORT and SSH_TEST_PASSWORD"
          (true t)))))

(define-test keyboard-interactive-auth-fails-with-wrong-response
  :parent (:ssh/integration-tests ssh/integration-tests)
  (let* ((port (integration-kbdint-port))
         (password (integration-password))
         (target (and port (integration-target port))))
    (if (and target password)
        (of-type 'ssh:auth-error
          (handler-case
              (let ((client (connect (integration-target-host target)
                                     :port (integration-target-port target)
                                     :username (integration-target-user target)
                                     :known-hosts-path (integration-target-known-hosts target)
                                     :strict-host-checking t
                                     :keyboard-interactive-callback
                                     (keyboard-interactive-response-callback
                                      "definitely-not-the-right-password"))))
                (unwind-protect
                     nil
                  (ignore-errors (disconnect client))))
            (ssh:auth-error (c) c)))
        (skip "requires SSH_TEST_KBDINT_PORT and SSH_TEST_PASSWORD"
          (true t)))))

(define-test publickey-then-keyboard-interactive-partial-success-works
  :parent (:ssh/integration-tests ssh/integration-tests)
  (let* ((port (integration-partial-success-port))
         (password (integration-password))
         (target (and port password (integration-target port))))
    (if target
        (let ((captured-condition nil)
              (client nil))
          (setf client
                (handler-bind ((ssh/auth:auth-partial-success
                                (lambda (c)
                                  (setf captured-condition c)
                                  (invoke-restart 'ssh/auth::continue-authentication
                                                  "keyboard-interactive"
                                                  (keyboard-interactive-response-callback password)))))
                  (connect (integration-target-host target)
                           :port (integration-target-port target)
                           :username (integration-target-user target)
                           :known-hosts-path (integration-target-known-hosts target)
                           :identity (fixture-path "id_ed25519_nopass")
                           :strict-host-checking t)))
          (unwind-protect
               (progn
                 (true captured-condition)
                 (is string= "publickey"
                     (ssh/auth:auth-partial-success-attempted-method captured-condition))
                 (is equal '("keyboard-interactive")
                     (ssh/auth:auth-partial-success-allowed-methods captured-condition))
                 (true (ssh/auth:auth-partial-success-partial-success-p captured-condition))
                 (multiple-value-bind (stdout stderr exit-code)
                     (run-command client "whoami")
                   (is string= (integration-user) (trim-output stdout))
                   (is string= "" stderr)
                   (is = 0 exit-code)))
            (ignore-errors (disconnect client))))
        (skip "requires SSH_TEST_PARTIAL_SUCCESS_PORT and SSH_TEST_PASSWORD"
          (true t)))))

(define-test run-command-returns-stdout-stderr-and-exit-code
  :parent (:ssh/integration-tests ssh/integration-tests)
  (with-live-client (client :identity (fixture-path "id_ed25519_nopass"))
    (multiple-value-bind (stdout stderr exit-code)
        (run-command client
                     "printf 'out'; printf 'err' 1>&2; exit 7")
      (is string= "out" stdout)
      (is string= "err" stderr)
      (is = 7 exit-code))))

(define-test rekey-after-time-limit-keeps-session-usable
  :parent (:ssh/integration-tests ssh/integration-tests)
  (with-live-client (client :identity (fixture-path "id_ed25519_nopass"))
    (let* ((transport (client-transport client))
           (session-id (copy-seq (ssh/transport:transport-session-id transport)))
           (old-rekey-time (- (get-universal-time) 2)))
      (reset-rekey-baseline transport)
      (setf (ssh/transport::transport-rekey-packet-limit transport) nil
            (ssh/transport::transport-rekey-byte-limit transport) nil
            (ssh/transport::transport-rekey-seconds-limit transport) 1
            (ssh/transport::transport-last-rekey-time transport) old-rekey-time)
      (assert-live-command client "printf time-rekey-ok" "time-rekey-ok")
      (true (> (ssh/transport::transport-last-rekey-time transport)
               old-rekey-time))
      (is equalp session-id (ssh/transport:transport-session-id transport))
      (setf (ssh/transport::transport-rekey-seconds-limit transport) nil)
      (assert-live-command client "printf after-time-rekey" "after-time-rekey"))))

(define-test rekey-after-data-limit-keeps-session-usable
  :parent (:ssh/integration-tests ssh/integration-tests)
  (with-live-client (client :identity (fixture-path "id_ed25519_nopass"))
    (let* ((transport (client-transport client))
           (session-id (copy-seq (ssh/transport:transport-session-id transport))))
      (reset-rekey-baseline transport)
      (let ((old-rekey-bytes-in
              (ssh/transport::transport-last-rekey-bytes-in transport)))
        (setf (ssh/transport::transport-rekey-packet-limit transport) nil
              (ssh/transport::transport-rekey-byte-limit transport) 4096
              (ssh/transport::transport-rekey-seconds-limit transport) nil)
        (multiple-value-bind (stdout stderr exit-code)
            (run-command client "yes rekey-data | head -c 8192")
          (is = 8192 (length stdout))
          (is string= "" stderr)
          (is = 0 exit-code))
        (true (> (ssh/transport::transport-last-rekey-bytes-in transport)
                 old-rekey-bytes-in))
        (is equalp session-id (ssh/transport:transport-session-id transport))
        (setf (ssh/transport::transport-rekey-byte-limit transport) nil)
        (assert-live-command client "printf after-data-rekey" "after-data-rekey")))))

(define-test shell-helpers-work-over-live-connection
  :parent (:ssh/integration-tests ssh/integration-tests)
  (with-live-client (client :identity (fixture-path "id_ed25519_nopass"))
    (with-open-shell (stream client)
      (shell-write-line stream "printf 'shell-ok\\n'; printf '__DONE__'")
      (multiple-value-bind (text status)
          (shell-read-until stream "__DONE__")
        (is string= (concatenate 'string "shell-ok" (string #\Newline)) text)
        (is eq :found status)))))

(define-test open-subsystem-opens-cleanly
  :parent (:ssh/integration-tests ssh/integration-tests)
  (with-live-client (client :identity (fixture-path "id_ed25519_nopass"))
    (multiple-value-bind (stream channel)
        (open-subsystem client "sftp")
      (declare (ignore channel))
      (true (typep stream 'ssh:ssh-channel-stream))
      (close stream))))

(define-test strict-host-key-checking-rejects-changed-key
  :parent (:ssh/integration-tests ssh/integration-tests)
  (let ((target (integration-target)))
    (if target
        (let ((known-hosts (write-temp-known-hosts
                            (integration-target-host target)
                            "ssh-ed25519"
                            (fixture-public-key-base64 "id_ed25519_nopass.pub"))))
          (of-type 'ssh/known-hosts:host-key-changed-error
            (handler-case
                (let ((client (connect (integration-target-host target)
                                       :port (integration-target-port target)
                                       :username (integration-target-user target)
                                       :known-hosts-path known-hosts
                                       :strict-host-checking t)))
                  (unwind-protect
                       nil
                    (disconnect client)))
              (ssh/known-hosts:host-key-changed-error (c) c))))
        (skip "requires SSH_TEST_HOST, SSH_TEST_PORT, SSH_TEST_USER, and SSH_TEST_KNOWN_HOSTS"
          (true t)))))

(define-test non-strict-host-key-checking-accepts-changed-key
  :parent (:ssh/integration-tests ssh/integration-tests)
  (let ((target (integration-target)))
    (if target
        (let ((known-hosts (write-temp-known-hosts
                            (integration-target-host target)
                            "ssh-ed25519"
                            (fixture-public-key-base64 "id_ed25519_nopass.pub"))))
          (let ((client (connect (integration-target-host target)
                                 :port (integration-target-port target)
                                 :username (integration-target-user target)
                                 :known-hosts-path known-hosts
                                 :identity (fixture-path "id_ed25519_nopass")
                                 :strict-host-checking nil)))
            (unwind-protect
                 (progn
                   (disconnect client)
                   (let ((strict-client (connect (integration-target-host target)
                                                  :port (integration-target-port target)
                                                  :username (integration-target-user target)
                                                  :known-hosts-path known-hosts
                                                  :identity (fixture-path "id_ed25519_nopass")
                                                  :strict-host-checking t)))
                     (unwind-protect
                          (true strict-client)
                       (disconnect strict-client))))
              (ignore-errors (disconnect client)))))
        (skip "requires SSH_TEST_HOST, SSH_TEST_PORT, SSH_TEST_USER, and SSH_TEST_KNOWN_HOSTS"
          (true t)))))
