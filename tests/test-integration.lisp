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

(defun write-empty-known-hosts ()
  (let ((path (merge-pathnames
               (format nil "cl-ssh-test-~A.known_hosts" (gensym))
               (uiop:temporary-directory))))
    (with-open-file (f path :direction :output
                            :if-exists :supersede
                            :if-does-not-exist :create)
      (write-string "" f))
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
       :user (or (env-value "SSH_TEST_USER") "ssh-tést")
       :known-hosts known-hosts
       :password (env-value "SSH_TEST_PASSWORD")))))

(defun integration-password ()
  (env-value "SSH_TEST_PASSWORD"))

(defun integration-user ()
  (or (env-value "SSH_TEST_USER") "ssh-tést"))

(defun integration-banner-port ()
  (env-port "SSH_TEST_BANNER_PORT"))

(defun integration-banner-text ()
  (env-value "SSH_TEST_BANNER_TEXT"))

(defun integration-kbdint-port ()
  (env-port "SSH_TEST_KBDINT_PORT"))

(defun integration-partial-success-port ()
  (env-port "SSH_TEST_PARTIAL_SUCCESS_PORT"))

(defun integration-aes256-gcm-port ()
  (env-port "SSH_TEST_AES256_GCM_PORT"))

(defun integration-aes128-gcm-port ()
  (env-port "SSH_TEST_AES128_GCM_PORT"))

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

(defun client-connection (client)
  (ssh::client-connection client))

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

(defun run-command-octets (client command)
  (let* ((connection (client-connection client))
         (ch (ssh/connection:open-channel
              connection :type ssh/constants:+channel-session+ :capture-output t)))
    (unless (ssh/connection:channel-request
             ch ssh/constants:+request-exec+
             :data-writer (lambda (buffer)
                            (ssh/buffer:write-string* buffer command)))
      (error "server rejected exec request"))
    (ssh/connection:channel-wait-until
     ch #'ssh/connection:channel-close-p)
    (values (copy-seq (ssh/connection:channel-stdout-buffer ch))
            (copy-seq (ssh/connection:channel-stderr-buffer ch))
            (or (ssh/connection:channel-exit-status ch) 0))))

(defun rsa-live-test (port expected-algorithm)
  (if port
      (let ((target (integration-target port)))
        (if target
            (let* ((transport (ssh/transport::connect-transport
                               (integration-target-host target)
                               :port (integration-target-port target)
                               :known-hosts-path (integration-target-known-hosts target)
                               :strict-host-checking t))
                   (key-info (ssh/keys::load-private-key (fixture-path "id_rsa_nopass")))
                   (client nil))
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
                     (let ((connection (ssh/connection:make-connection transport)))
                       (setf client (ssh::%make-client :transport transport
                                                       :connection connection))
                       (multiple-value-bind (stdout stderr exit-code)
                           (run-command client "whoami")
                         (is string= (integration-user) (trim-output stdout))
                         (is string= "" stderr)
                         (is = 0 exit-code))))
                (if client
                    (ignore-errors (disconnect client))
                    (ignore-errors
                      (ssh/transport::transport-disconnect transport)))))
            (skip "requires SSH_TEST_HOST, SSH_TEST_USER, and SSH_TEST_KNOWN_HOSTS"
                  (true t))))
      (skip "requires an RSA algorithm-specific SSH_TEST_*_PORT"
            (true t))))

(defun gcm-live-test (port expected-key-length &key rekey-p
                                                 (compression :none)
                                                 (expected-compression "none"))
  (if port
      (let ((target (integration-target port)))
        (if target
            (let ((known-hosts (write-empty-known-hosts)))
              (unwind-protect
                   (with-connection (client (integration-target-host target)
                                            :port (integration-target-port target)
                                            :username (integration-target-user target)
                                            :known-hosts-path known-hosts
                                            :identity (fixture-path "id_ed25519_nopass")
                                            :strict-host-checking :accept-new
                                            :compression compression)
                     (let* ((transport (client-transport client))
                            (packet-stream
                              (ssh/transport:transport-packet-stream transport))
                            (outbound
                              (ssh/packet::packet-stream-protection-out packet-stream))
                            (inbound
                              (ssh/packet::packet-stream-protection-in packet-stream)))
                       (of-type 'ssh/packet::gcm-protection outbound)
                       (of-type 'ssh/packet::gcm-protection inbound)
                       (false (eq outbound inbound))
                       (is string= expected-compression
                           (ssh/compression:compressor-algorithm
                            (ssh/packet:packet-stream-compression-out packet-stream)))
                       (is string= expected-compression
                           (ssh/compression:decompressor-algorithm
                            (ssh/packet:packet-stream-compression-in packet-stream)))
                       (is = expected-key-length
                           (length (ssh/packet::gcm-protection-key outbound)))
                       (is = expected-key-length
                           (length (ssh/packet::gcm-protection-key inbound)))
                       (let ((outbound-iv-before
                               (copy-seq (ssh/packet::gcm-protection-iv outbound)))
                             (inbound-iv-before
                               (copy-seq (ssh/packet::gcm-protection-iv inbound))))
                         (is = 12 (length outbound-iv-before))
                         (is = 12 (length inbound-iv-before))
                         (assert-live-command client "printf gcm-packet-ok" "gcm-packet-ok")
                         (let ((outbound-iv-after
                                 (ssh/packet::gcm-protection-iv outbound))
                               (inbound-iv-after
                                 (ssh/packet::gcm-protection-iv inbound)))
                           (is equalp (subseq outbound-iv-before 0 4)
                               (subseq outbound-iv-after 0 4))
                           (is equalp (subseq inbound-iv-before 0 4)
                               (subseq inbound-iv-after 0 4))
                           (false (equalp outbound-iv-before outbound-iv-after))
                           (false (equalp inbound-iv-before inbound-iv-after)))
                         (multiple-value-bind (stdout stderr exit-code)
                             (run-command client "yes gcm | head -c 65536")
                           (is = 65536 (length stdout))
                           (is string= "" stderr)
                           (is = 0 exit-code))
                         (when rekey-p
                           (ssh/connection:connection-rekey
                            (client-connection client))
                           (let ((new-outbound
                                   (ssh/packet::packet-stream-protection-out packet-stream))
                                 (new-inbound
                                   (ssh/packet::packet-stream-protection-in packet-stream)))
                             (of-type 'ssh/packet::gcm-protection new-outbound)
                             (of-type 'ssh/packet::gcm-protection new-inbound)
                             (false (eq outbound new-outbound))
                             (false (eq inbound new-inbound)))
                           (assert-live-command client
                                                "printf gcm-rekey-ok"
                                                "gcm-rekey-ok")))))
                (ignore-errors
                 (delete-file (ssh/known-hosts::known-hosts-lock-path known-hosts)))
                (ignore-errors (delete-file known-hosts))))
            (skip "requires SSH_TEST_HOST, SSH_TEST_USER, SSH_TEST_KNOWN_HOSTS, and a GCM port"
              (true t))))
      (skip "requires an SSH_TEST_AES*_GCM_PORT"
        (true t))))

(defmacro with-live-client ((client &key identity passphrase password port
                                      compression
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
                                   ,@(when compression `(:compression ,compression))
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
  (with-live-client (client
                     :identity (fixture-path "id_ed25519_nopass")
                     :compression :none)
    (let* ((transport (ssh::client-transport client))
           (packet-stream (ssh/transport:transport-packet-stream transport)))
      (true (transport-server-sig-algs transport))
      ;; The client explicitly disables compression, so this complete cycle is
      ;; independent of whether the externally supplied base server offers it.
      (is string= "none"
          (ssh/compression:compressor-algorithm
           (ssh/packet:packet-stream-compression-out packet-stream)))
      (is string= "none"
          (ssh/compression:decompressor-algorithm
           (ssh/packet:packet-stream-compression-in packet-stream)))
      (assert-live-command client "printf no-compression-ok" "no-compression-ok"))))

(define-test rsa-host-pins-and-revocations-work-with-sha2
  :parent (:ssh/integration-tests ssh/integration-tests)
  ;; OpenSSH regress/keytype.sh and cert-hostkey.sh: force algorithms and
  ;; require real authentication to succeed or fail under the trust policy.
  (let ((target (integration-target)))
    (if (null target)
        (skip "requires the OpenSSH integration target")
        (dolist (algorithm '("rsa-sha2-256" "rsa-sha2-512"))
          (let* ((ssh/algorithms::+preferred-host-key+ (list algorithm))
                 (path (write-empty-known-hosts))
                 (identity (fixture-path "id_ed25519_nopass")))
            (unwind-protect
                 (progn
                   ;; Verify an existing ssh-keyscan ssh-rsa pin.
                   (with-connection (client (integration-target-host target)
                                            :port (integration-target-port target)
                                            :username (integration-target-user target)
                                            :identity identity
                                            :known-hosts-path (integration-target-known-hosts target))
                     (assert-live-command client "printf rsa-pin-ok" "rsa-pin-ok")
                     (true (ssh/transport::transport-strict-kex-p (client-transport client))))
                   ;; TOFU must write the key format, independent of the signature hash.
                   (with-connection (client (integration-target-host target)
                                            :port (integration-target-port target)
                                            :username (integration-target-user target)
                                            :identity identity :known-hosts-path path
                                            :strict-host-checking :accept-new)
                     (assert-live-command client "printf rsa-tofu-ok" "rsa-tofu-ok"))
                   (let ((entry (first (ssh/known-hosts::load-known-hosts path))))
                     (is string= "ssh-rsa" (ssh/known-hosts::known-hosts-entry-key-type entry))
                     (with-open-file (stream path :direction :output :if-exists :append)
                       (format stream "@revoked * ssh-rsa ~A~%"
                               (ssh/known-hosts::base64-encode
                                (ssh/known-hosts::known-hosts-entry-key-blob entry))))
                     (dolist (policy '(:yes :accept-new :no))
                       (fail (with-connection (client (integration-target-host target)
                                                      :port (integration-target-port target)
                                                      :username (integration-target-user target)
                                                      :identity identity :known-hosts-path path
                                                      :strict-host-checking policy)
                               (run-command client "true"))
                             'ssh:host-key-revoked-error))
                     ;; A different RSA pin must be changed, not an unknown algorithm.
                     (with-open-file (stream path :direction :output :if-exists :supersede)
                       (format stream "~A ssh-rsa ~A~%"
                               (integration-target-host target)
                               (fixture-public-key-base64 "id_rsa_nopass.pub")))
                     (fail (with-connection (client (integration-target-host target)
                                                    :port (integration-target-port target)
                                                    :username (integration-target-user target)
                                                    :identity identity :known-hosts-path path
                                                    :strict-host-checking :accept-new)
                             (run-command client "true"))
                           'ssh:host-key-changed-error)))
              (delete-file path)))))))

(define-test ctr-mac-kex-matrix-preserves-data-through-rekey
  :parent (:ssh/integration-tests ssh/integration-tests)
  ;; OpenSSH regress/try-ciphers.sh, transfer.sh and rekey.sh:
  ;; force each supported classic protection pair and compare complete output.
  (dolist (cipher '("aes128-ctr" "aes256-ctr"))
    (dolist (mac '("hmac-sha2-256" "hmac-sha2-512"))
      (dolist (kex '("curve25519-sha256" "curve25519-sha256@libssh.org"
                    "diffie-hellman-group14-sha256"))
        (let ((ssh/algorithms::+preferred-cipher+ (list cipher))
              (ssh/algorithms::+preferred-mac+ (list mac))
              (ssh/algorithms::+preferred-classic-mac+ (list mac))
              (ssh/algorithms::+preferred-kex+ (list kex))
              ;; Rekey runs in the dispatcher thread with these same preferences.
              (bt2:*default-special-bindings*
                (append
                 (list (cons 'ssh/algorithms::+preferred-cipher+
                             (list 'quote (list cipher)))
                       (cons 'ssh/algorithms::+preferred-mac+
                             (list 'quote (list mac)))
                       (cons 'ssh/algorithms::+preferred-classic-mac+
                             (list 'quote (list mac)))
                       (cons 'ssh/algorithms::+preferred-kex+
                             (list 'quote (list kex))))
                 bt2:*default-special-bindings*)))
          (with-live-client (client :identity (fixture-path "id_ed25519_nopass"))
            (let* ((transport (client-transport client))
                   (sid (copy-seq (ssh/transport:transport-session-id transport)))
                   (pattern (ssh/buffer:utf-8-to-octets "0123456789abcdef"))
                   (expected (make-array 32768 :element-type '(unsigned-byte 8))))
              (true (ssh/transport::transport-strict-kex-p transport))
              (dotimes (i (length expected))
                (setf (aref expected i) (aref pattern (mod i 16))))
              (reset-rekey-baseline transport)
              (setf (ssh/transport::transport-rekey-byte-limit transport) 4096
                    (ssh/transport::transport-rekey-packet-limit transport) nil
                    (ssh/transport::transport-rekey-seconds-limit transport) nil)
              (let ((before (ssh/transport::transport-last-rekey-bytes-in transport)))
                (multiple-value-bind (stdout stderr code)
                    (run-command-octets
                     client
                     "i=0; while [ \"$i\" -lt 2048 ]; do printf 0123456789abcdef; i=$((i+1)); done")
                  (is equalp expected stdout)
                  (is = 0 (length stderr))
                  (is = 0 code))
                (true (> (ssh/transport::transport-last-rekey-bytes-in transport) before)))
              (is equalp sid (ssh/transport:transport-session-id transport))
              (setf (ssh/transport::transport-rekey-byte-limit transport) nil)
              (assert-live-command client "printf after-rekey" "after-rekey"))))))))

(define-test trust-on-first-use-records-live-host-key
  :parent (:ssh/integration-tests ssh/integration-tests)
  (let ((target (integration-target)))
    (if target
        (let ((known-hosts (write-empty-known-hosts)))
          (unwind-protect
               (let ((client (connect (integration-target-host target)
                                      :port (integration-target-port target)
                                      :username (integration-target-user target)
                                      :known-hosts-path known-hosts
                                      :identity (fixture-path "id_ed25519_nopass")
                                      :strict-host-checking :accept-new)))
                 (unwind-protect
                      (progn
                        (let* ((entries (ssh/known-hosts::load-known-hosts known-hosts))
                               (entry (first entries)))
                          (is = 1 (length entries))
                          (true entry)
                          (when entry
                            (is string= (integration-target-host target)
                                (ssh/known-hosts::known-hosts-entry-raw-hostname entry))
                            (true (member (ssh/known-hosts::known-hosts-entry-key-type entry)
                                          ssh/algorithms:+preferred-host-key+
                                          :test #'string=))
                            (true (plusp (length (ssh/known-hosts::known-hosts-entry-key-blob entry))))))
                        (false
                         (probe-file
                          (ssh/known-hosts::known-hosts-lock-path known-hosts))))
                   (ignore-errors (disconnect client))))
            (ignore-errors (delete-file (ssh/known-hosts::known-hosts-lock-path known-hosts)))
            (ignore-errors (delete-file known-hosts))))
        (skip "requires SSH_TEST_HOST, SSH_TEST_PORT, SSH_TEST_USER, and SSH_TEST_KNOWN_HOSTS"
          (true t)))))

(define-test strict-host-key-checking-rejects-unknown-key
  :parent (:ssh/integration-tests ssh/integration-tests)
  (let ((target (integration-target)))
    (if target
        (let* ((known-hosts (write-empty-known-hosts))
               (lock-path
                 (ssh/known-hosts::known-hosts-lock-path known-hosts)))
          (unwind-protect
               (progn
                 (of-type 'ssh:unknown-host-key-error
                   (handler-case
                       (let ((client
                               (connect
                                (integration-target-host target)
                                :port (integration-target-port target)
                                :username (integration-target-user target)
                                :known-hosts-path known-hosts)))
                         (unwind-protect nil (disconnect client)))
                     (ssh:unknown-host-key-error (condition) condition)))
                 (is string= "" (uiop:read-file-string known-hosts))
                 (false (probe-file lock-path)))
            (ignore-errors (delete-file lock-path))
            (ignore-errors (delete-file known-hosts))))
        (skip
         "requires SSH_TEST_HOST, SSH_TEST_PORT, SSH_TEST_USER, and SSH_TEST_KNOWN_HOSTS"
         (true t)))))

(define-test public-key-auth-works-with-rsa-sha2-512
  :parent (:ssh/integration-tests ssh/integration-tests)
  (rsa-live-test (env-port "SSH_TEST_PORT" 2222) "rsa-sha2-512"))

(define-test public-key-auth-works-with-rsa-sha2-256
  :parent (:ssh/integration-tests ssh/integration-tests)
  (rsa-live-test (env-port "SSH_TEST_RSA_SHA2_256_PORT") "rsa-sha2-256"))

(define-test public-key-auth-rejects-legacy-ssh-rsa-by-default
  :parent (:ssh/integration-tests ssh/integration-tests)
  (let ((port (env-port "SSH_TEST_SSH_RSA_PORT")))
    (if port
        (let ((target (integration-target port)))
          (if target
              (let ((transport (ssh/transport::connect-transport
                                (integration-target-host target)
                                :port (integration-target-port target)
                                :known-hosts-path (integration-target-known-hosts target)
                                :strict-host-checking t)))
                (unwind-protect
                     (of-type 'ssh:auth-error
                       (handler-case
                           (progn
                             (ssh/auth::authenticate transport
                                                     (integration-target-user target)
                                                     :identity (fixture-path "id_rsa_nopass"))
                             nil)
                         (ssh:auth-error (condition) condition)))
                  (ignore-errors (ssh/transport::transport-disconnect transport))))
              (skip "requires SSH_TEST_HOST, SSH_TEST_USER, and SSH_TEST_KNOWN_HOSTS"
                (true t))))
        (skip "requires SSH_TEST_SSH_RSA_PORT"
          (true t)))))

(define-test public-key-auth-works-with-legacy-ssh-rsa-feature
  :parent (:ssh/integration-tests ssh/integration-tests)
  (let ((*features* (cons :cl-ssh-legacy-rsa-sha1 *features*)))
    (rsa-live-test (env-port "SSH_TEST_SSH_RSA_PORT") "ssh-rsa")))

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

(define-test userauth-banner-decodes-utf8-text
  :parent (:ssh/integration-tests ssh/integration-tests)
  (let* ((port (integration-banner-port))
         (text (integration-banner-text))
         (target (and port text (integration-target port))))
    (if target
        (let ((captured-output
                (with-output-to-string (*standard-output*)
                  (let ((client (connect (integration-target-host target)
                                         :port (integration-target-port target)
                                         :username (integration-target-user target)
                                         :known-hosts-path (integration-target-known-hosts target)
                                         :identity (fixture-path "id_ed25519_nopass")
                                         :strict-host-checking t)))
                    (unwind-protect
                         nil
                      (ignore-errors (disconnect client)))))))
          (true (search text captured-output :test #'char=)))
        (skip "requires SSH_TEST_BANNER_PORT and SSH_TEST_BANNER_TEXT"
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

(define-test run-command-preserves-raw-channel-data-bytes
  :parent (:ssh/integration-tests ssh/integration-tests)
  (with-live-client (client :identity (fixture-path "id_ed25519_nopass"))
    (multiple-value-bind (stdout stderr exit-code)
        (run-command-octets client "printf '\\000\\200\\377'")
      (is equal '(0 128 255) (map 'list #'identity stdout))
      (is = 0 (length stderr))
      (is = 0 exit-code))))

(define-test aes256-gcm-openssh-packets-and-rekey-work
  :parent (:ssh/integration-tests ssh/integration-tests)
  ;; This existing server overrides the shared Compression=no configuration.
  ;; Its command, bulk transfer, rekey, and post-rekey command form the single
  ;; complete compressed integration cycle.
  (gcm-live-test (integration-aes256-gcm-port) 32
                 :rekey-p t
                 :compression :zlib
                 :expected-compression "zlib@openssh.com"))

(define-test aes128-gcm-openssh-packets-work
  :parent (:ssh/integration-tests ssh/integration-tests)
  (gcm-live-test (integration-aes128-gcm-port) 16))

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

(define-test concurrent-commands-share-one-live-connection
  :parent (:ssh/integration-tests ssh/integration-tests)
  (with-live-client (client :identity (fixture-path "id_ed25519_nopass"))
    (let ((first-values nil)
          (first-error nil))
      (let ((first-thread
              (bt2:make-thread
               (lambda ()
                 (handler-case
                     (setf first-values
                           (multiple-value-list
                            (run-command client
                                         "sleep 1; printf first-channel")))
                   (error (condition)
                     (setf first-error condition)))))))
        (multiple-value-bind (stdout stderr exit-code)
            (run-command client "printf second-channel")
          (is string= "second-channel" stdout)
          (is string= "" stderr)
          (is = 0 exit-code))
        (bt2:join-thread first-thread)
        (false first-error)
        (when first-values
          (is string= "first-channel" (first first-values))
          (is string= "" (second first-values))
          (is = 0 (third first-values)))))))

(define-test pty-shell-allows-concurrent-blocking-read-and-write
  :parent (:ssh/integration-tests ssh/integration-tests)
  (with-live-client (client :identity (fixture-path "id_ed25519_nopass"))
    (multiple-value-bind (stream channel)
        (open-shell client :pty t)
      (declare (ignore channel))
      (unwind-protect
           (let ((text nil)
                 (status nil)
                 (read-error nil))
             (let ((reader
                     (bt2:make-thread
                      (lambda ()
                        (handler-case
                            (multiple-value-setq (text status)
                              (shell-read-until stream "__TTY_DONE__"))
                          (error (condition)
                            (setf read-error condition)))))))
               (shell-write-line stream
                                 "printf 'tty-full-duplex'; printf '__TTY_DONE__'")
               (bt2:join-thread reader)
               (false read-error)
               (is eq :found status)
               (true (search "tty-full-duplex" text))))
        (ignore-errors (close stream))))))

(define-test active-shell-and-command-use-isolated-live-channels
  :parent (:ssh/integration-tests ssh/integration-tests)
  (with-live-client (client :identity (fixture-path "id_ed25519_nopass"))
    (multiple-value-bind (stream channel)
        (open-shell client)
      (declare (ignore channel))
      (unwind-protect
           (let ((shell-text nil)
                 (shell-status nil))
             (let ((reader
                     (bt2:make-thread
                      (lambda ()
                        (multiple-value-setq (shell-text shell-status)
                          (shell-read-until stream "__SHELL_DONE__"))))))
               (shell-write-line stream
                                 "printf shell-active; printf __SHELL_DONE__")
               (multiple-value-bind (stdout stderr exit-code)
                   (run-command client "printf command-active")
                 (is string= "command-active" stdout)
                 (is string= "" stderr)
                 (is = 0 exit-code))
               (bt2:join-thread reader)
               (is string= "shell-active" shell-text)
               (is eq :found shell-status)))
        (ignore-errors (close stream))))))

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

(define-test accept-new-host-key-checking-rejects-changed-key
  :parent (:ssh/integration-tests ssh/integration-tests)
  (let ((target (integration-target)))
    (if target
        (let* ((known-hosts
                 (write-temp-known-hosts
                  (integration-target-host target)
                  "ssh-ed25519"
                  (fixture-public-key-base64 "id_ed25519_nopass.pub")))
               (original (uiop:read-file-string known-hosts)))
          (of-type 'ssh/known-hosts:host-key-changed-error
            (handler-case
                (let ((client
                        (connect
                         (integration-target-host target)
                         :port (integration-target-port target)
                         :username (integration-target-user target)
                         :known-hosts-path known-hosts
                         :strict-host-checking :accept-new)))
                  (unwind-protect nil (disconnect client)))
              (ssh/known-hosts:host-key-changed-error (condition) condition)))
          (is string= original (uiop:read-file-string known-hosts))
          (false
           (probe-file
            (ssh/known-hosts::known-hosts-lock-path known-hosts))))
        (skip
         "requires SSH_TEST_HOST, SSH_TEST_PORT, SSH_TEST_USER, and SSH_TEST_KNOWN_HOSTS"
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
