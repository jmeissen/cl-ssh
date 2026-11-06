;;;; Tests for ssh/known-hosts -- known_hosts verification and updates.

(defpackage :ssh/tests/known-hosts
  (:use :cl :parachute)
  (:import-from :ssh/tests #:octets)
  (:import-from :ssh/known-hosts
                #:check-host-key
                #:normalize-host-key-policy
                #:unknown-host-key-error
                #:unknown-host-key-error-hostname
                #:unknown-host-key-error-key-type
                #:unknown-host-key-error-received-fingerprint
                #:host-key-changed-error))

(in-package :ssh/tests/known-hosts)

;;;; Helpers

(defun write-temp-known-hosts (content)
  "Write CONTENT to a fresh temp known_hosts file and return its pathname."
  (let ((path (merge-pathnames (format nil "cl-ssh-test-~A.known_hosts" (gensym))
                               (uiop:temporary-directory))))
    (with-open-file (f path :direction :output
                            :if-exists :supersede
                            :if-does-not-exist :create)
      (write-string content f))
    path))

;;;; ---- Non-strict update --------------------------------------------------

(define-test check-host-key-non-strict-updates-changed-entry
  :parent (:ssh/tests ssh/tests)
  (let* ((old-key (octets 1 2 3))
         (new-key (octets 4 5 6))
         (path (write-temp-known-hosts
                (format nil "example.com ssh-ed25519 AQID~%"))))
    (is eq :accepted-changed
        (check-host-key "example.com" "ssh-ed25519" new-key
                        :known-hosts-path path
                        :strict nil))
    (let* ((entries (ssh/known-hosts::load-known-hosts path))
           (entry (first entries)))
      (is = 1 (length entries))
      (is equalp new-key (ssh/known-hosts::known-hosts-entry-key-blob entry))
      (false (equalp old-key (ssh/known-hosts::known-hosts-entry-key-blob entry))))))

(define-test check-host-key-default-rejects-unknown-without-writing
  :parent (:ssh/tests ssh/tests)
  (let* ((key (octets 1 2 3))
         (path (write-temp-known-hosts ""))
         (lock-path (ssh/known-hosts::known-hosts-lock-path path))
         (condition
           (handler-case
               (progn
                 (check-host-key "unknown.example" "ssh-ed25519" key
                                 :known-hosts-path path)
                 nil)
             (unknown-host-key-error (caught) caught))))
    (of-type 'unknown-host-key-error condition)
    (is string= "unknown.example"
        (unknown-host-key-error-hostname condition))
    (is string= "ssh-ed25519"
        (unknown-host-key-error-key-type condition))
    (of-type 'string
             (unknown-host-key-error-received-fingerprint condition))
    (is string= "" (uiop:read-file-string path))
    (false (probe-file lock-path))))

(define-test check-host-key-accept-new-records-unknown
  :parent (:ssh/tests ssh/tests)
  (let* ((key (octets 1 2 3))
         (path (write-temp-known-hosts "")))
    (is eq :accepted-tofu
        (check-host-key "new.example" "ssh-ed25519" key
                        :known-hosts-path path
                        :strict :accept-new))
    (let ((entries (ssh/known-hosts::load-known-hosts path)))
      (is = 1 (length entries))
      (is string= "new.example"
          (ssh/known-hosts::known-hosts-entry-raw-hostname
           (first entries))))))

(define-test check-host-key-accept-new-rejects-changed-without-writing
  :parent (:ssh/tests ssh/tests)
  (let* ((path
           (write-temp-known-hosts
            (format nil "example.com ssh-ed25519 AQID~%")))
         (original (uiop:read-file-string path))
         (lock-path (ssh/known-hosts::known-hosts-lock-path path))
         (condition
           (handler-case
               (progn
                 (check-host-key "example.com" "ssh-ed25519"
                                 (octets 4 5 6)
                                 :known-hosts-path path
                                 :strict :accept-new)
                 nil)
             (host-key-changed-error (caught) caught))))
    (of-type 'host-key-changed-error condition)
    (is string= original (uiop:read-file-string path))
    (false (probe-file lock-path))))

(define-test normalize-host-key-policy-aliases
  :parent (:ssh/tests ssh/tests)
  (is eq :yes (normalize-host-key-policy t))
  (is eq :yes (normalize-host-key-policy :yes))
  (is eq :yes (normalize-host-key-policy :default))
  (is eq :yes (normalize-host-key-policy :ask))
  (is eq :no (normalize-host-key-policy nil))
  (is eq :no (normalize-host-key-policy :no))
  (is eq :accept-new (normalize-host-key-policy :accept-new)))

;;;; ---- Hostname matching -------------------------------------------------

(define-test check-host-key-matches-hostname-case-insensitively
  :parent (:ssh/tests ssh/tests)
  (let* ((key (octets 1 2 3))
         (path (write-temp-known-hosts
                (format nil "Example.COM ssh-ed25519 AQID~%"))))
    (is eq :accepted-known
        (check-host-key "example.com" "ssh-ed25519" key
                        :known-hosts-path path))
    (let ((entries (ssh/known-hosts::load-known-hosts path)))
      (is = 1 (length entries))
      (is string= "Example.COM"
          (ssh/known-hosts::known-hosts-entry-raw-hostname (first entries))))))

(define-test load-known-hosts-skips-invalid-utf-8-lines
  :parent (:ssh/tests ssh/tests)
  (let ((path (merge-pathnames (format nil "cl-ssh-test-invalid-utf8-~A.known_hosts"
                                       (gensym))
                               (uiop:temporary-directory))))
    (unwind-protect
         (progn
           (with-open-file (stream path
                                   :direction :output
                                   :if-exists :supersede
                                   :if-does-not-exist :create
                                   :element-type '(unsigned-byte 8))
             (write-byte #xc0 stream)
             (write-byte #x0a stream)
             (write-sequence
              (babel:string-to-octets
               (format nil "example.com ssh-ed25519 AQID~%")
               :encoding :utf-8)
              stream))
           (let ((entries (ssh/known-hosts::load-known-hosts path)))
             (is = 1 (length entries))
             (is string= "example.com"
                 (ssh/known-hosts::known-hosts-entry-raw-hostname
                  (first entries)))))
      (ignore-errors (delete-file path)))))

;;;; ---- File locking ------------------------------------------------------

(define-test add-known-host-respects-existing-lock-file
  :parent (:ssh/tests ssh/tests)
  (let* ((path (write-temp-known-hosts ""))
         (lock-path (ssh/known-hosts::known-hosts-lock-path path)))
    (unwind-protect
         (with-open-file (lock lock-path :direction :output
                                         :if-exists :supersede
                                         :if-does-not-exist :create)
           (let ((ssh/known-hosts::*known-hosts-lock-timeout-seconds* 0)
                 (ssh/known-hosts::*known-hosts-lock-retry-delay-seconds* 0))
             (fail (ssh/known-hosts::add-known-host
                    path "example.com" "ssh-ed25519" (octets 1 2 3))
                   'ssh/known-hosts::known-hosts-lock-error)))
      (ignore-errors
       (delete-file lock-path)))))

(define-test check-host-key-removes-lock-file-after-write
  :parent (:ssh/tests ssh/tests)
  (let* ((key (octets 1 2 3))
         (path (write-temp-known-hosts ""))
         (lock-path (ssh/known-hosts::known-hosts-lock-path path)))
    (is eq :accepted-tofu
        (check-host-key "example.com" "ssh-ed25519" key
                        :known-hosts-path path
                        :strict :accept-new))
    (false (probe-file lock-path))))

(define-test rsa-sha2-uses-existing-rsa-pins
  :parent (:ssh/tests ssh/tests)
  ;; Like OpenSSH regress/keytype.sh: the key format remains ssh-rsa.
  (dolist (stored '("ssh-rsa" "rsa-sha2-256" "rsa-sha2-512"))
    (dolist (algorithm '("rsa-sha2-256" "rsa-sha2-512"))
      (let* ((content (format nil "example.com ~A AQID~%" stored))
             (path (write-temp-known-hosts content)))
        (unwind-protect
             (progn
               (is eq :accepted-known
                   (check-host-key "example.com" algorithm (octets 1 2 3)
                                   :known-hosts-path path))
               (fail (check-host-key "example.com" algorithm (octets 4 5 6)
                                     :known-hosts-path path :strict :accept-new)
                     'host-key-changed-error)
               (is string= content (uiop:read-file-string path)))
          (delete-file path)))))
  (let ((path (write-temp-known-hosts "")))
    (unwind-protect
         (progn
           (check-host-key "example.com" "rsa-sha2-512" (octets 1 2 3)
                           :known-hosts-path path :strict :accept-new)
           (is string= (format nil "example.com ssh-rsa AQID~%")
               (uiop:read-file-string path)))
      (delete-file path))))

(define-test revoked-host-key-overrides-trust-and-policy
  :parent (:ssh/tests ssh/tests)
  ;; OpenSSH regress/cert-hostkey.sh uses "@revoked *"; also exercise order.
  (dolist (policy '(:yes :accept-new :no))
    (dolist (pattern '("example.com" "*" "*.com" "other,example.com"))
      (dolist (revoked-first '(nil t))
        (let* ((trust (format nil "example.com ssh-rsa AQID~%"))
               (revocation (format nil "@revoked ~A ssh-rsa AQID~%" pattern))
               (content (if revoked-first
                            (concatenate 'string revocation trust)
                            (concatenate 'string trust revocation)))
               (path (write-temp-known-hosts content)))
          (unwind-protect
               (progn
                 (fail (check-host-key "example.com" "rsa-sha2-256" (octets 1 2 3)
                                       :known-hosts-path path :strict policy)
                       'ssh/known-hosts::host-key-revoked-error)
                 (is string= content (uiop:read-file-string path)))
            (delete-file path)))))))

(define-test revocation-is-scoped-and-preserved
  :parent (:ssh/tests ssh/tests)
  (dolist (revocation '("@revoked other.com ssh-ed25519 AQID"
                        "@revoked *,!example.com ssh-ed25519 AQID"
                        "@revoked * ssh-ed25519 BAUG"))
    (let ((path (write-temp-known-hosts
                 (format nil "~A~%example.com ssh-ed25519 AQID~%" revocation))))
      (unwind-protect
           (is eq :accepted-known
               (check-host-key "example.com" "ssh-ed25519" (octets 1 2 3)
                               :known-hosts-path path))
        (delete-file path))))
  (let* ((revocation "@revoked * ssh-ed25519 BwgJ")
         (path (write-temp-known-hosts
                (format nil "~A~%example.com ssh-ed25519 AQID~%" revocation))))
    (unwind-protect
         (progn
           (is eq :accepted-changed
               (check-host-key "example.com" "ssh-ed25519" (octets 4 5 6)
                               :known-hosts-path path :strict :no))
           (true (search revocation (uiop:read-file-string path)))
           (fail (check-host-key "example.com" "ssh-ed25519" (octets 7 8 9)
                                 :known-hosts-path path :strict :no)
                 'ssh/known-hosts::host-key-revoked-error))
      (delete-file path))))

(define-test changed-key-does-not-replace-other-hosts-in-a-shared-pin
  :parent (:ssh/tests ssh/tests)
  (dolist (pattern '("*.com" "example.com,other.com"))
    (let ((path (write-temp-known-hosts
                 (format nil "~A ssh-ed25519 AQID~%" pattern))))
      (unwind-protect
           (progn
             (check-host-key "example.com" "ssh-ed25519" (octets 4 5 6)
                             :known-hosts-path path :strict :no)
             (is eq :accepted-known
                 (check-host-key "example.com" "ssh-ed25519" (octets 4 5 6)
                                 :known-hosts-path path))
             (is eq :accepted-known
                 (check-host-key "other.com" "ssh-ed25519" (octets 1 2 3)
                                 :known-hosts-path path))
             (fail (check-host-key "other.com" "ssh-ed25519" (octets 4 5 6)
                                   :known-hosts-path path)
                   'host-key-changed-error)
             (fail (check-host-key "example.com" "ssh-ed25519" (octets 1 2 3)
                                   :known-hosts-path path)
                   'host-key-changed-error))
        (delete-file path)))))

(define-test hashed-revocations-and-unsupported-markers
  :parent (:ssh/tests ssh/tests)
  (let* ((salt (make-array 20 :element-type '(unsigned-byte 8) :initial-element 7))
         (mac (ironclad:make-mac :hmac salt :sha1)))
    (ironclad:update-mac mac (ssh/buffer:utf-8-to-octets "example.com"))
    (let* ((hashed (format nil "|1|~A|~A"
                           (ssh/known-hosts::base64-encode salt)
                           (ssh/known-hosts::base64-encode (ironclad:produce-mac mac))))
           (path (write-temp-known-hosts
                  (format nil "@revoked ~A ssh-ed25519 AQID~%" hashed)))
           (before (uiop:read-file-string path)))
      (unwind-protect
           (dolist (policy '(:yes :accept-new :no))
             (fail (check-host-key "example.com" "ssh-ed25519" (octets 1 2 3)
                                   :known-hosts-path path :strict policy)
                   'ssh:host-key-revoked-error)
             (is string= before (uiop:read-file-string path)))
        (delete-file path))))
  (dolist (marker '("@cert-authority" "@unknown"))
    (let ((path (write-temp-known-hosts
                 (format nil "~A example.com ssh-ed25519 AQID~%" marker))))
      (unwind-protect
           (fail (check-host-key "example.com" "ssh-ed25519" (octets 1 2 3)
                                 :known-hosts-path path)
                 'unknown-host-key-error)
        (delete-file path)))))
