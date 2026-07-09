;;;; Tests for ssh/known-hosts -- known_hosts verification and updates.

(defpackage :ssh/tests/known-hosts
  (:use :cl :parachute)
  (:import-from :ssh/tests #:octets)
  (:import-from :ssh/known-hosts #:check-host-key))

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
                        :known-hosts-path path))
    (false (probe-file lock-path))))
