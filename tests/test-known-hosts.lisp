;;;; Tests for ssh/known-hosts -- known_hosts verification and updates.

(defpackage :ssh/tests/known-hosts
  (:use :cl :parachute)
  (:import-from :ssh/tests #:octets)
  (:import-from :ssh/known-hosts #:check-host-key))

(in-package :ssh/tests/known-hosts)

;;;; Helpers

(defun write-temp-known-hosts (content)
  "Write CONTENT to a fresh temp known_hosts file and return its pathname."
  (let ((path (merge-pathnames "cl-ssh-test.known_hosts"
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
         (path (write-temp-known-hosts "example.com ssh-ed25519 AQID\n")))
    (is eq :accepted-changed
        (check-host-key "example.com" "ssh-ed25519" new-key
                        :known-hosts-path path
                        :strict nil))
    (let* ((entries (ssh/known-hosts::load-known-hosts path))
           (entry (first entries)))
      (is = 1 (length entries))
      (is equalp new-key (ssh/known-hosts::known-hosts-entry-key-blob entry))
      (false (equalp old-key (ssh/known-hosts::known-hosts-entry-key-blob entry))))))
