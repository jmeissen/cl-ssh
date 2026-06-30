;;;; Tests for ssh/config — ~/.ssh/config parser.
;;;;
;;;; Internal helpers are tested directly via double-colon access.
;;;; File-level tests write temporary config files so no real ~/.ssh/config
;;;; is touched.

(defpackage :ssh/tests/config
  (:use :cl :parachute)
  (:import-from :ssh/tests #:octets)
  (:import-from :ssh/config
    #:resolve-host
    #:ssh-config-hostname
    #:ssh-config-port
    #:ssh-config-user
    #:ssh-config-identity-files
    #:ssh-config-strict-host-checking
    #:ssh-config-known-hosts-file
    #:ssh-config-rekey-byte-limit
    #:ssh-config-rekey-seconds-limit))

(in-package :ssh/tests/config)

;;;; Helpers

(defun glob-match-p (pattern string)
  (ssh/config::glob-match-p pattern string))

(defun patterns-match-p (patterns alias)
  (ssh/config::patterns-match-p patterns alias))

(defun expand-tilde (s)
  (ssh/config::expand-tilde s))

(defun write-temp-config (content)
  "Write CONTENT to a fresh temp file and return its pathname."
  (let ((path (merge-pathnames "cl-ssh-test.config"
                               (uiop:temporary-directory))))
    (with-open-file (f path :direction :output
                            :if-exists :supersede
                            :if-does-not-exist :create)
      (write-string content f))
    path))

(defmacro with-config (content &body body)
  "Write CONTENT as a temporary SSH config file, bind *config-path* and
   run BODY with RESOLVE bound to (lambda (alias) (resolve-host alias ...))."
  (let ((path (gensym "PATH")))
    `(let* ((,path   (write-temp-config ,content))
            (resolve (lambda (alias) (resolve-host alias :config-path ,path))))
       (declare (ignorable resolve))
       ,@body)))

;;; ---- glob-match-p -------------------------------------------------------

(define-test glob-exact-match
  :parent (:ssh/tests ssh/tests)
  (true  (glob-match-p "foo" "foo"))
  (false (glob-match-p "foo" "bar"))
  (false (glob-match-p "foo" "foobar")))

(define-test glob-case-insensitive
  :parent (:ssh/tests ssh/tests)
  (true (glob-match-p "MyServer" "myserver"))
  (true (glob-match-p "myserver" "MyServer"))
  (true (glob-match-p "MYSERVER" "myserver")))

(define-test glob-star-matches-any-sequence
  :parent (:ssh/tests ssh/tests)
  (true  (glob-match-p "*"       "anything"))
  (true  (glob-match-p "*"       ""))
  (true  (glob-match-p "foo*"    "foobar"))
  (true  (glob-match-p "foo*"    "foo"))
  (false (glob-match-p "foo*"    "barfoo"))
  (true  (glob-match-p "*foo"    "barfoo"))
  (true  (glob-match-p "f*bar"   "foobar"))
  (true  (glob-match-p "*.example.com" "host.example.com"))
  (false (glob-match-p "*.example.com" "host.other.com")))

(define-test glob-question-matches-one-char
  :parent (:ssh/tests ssh/tests)
  (true  (glob-match-p "fo?"    "foo"))
  (true  (glob-match-p "fo?"    "fob"))
  (false (glob-match-p "fo?"    "fo"))
  (false (glob-match-p "fo?"    "fooo"))
  (true  (glob-match-p "???"    "abc"))
  (false (glob-match-p "???"    "ab")))

(define-test glob-combined-wildcards
  :parent (:ssh/tests ssh/tests)
  (true  (glob-match-p "web-?.example.com" "web-1.example.com"))
  (false (glob-match-p "web-?.example.com" "web-12.example.com"))
  (true  (glob-match-p "web-*.example.com" "web-12.example.com")))

;;; ---- patterns-match-p ---------------------------------------------------

(define-test patterns-single-match
  :parent (:ssh/tests ssh/tests)
  (true  (patterns-match-p '("myserver") "myserver"))
  (false (patterns-match-p '("myserver") "other")))

(define-test patterns-multiple-alternatives
  :parent (:ssh/tests ssh/tests)
  ;; Any one pattern matching is sufficient
  (true  (patterns-match-p '("host1" "host2") "host1"))
  (true  (patterns-match-p '("host1" "host2") "host2"))
  (false (patterns-match-p '("host1" "host2") "host3")))

(define-test patterns-wildcard-catch-all
  :parent (:ssh/tests ssh/tests)
  (true (patterns-match-p '("*") "anything"))
  (true (patterns-match-p '("*") "192.168.1.1")))

(define-test patterns-negation
  :parent (:ssh/tests ssh/tests)
  ;; !pattern excludes the alias even when another pattern matched
  (false (patterns-match-p '("*" "!myserver") "myserver"))
  (true  (patterns-match-p '("*" "!myserver") "otherserver"))
  ;; Negation alone (no positive match) never matches
  (false (patterns-match-p '("!badhost") "goodhost")))

;;; ---- expand-tilde -------------------------------------------------------

(define-test expand-tilde-alone
  :parent (:ssh/tests ssh/tests)
  (let ((home (namestring (user-homedir-pathname))))
    (is string= home (expand-tilde "~"))))

(define-test expand-tilde-with-path
  :parent (:ssh/tests ssh/tests)
  (let* ((home     (namestring (user-homedir-pathname)))
         (expanded (expand-tilde "~/.ssh/id_ed25519")))
    ;; home ends with a slash (it's a directory pathname); the relative
    ;; portion directly follows it in the expanded string.
    (is string= home (subseq expanded 0 (length home)))
    (is string= ".ssh/id_ed25519" (subseq expanded (length home)))))

(define-test expand-tilde-absolute-unchanged
  :parent (:ssh/tests ssh/tests)
  (is string= "/etc/ssh/key" (expand-tilde "/etc/ssh/key")))

(define-test expand-tilde-no-tilde-unchanged
  :parent (:ssh/tests ssh/tests)
  (is string= "relative/path" (expand-tilde "relative/path")))

;;; ---- resolve-host: basic matching --------------------------------------

(define-test resolve-host-exact-alias
  :parent (:ssh/tests ssh/tests)
  (with-config "Host myserver
    HostName 192.168.1.10
    Port 2222
    User alice
"
    (let ((cfg (funcall resolve "myserver")))
      (is string= "192.168.1.10" (ssh-config-hostname cfg))
      (is =       2222           (ssh-config-port cfg))
      (is string= "alice"        (ssh-config-user cfg)))))

(define-test resolve-host-no-match-returns-empty
  :parent (:ssh/tests ssh/tests)
  (with-config "Host myserver
    HostName 192.168.1.10
"
    (let ((cfg (funcall resolve "otherhost")))
      (is eq nil (ssh-config-hostname cfg))
      (is eq nil (ssh-config-port cfg)))))

(define-test resolve-host-catch-all-star
  :parent (:ssh/tests ssh/tests)
  (with-config "Host *
    User defaultuser
    StrictHostKeyChecking yes
"
    (let ((cfg (funcall resolve "anything.example.com")))
      (is string= "defaultuser" (ssh-config-user cfg))
      (is eq :yes (ssh-config-strict-host-checking cfg)))))

(define-test resolve-host-specific-then-star
  :parent (:ssh/tests ssh/tests)
  ;; Specific block sets User; Host * provides a fallback Port
  (with-config "Host myserver
    HostName real.host.com
    User alice

Host *
    Port 22
    User defaultuser
"
    (let ((cfg (funcall resolve "myserver")))
      ;; Specific match wins for User
      (is string= "alice"         (ssh-config-user cfg))
      (is string= "real.host.com" (ssh-config-hostname cfg))
      ;; Port came from Host *
      (is = 22 (ssh-config-port cfg)))))

;;; ---- resolve-host: first-match-wins ------------------------------------

(define-test first-match-wins-for-duplicate-keys
  :parent (:ssh/tests ssh/tests)
  ;; Two blocks both match; the first Port wins
  (with-config "Host web*
    Port 8080

Host web-prod
    Port 443
    User deploy
"
    (let ((cfg (funcall resolve "web-prod")))
      (is = 8080 (ssh-config-port cfg))     ; first match wins
      (is string= "deploy" (ssh-config-user cfg)))))  ; only in second block

;;; ---- resolve-host: IdentityFile accumulation ---------------------------

(define-test identity-files-accumulate-in-order
  :parent (:ssh/tests ssh/tests)
  (with-config "Host myserver
    IdentityFile /keys/ed25519
    IdentityFile /keys/rsa

Host *
    IdentityFile /keys/fallback
"
    (let ((ids (ssh-config-identity-files (funcall resolve "myserver"))))
      (is = 3 (length ids))
      (is string= "/keys/ed25519"  (first ids))
      (is string= "/keys/rsa"      (second ids))
      (is string= "/keys/fallback" (third ids)))))

(define-test identity-files-no-duplicates
  :parent (:ssh/tests ssh/tests)
  (with-config "Host myserver
    IdentityFile /keys/shared

Host *
    IdentityFile /keys/shared
"
    (let ((ids (ssh-config-identity-files (funcall resolve "myserver"))))
      (is = 1 (length ids)))))

;;; ---- resolve-host: StrictHostKeyChecking values ------------------------

(define-test strict-host-checking-yes
  :parent (:ssh/tests ssh/tests)
  (with-config "Host myserver
    StrictHostKeyChecking yes
"
    (is eq :yes (ssh-config-strict-host-checking (funcall resolve "myserver")))))

(define-test strict-host-checking-no
  :parent (:ssh/tests ssh/tests)
  (with-config "Host myserver
    StrictHostKeyChecking no
"
    (is eq :no (ssh-config-strict-host-checking (funcall resolve "myserver")))))

(define-test strict-host-checking-accept-new
  :parent (:ssh/tests ssh/tests)
  (with-config "Host myserver
    StrictHostKeyChecking accept-new
"
    (is eq :accept-new (ssh-config-strict-host-checking (funcall resolve "myserver")))))

(define-test strict-host-checking-default-when-absent
  :parent (:ssh/tests ssh/tests)
  (with-config "Host myserver
    HostName real.host.com
"
    (is eq :default (ssh-config-strict-host-checking (funcall resolve "myserver")))))

;;; ---- resolve-host: comments and blank lines ----------------------------

(define-test config-ignores-comments-and-blanks
  :parent (:ssh/tests ssh/tests)
  (with-config "# This is a comment
Host myserver
    # Another comment
    HostName 10.0.0.1

    Port 2022
"
    (let ((cfg (funcall resolve "myserver")))
      (is string= "10.0.0.1" (ssh-config-hostname cfg))
      (is = 2022 (ssh-config-port cfg)))))

;;; ---- resolve-host: key=value syntax ------------------------------------

(define-test config-accepts-equals-separator
  :parent (:ssh/tests ssh/tests)
  (with-config "Host myserver
    HostName=10.0.0.1
    Port=9999
    User=bob
"
    (let ((cfg (funcall resolve "myserver")))
      (is string= "10.0.0.1" (ssh-config-hostname cfg))
      (is = 9999 (ssh-config-port cfg))
      (is string= "bob" (ssh-config-user cfg)))))

;;; ---- resolve-host: RekeyLimit -----------------------------------------

(define-test rekey-limit-parses-byte-units
  :parent (:ssh/tests ssh/tests)
  (with-config "Host myserver
    RekeyLimit 64K
"
    (let ((cfg (funcall resolve "myserver")))
      (is = 65536 (ssh-config-rekey-byte-limit cfg))
      (is eq nil (ssh-config-rekey-seconds-limit cfg)))))

(define-test rekey-limit-parses-byte-and-time-units
  :parent (:ssh/tests ssh/tests)
  (with-config "Host myserver
    RekeyLimit 512M 2h
"
    (let ((cfg (funcall resolve "myserver")))
      (is = (* 512 1024 1024) (ssh-config-rekey-byte-limit cfg))
      (is = 7200 (ssh-config-rekey-seconds-limit cfg)))))

(define-test rekey-limit-none-disables-time-limit
  :parent (:ssh/tests ssh/tests)
  (with-config "Host myserver
    RekeyLimit 1G none
"
    (let ((cfg (funcall resolve "myserver")))
      (is = (* 1024 1024 1024) (ssh-config-rekey-byte-limit cfg))
      (is eq nil (ssh-config-rekey-seconds-limit cfg)))))

(define-test rekey-limit-none-disables-byte-and-time-limit
  :parent (:ssh/tests ssh/tests)
  (with-config "Host myserver
    RekeyLimit none
"
    (let ((cfg (funcall resolve "myserver")))
      (is eq nil (ssh-config-rekey-byte-limit cfg))
      (is eq nil (ssh-config-rekey-seconds-limit cfg)))))

(define-test rekey-limit-default-keeps-library-byte-default
  :parent (:ssh/tests ssh/tests)
  (with-config "Host myserver
    RekeyLimit default 30m
"
    (let ((cfg (funcall resolve "myserver")))
      (is eq :default (ssh-config-rekey-byte-limit cfg))
      (is = 1800 (ssh-config-rekey-seconds-limit cfg)))))

(define-test rekey-limit-first-match-wins
  :parent (:ssh/tests ssh/tests)
  (with-config "Host web*
    RekeyLimit 32K 10s

Host web-prod
    RekeyLimit 1G 1h
"
    (let ((cfg (funcall resolve "web-prod")))
      (is = 32768 (ssh-config-rekey-byte-limit cfg))
      (is = 10 (ssh-config-rekey-seconds-limit cfg)))))

(define-test rekey-limit-invalid-value-is-ignored
  :parent (:ssh/tests ssh/tests)
  (with-config "Host myserver
    RekeyLimit nonsense
"
    (let ((cfg (funcall resolve "myserver")))
      (is eq :unset (ssh-config-rekey-byte-limit cfg))
      (is eq :unset (ssh-config-rekey-seconds-limit cfg)))))

;;; ---- resolve-host: missing file ----------------------------------------

(define-test missing-config-file-returns-empty
  :parent (:ssh/tests ssh/tests)
  (let ((cfg (resolve-host "anyhost"
                           :config-path #p"/nonexistent/path/ssh_config")))
    (is eq nil (ssh-config-hostname cfg))
    (is eq nil (ssh-config-port cfg))
    (is eq nil (ssh-config-user cfg))
    (is eq :default (ssh-config-strict-host-checking cfg))
    (is eq :unset (ssh-config-rekey-byte-limit cfg))
    (is eq :unset (ssh-config-rekey-seconds-limit cfg))))
