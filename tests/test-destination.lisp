(defpackage :ssh/tests/destination
  (:use :cl :parachute))

(in-package :ssh/tests/destination)

(define-test destination-openssh-uri-cases
  :parent (:ssh/tests ssh/tests)
  ;; Adapted from OpenSSH connect-uri.sh: no slash, empty slash, nonempty path.
  (dolist (input '("ssh://someuser@some.host:22"
                   "ssh://someuser@some.host:22/"))
    (is equal '("some.host" "someuser" 22)
        (multiple-value-list (ssh::parse-destination input))))
  ;; The generic OpenSSH URI unit test permits a path; the SSH wrapper rejects it.
  (fail (ssh::parse-destination "ssh://someuser@some.host:22/some/path")))

(define-test connect-destination-ipv6-and-defaults
  :parent (:ssh/tests ssh/tests)
  (multiple-value-bind (client connect-call auth-call)
      (ssh/tests/ssh::run-connect-with-mocks :destination "ssh://alice@[::1]:2222/")
    (true client)
    (is string= "::1" (first connect-call))
    (is = 2222 (getf (second connect-call) :port))
    (is string= "alice" (second auth-call)))
  (multiple-value-bind (client connect-call auth-call)
      (ssh/tests/ssh::run-connect-with-mocks :destination "ssh://example.com")
    (true client)
    (is string= "example.com" (first connect-call))
    (is = 22 (getf (second connect-call) :port))
    (is string= (ssh::get-current-username) (second auth-call))))

(define-test connect-rejects-invalid-destinations-before-config-or-network
  :parent (:ssh/tests ssh/tests)
  (let ((original (symbol-function 'ssh/config:resolve-host))
        (resolved nil))
    (unwind-protect
         (progn
           (setf (symbol-function 'ssh/config:resolve-host)
                 (lambda (&rest args)
                   (declare (ignore args))
                   (setf resolved t)
                   (error "Unexpected config lookup.")))
           (dolist (destination '("ssh://host/path" "ssh://host:0" "ssh://[::1"))
             (fail (ssh:connect destination)))
           (false resolved))
      (setf (symbol-function 'ssh/config:resolve-host) original))))

(define-test connect-destination-precedence
  :parent (:ssh/tests ssh/tests)
  (dolist (case '(("ssh://uri-user@myserver:2222" nil "uri-user" 2222)
                  ("uri-user@myserver" nil "uri-user" 2200)
                  ("ssh://myserver" nil "config-user" 2200)
                  ("ssh://uri-user@myserver:2222" (:username "explicit" :port 2223)
                   "explicit" 2223)))
    (destructuring-bind (destination args expected-user expected-port) case
      (multiple-value-bind (client connect-call auth-call)
          (ssh/tests/ssh::run-connect-with-mocks
           :destination destination :connect-args args
           :config-content "Host myserver
    HostName real.example.com
    User config-user
    Port 2200
")
        (true client)
        (is string= "real.example.com" (first connect-call))
        (is = expected-port (getf (second connect-call) :port))
        (is string= expected-user (second auth-call))))))

(define-test destination-invalid-input
  :parent (:ssh/tests ssh/tests)
  (dolist (input '("" "@host" "alice@" "host/path" "alice@host:/path"
                   "host:2222" "alice@host:2222" "host?query" "host#fragment"
                   "host name" "ssh://" "ssh://@host" "ssh://alice@"
                   "ssh://host:0" "ssh://host:65536" "ssh://host:-1"
                   "ssh://host:22x" "ssh://host:22:23" "ssh://host:"
                   "ssh://host:/" "ssh://[::1" "ssh://[]"
                   "ssh://[::1]junk" "ssh://::1" "ssh://host/path"
                   "ssh://host//" "ssh://host?query" "ssh://host#fragment"
                   "ssh://a@b@host" "ssh://%00@host" "ssh://%@host"
                   "ssh://%0@host" "ssh://%GG@host" "ssh://;x=y@host"
                   "sftp://alice@host" "https://host"
                   "ssh://host/path@other" "ssh://a?b@host" "ssh://a#b@host"
                   "alice/path@host" "alice?query@host" "alice#fragment@host"))
    (fail (ssh::parse-destination input)))
  (fail (ssh::parse-destination (concatenate 'string "host" (string (code-char 0))))))

(define-test destination-uri-user-decoding
  :parent (:ssh/tests ssh/tests)
  (dolist (case '(("ssh://alice%40realm@host" "host" "alice@realm" nil)
                  ("ssh://alice+smith@host" "host" "alice smith" nil)
                  ("ssh://alice%2Bsmith@host" "host" "alice+smith" nil)
                  ("ssh://jos%C3%A9@host" "host" "josé" nil)
                  ("ssh://alice;fingerprint=ignored@host" "host" "alice" nil)
                  ("alice%40realm@host" "host" "alice%40realm" nil)))
    (is equal (rest case)
        (multiple-value-list (ssh::parse-destination (first case))))))

(define-test destination-hosts-and-ipv6
  :parent (:ssh/tests ssh/tests)
  (dolist (case '(("myserver" "myserver" nil nil)
                  ("alice@myserver" "myserver" "alice" nil)
                  ("alice@realm@myserver" "myserver" "alice@realm" nil)
                  ("1.22.33.144" "1.22.33.144" nil nil)
                  ("::1" "::1" nil nil)
                  ("alice@2001:db8::1" "2001:db8::1" "alice" nil)
                  ("ssh://myserver" "myserver" nil nil)
                  ("ssh://myserver:2222" "myserver" nil 2222)
                  ("ssh://someuser@1.22.33.144:22" "1.22.33.144" "someuser" 22)
                  ("ssh://someuser@[1.22.33.144]:22" "1.22.33.144" "someuser" 22)
                  ("ssh://someuser@[::1]:2222" "::1" "someuser" 2222)
                  ("ssh://[2001:db8::1]" "2001:db8::1" nil nil)
                  ("ssh://host:1" "host" nil 1)
                  ("ssh://host:65535/" "host" nil 65535)))
    (is equal (rest case)
        (multiple-value-list (ssh::parse-destination (first case))))))
