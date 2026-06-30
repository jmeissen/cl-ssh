;;;; Tests for ssh/ssh — public API option handling.

(defpackage :ssh/tests/ssh
  (:use :cl :parachute)
  (:import-from :ssh
                #:connect))

(in-package :ssh/tests/ssh)

(defun run-connect-with-mocks (&key config-content connect-args)
  (let* ((mock-config-path (ssh/tests/config::write-temp-config (or config-content "")))
         (original-resolve (symbol-function 'ssh/config:resolve-host))
         (original-connect (symbol-function 'ssh/transport:connect-transport))
         (original-authenticate (symbol-function 'ssh/auth:authenticate))
         (captured-connect-args nil)
         (captured-authenticate-args nil)
         (transport (ssh/transport::make-transport)))
    (unwind-protect
         (progn
           (setf (symbol-function 'ssh/config:resolve-host)
                 (lambda (alias &key config-path)
                   (declare (ignore config-path))
                   (funcall original-resolve alias :config-path mock-config-path))
                 (symbol-function 'ssh/transport:connect-transport)
                 (lambda (host &rest args)
                   (setf captured-connect-args (list host args))
                   transport)
                 (symbol-function 'ssh/auth:authenticate)
                 (lambda (&rest args)
                   (setf captured-authenticate-args args)
                   t))
           (values (apply #'connect "myserver" connect-args)
                   captured-connect-args
                   captured-authenticate-args))
      (setf (symbol-function 'ssh/config:resolve-host) original-resolve
            (symbol-function 'ssh/transport:connect-transport) original-connect
            (symbol-function 'ssh/auth:authenticate) original-authenticate))))

(define-test connect-passes-explicit-rekey-limits-to-transport
  :parent (:ssh/tests ssh/tests)
  (multiple-value-bind (client connect-call authenticate-call)
      (run-connect-with-mocks
       :connect-args '(:username "alice"
                       :rekey-byte-limit 65536
                       :rekey-seconds-limit 120))
    (true client)
    (destructuring-bind (host args) connect-call
      (is string= "myserver" host)
      (is = 65536 (getf args :rekey-byte-limit))
      (is = 120 (getf args :rekey-seconds-limit)))
    (is string= "alice" (second authenticate-call))))

(define-test connect-uses-config-rekey-limits
  :parent (:ssh/tests ssh/tests)
  (multiple-value-bind (client connect-call authenticate-call)
      (run-connect-with-mocks
       :config-content "Host myserver
    User bob
    RekeyLimit 128K 5m
")
    (declare (ignore authenticate-call))
    (true client)
    (destructuring-bind (host args) connect-call
      (is string= "myserver" host)
      (is = 131072 (getf args :rekey-byte-limit))
      (is = 300 (getf args :rekey-seconds-limit)))))

(define-test connect-keywords-override-config-rekey-limits
  :parent (:ssh/tests ssh/tests)
  (multiple-value-bind (client connect-call authenticate-call)
      (run-connect-with-mocks
       :config-content "Host myserver
    RekeyLimit 128K 5m
"
       :connect-args '(:username "alice"
                       :rekey-byte-limit 2048
                       :rekey-seconds-limit nil))
    (declare (ignore authenticate-call))
    (true client)
    (destructuring-bind (host args) connect-call
      (is string= "myserver" host)
      (is = 2048 (getf args :rekey-byte-limit))
      (true (member :rekey-seconds-limit args))
      (is eq nil (getf args :rekey-seconds-limit)))))

(define-test connect-default-rekey-keyword-overrides-config
  :parent (:ssh/tests ssh/tests)
  (multiple-value-bind (client connect-call authenticate-call)
      (run-connect-with-mocks
       :config-content "Host myserver
    RekeyLimit 128K 5m
"
       :connect-args '(:rekey-byte-limit :default
                       :rekey-seconds-limit :default))
    (declare (ignore authenticate-call))
    (true client)
    (destructuring-bind (host args) connect-call
      (is string= "myserver" host)
      (is eq :default (getf args :rekey-byte-limit))
      (is eq :default (getf args :rekey-seconds-limit)))))
