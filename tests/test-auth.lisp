;;;; Tests for ssh/auth keyboard-interactive authentication (RFC 4256).

(defpackage :ssh/tests/auth
  (:use :cl :parachute)
  (:import-from :ssh
                #:make-keyboard-interactive-cli-callback)
  (:import-from :ssh/auth
                #:authenticate
                #:auth-error)
  (:import-from :ssh/buffer
                #:make-write-buffer
                #:make-read-buffer
                #:write-byte*
                #:write-boolean
                #:write-uint32
                #:write-string*
                #:read-byte*
                #:read-uint32
                #:read-string*
                #:read-boolean
                #:buffer-to-octets
                #:utf-8-to-octets)
  (:import-from :ssh/constants
                #:+msg-userauth-request+
                #:+msg-userauth-success+
                #:+msg-userauth-failure+
                #:+msg-userauth-banner+
                #:+msg-userauth-info-response+
                #:+service-connection+
                #:+auth-keyboard-interactive+))

(in-package :ssh/tests/auth)

(defun octets->string (octets)
  (map 'string #'code-char octets))

(defun build-userauth-success ()
  (ssh/tests:octets +msg-userauth-success+))

(defun build-userauth-failure (&key (methods '("password" "publickey")) (partial nil))
  (let ((buf (make-write-buffer)))
    (write-byte* buf +msg-userauth-failure+)
    (write-string* buf (format nil "~{~A~^,~}" methods))
    (write-boolean buf partial)
    (buffer-to-octets buf)))

(defun build-userauth-banner (text &optional (language-tag ""))
  (let ((buf (make-write-buffer)))
    (write-byte* buf +msg-userauth-banner+)
    (write-string* buf text)
    (write-string* buf language-tag)
    (buffer-to-octets buf)))

(defun build-info-request (&key (name "") (instruction "") (language-tag "") (prompts '()))
  (let ((buf (make-write-buffer)))
    (write-byte* buf ssh/constants:+msg-userauth-info-request+)
    (write-string* buf (utf-8-to-octets name))
    (write-string* buf (utf-8-to-octets instruction))
    (write-string* buf (utf-8-to-octets language-tag))
    (write-uint32 buf (length prompts))
    (dolist (prompt prompts)
      (write-string* buf (utf-8-to-octets (car prompt)))
      (write-boolean buf (cdr prompt)))
    (buffer-to-octets buf)))

(defun decode-initial-keyboard-interactive-request (payload)
  (let ((buf (make-read-buffer payload)))
    (values
     (read-byte* buf)
     (octets->string (read-string* buf))
     (octets->string (read-string* buf))
     (octets->string (read-string* buf))
     (octets->string (read-string* buf))
     (octets->string (read-string* buf)))))

(defun decode-info-response (payload)
  (let ((buf (make-read-buffer payload)))
    (let ((message-type (read-byte* buf))
          (count (read-uint32 buf))
          (responses '()))
      (loop repeat count
            do (push (read-string* buf) responses))
      (values message-type (nreverse responses)))))

(defun run-with-mocked-auth-io (incoming thunk)
  (let* ((queue (copy-list incoming))
         (sent '())
         (transport (ssh/transport::make-transport))
         (original-send (symbol-function 'ssh/transport:transport-send))
         (original-recv (symbol-function 'ssh/transport:transport-recv)))
    (unwind-protect
         (progn
           (setf (symbol-function 'ssh/transport:transport-send)
                 (lambda (_transport payload)
                   (declare (ignore _transport))
                   (push payload sent)
                   nil))
           (setf (symbol-function 'ssh/transport:transport-recv)
                 (lambda (_transport)
                   (declare (ignore _transport))
                   (if queue
                       (pop queue)
                       (error "test transport underflow"))))
           (values (funcall thunk transport) (nreverse sent)))
      (setf (symbol-function 'ssh/transport:transport-send) original-send
            (symbol-function 'ssh/transport:transport-recv) original-recv))))

(define-test keyboard-interactive-initial-request-encoding
  :parent (:ssh/tests ssh/tests)
  (multiple-value-bind (result sent)
      (run-with-mocked-auth-io
       (list (build-userauth-success))
       (lambda (transport)
         (ssh/auth::try-keyboard-interactive transport
                                             "alice"
                                             (lambda (&rest _) (declare (ignore _)) '())
                                             :submethods '("otp" "sms"))))
    (true result)
    (is = 1 (length sent))
    (multiple-value-bind (message-type username service method language-tag submethods)
        (decode-initial-keyboard-interactive-request (first sent))
      (is = +msg-userauth-request+ message-type)
      (is string= "alice" username)
      (is string= +service-connection+ service)
      (is string= +auth-keyboard-interactive+ method)
      (is string= "" language-tag)
      (is string= "otp,sms" submethods))))

(define-test keyboard-interactive-parse-info-request
  :parent (:ssh/tests ssh/tests)
  (let ((payload (build-info-request
                  :name "Keyboard"
                  :instruction "Enter code"
                  :language-tag "en-US"
                  :prompts '(("Code: " . nil) ("Echo: " . t)))))
    (multiple-value-bind (name instruction language-tag prompts)
        (ssh/auth::parse-keyboard-interactive-info-request payload)
      (is string= "Keyboard" name)
      (is string= "Enter code" instruction)
      (is string= "en-US" language-tag)
      (is equal '((:prompt "Code: " :echo nil)
                  (:prompt "Echo: " :echo t))
          prompts))))

(define-test keyboard-interactive-parse-info-request-utf8
  :parent (:ssh/tests ssh/tests)
  (let ((payload (build-info-request
                  :name "Kéyboard"
                  :instruction "Enter värde"
                  :language-tag "sv-SE"
                  :prompts '(("Lösenord: " . nil) ("Kod 値: " . t)))))
    (multiple-value-bind (name instruction language-tag prompts)
        (ssh/auth::parse-keyboard-interactive-info-request payload)
      (is string= "Kéyboard" name)
      (is string= "Enter värde" instruction)
      (is string= "sv-SE" language-tag)
      (is equal '((:prompt "Lösenord: " :echo nil)
                  (:prompt "Kod 値: " :echo t))
          prompts))))

(define-test keyboard-interactive-encode-info-response-zero-and-utf8
  :parent (:ssh/tests ssh/tests)
  (multiple-value-bind (message-type responses)
      (decode-info-response (ssh/auth::encode-keyboard-interactive-info-response '()))
    (is = +msg-userauth-info-response+ message-type)
    (is = 0 (length responses)))
  (multiple-value-bind (message-type responses)
      (decode-info-response
       (ssh/auth::encode-keyboard-interactive-info-response '("päss" "値")))
    (is = +msg-userauth-info-response+ message-type)
    (is equalp (utf-8-to-octets "päss") (first responses))
    (is equalp (utf-8-to-octets "値") (second responses))))

(define-test keyboard-interactive-single-round-success
  :parent (:ssh/tests ssh/tests)
  (multiple-value-bind (result sent)
      (run-with-mocked-auth-io
       (list (build-info-request :prompts '(("Password: " . nil)))
             (build-userauth-success))
       (lambda (transport)
         (ssh/auth::try-keyboard-interactive transport
                                             "alice"
                                             (lambda (name instruction language-tag prompts)
                                               (declare (ignore name instruction language-tag prompts))
                                               '("päss")))))
    (true result)
    (is = 2 (length sent))
    (multiple-value-bind (message-type responses)
        (decode-info-response (second sent))
      (is = +msg-userauth-info-response+ message-type)
      (is = 1 (length responses))
      (is equalp (utf-8-to-octets "päss") (first responses)))))

(define-test keyboard-interactive-multi-round-success
  :parent (:ssh/tests ssh/tests)
  (multiple-value-bind (result sent)
      (run-with-mocked-auth-io
       (list (build-info-request
              :instruction "first"
              :prompts '(("First prompt" . nil)))
             (build-info-request
              :instruction "second"
              :prompts '(("Second prompt" . nil)
                         ("Third prompt" . t)))
             (build-userauth-success))
       (lambda (transport)
         (ssh/auth::try-keyboard-interactive
          transport
          "alice"
          (lambda (_name instruction _language-tag _prompts)
            (declare (ignore _name _language-tag _prompts))
            (if (string= instruction "first")
                '("one")
                '("two" "three"))))))
    (true result)
    (is = 3 (length sent))
    (multiple-value-bind (_type responses)
        (decode-info-response (second sent))
      (declare (ignore _type))
      (is equalp (list (utf-8-to-octets "one")) responses))
    (multiple-value-bind (_type responses)
        (decode-info-response (third sent))
      (declare (ignore _type))
      (is equalp (list (utf-8-to-octets "two")
                       (utf-8-to-octets "three"))
          responses))))

(define-test keyboard-interactive-zero-prompt-request
  :parent (:ssh/tests ssh/tests)
  (let ((calls 0))
    (multiple-value-bind (result sent)
        (run-with-mocked-auth-io
         (list (build-info-request :prompts '())
               (build-userauth-success))
         (lambda (transport)
           (ssh/auth::try-keyboard-interactive
            transport
            "alice"
            (lambda (_name _instruction _language-tag prompts)
              (declare (ignore _name _instruction _language-tag))
              (incf calls)
              (true (null prompts))
              '()))))
      (true result)
      (is = 1 calls)
      (multiple-value-bind (_type responses)
          (decode-info-response (second sent))
        (declare (ignore _type))
        (is = 0 (length responses))))))

(define-test keyboard-interactive-callback-wrong-response-count
  :parent (:ssh/tests ssh/tests)
  (of-type 'auth-error
    (handler-case
        (run-with-mocked-auth-io
         (list (build-info-request :prompts '(("Prompt" . nil))))
         (lambda (transport)
           (ssh/auth::try-keyboard-interactive
            transport
            "alice"
            (lambda (&rest _) (declare (ignore _)) '()))))
      (auth-error (c) c))))

(define-test keyboard-interactive-callback-non-string-response
  :parent (:ssh/tests ssh/tests)
  (of-type 'auth-error
    (handler-case
        (run-with-mocked-auth-io
         (list (build-info-request :prompts '(("Prompt" . nil))))
         (lambda (transport)
           (ssh/auth::try-keyboard-interactive
            transport
            "alice"
            (lambda (&rest _) (declare (ignore _)) '(123)))))
      (auth-error (c) c))))

(define-test keyboard-interactive-cli-helper-displays-prompts-and-reads-responses
  :parent (:ssh/tests ssh/tests)
  (let* ((input (make-string-input-stream (format nil "first~%second~%")))
         (output (make-string-output-stream))
         (callback (make-keyboard-interactive-cli-callback
                    :input input
                    :output output)))
    (is equal '("first" "second")
        (funcall callback
                 "Challenge"
                 "Enter the codes"
                 "en"
                 '((:prompt "Password:" :echo nil)
                   (:prompt "OTP:" :echo t))))
    (is string=
        (format nil "Challenge~%Enter the codes~%Password: [hidden] OTP: ")
        (get-output-stream-string output))))

(define-test keyboard-interactive-cli-helper-preserves-response-order
  :parent (:ssh/tests ssh/tests)
  (let* ((input (make-string-input-stream (format nil "one~%two~%three~%")))
         (output (make-string-output-stream))
         (callback (make-keyboard-interactive-cli-callback
                    :input input
                    :output output)))
    (is equal '("one" "two" "three")
        (funcall callback
                 ""
                 ""
                 ""
                 '((:prompt "First" :echo t)
                   (:prompt "Second" :echo nil)
                   (:prompt "Third" :echo t))))))

(define-test keyboard-interactive-cli-helper-allows-empty-responses
  :parent (:ssh/tests ssh/tests)
  (let* ((input (make-string-input-stream (format nil "~%")))
         (output (make-string-output-stream))
         (callback (make-keyboard-interactive-cli-callback
                    :input input
                    :output output)))
    (is equal '("")
        (funcall callback
                 ""
                 ""
                 ""
                 '((:prompt "Password:" :echo nil))))))

(define-test keyboard-interactive-cli-helper-uses-echo-aware-readers
  :parent (:ssh/tests ssh/tests)
  (let ((calls '())
        (output (make-string-output-stream))
        (callback nil))
    (flet ((visible-reader (stream)
             (declare (ignore stream))
             (push :visible calls)
             "visible")
           (hidden-reader (stream)
             (declare (ignore stream))
             (push :hidden calls)
             "hidden"))
      (setf callback
            (make-keyboard-interactive-cli-callback
             :input (make-string-input-stream "")
             :output output
             :reader #'visible-reader
             :no-echo-reader #'hidden-reader))
      (is equal '("visible" "hidden")
          (funcall callback
                   ""
                   ""
                   ""
                   '((:prompt "Visible:" :echo t)
                     (:prompt "Secret:" :echo nil))))
      (is equal '(:hidden :visible)
          calls))))

(define-test keyboard-interactive-failure-and-unexpected-message
  :parent (:ssh/tests ssh/tests)
  (of-type 'auth-error
    (handler-case
        (run-with-mocked-auth-io
         (list (build-userauth-failure :methods '("password") :partial nil))
         (lambda (transport)
           (ssh/auth::try-keyboard-interactive
            transport
            "alice"
            (lambda (&rest _) (declare (ignore _)) '()))))
      (auth-error (c) c)))
  (of-type 'auth-error
    (handler-case
        (run-with-mocked-auth-io
         (list (ssh/tests:octets 99))
         (lambda (transport)
           (ssh/auth::try-keyboard-interactive
            transport
            "alice"
            (lambda (&rest _) (declare (ignore _)) '()))))
      (auth-error (c) c))))

(define-test password-partial-success-continues-with-keyboard-interactive
  :parent (:ssh/tests ssh/tests)
  (let ((captured-condition nil))
    (multiple-value-bind (result sent)
        (run-with-mocked-auth-io
         (list (build-userauth-failure :methods '("keyboard-interactive") :partial t)
               (build-info-request :prompts '(("OTP" . nil)))
               (build-userauth-success))
         (lambda (transport)
           (handler-bind ((ssh/auth:auth-partial-success
                           (lambda (c)
                             (setf captured-condition c)
                             (invoke-restart 'ssh/auth::continue-authentication
                                             "keyboard-interactive"
                                             (lambda (name instruction language-tag prompts)
                                               (declare (ignore name instruction language-tag))
                                               (is equal '((:prompt "OTP" :echo nil)) prompts)
                                               '("000000"))))))
             (authenticate transport "alice" :password "secret"))))
      (true result)
      (is string= "password" (ssh/auth:auth-partial-success-attempted-method captured-condition))
      (is equal '("keyboard-interactive") (ssh/auth:auth-partial-success-allowed-methods captured-condition))
      (true (ssh/auth:auth-partial-success-partial-success-p captured-condition))
      (is = 3 (length sent))
      (multiple-value-bind (message-type username service method language-tag submethods)
          (decode-initial-keyboard-interactive-request (second sent))
        (declare (ignore username service language-tag))
        (is = +msg-userauth-request+ message-type)
        (is string= +auth-keyboard-interactive+ method)
        (is string= "" submethods))
      (multiple-value-bind (message-type responses)
          (decode-info-response (third sent))
        (is = +msg-userauth-info-response+ message-type)
        (is = 1 (length responses))
        (is equalp (utf-8-to-octets "000000") (first responses))))))

(define-test partial-success-rejects-disallowed-method
  :parent (:ssh/tests ssh/tests)
  (of-type 'auth-error
    (handler-case
        (run-with-mocked-auth-io
         (list (build-userauth-failure :methods '("keyboard-interactive") :partial t))
         (lambda (transport)
           (handler-bind ((ssh/auth:auth-partial-success
                           (lambda (c)
                             (declare (ignore c))
                             (invoke-restart 'ssh/auth::continue-authentication
                                             "password"
                                             "secret"))))
             (authenticate transport "alice" :password "secret"))))
      (auth-error (c) c))))

(define-test keyboard-interactive-skips-banner-before-info-request
  :parent (:ssh/tests ssh/tests)
  (let* ((banner (concatenate 'string
                              "Welcome"
                              (string (code-char 27))
                              "[2J"
                              (string (code-char 7))
                              (string (code-char 9))
                              "OK"
                              (string (code-char 10))))
         (stdout nil))
    (setf stdout
          (with-output-to-string (*standard-output*)
            (multiple-value-bind (result sent)
                (run-with-mocked-auth-io
                 (list (build-userauth-banner banner)
                       (build-info-request :prompts '(("OTP" . nil)))
                       (build-userauth-success))
                 (lambda (transport)
                   (ssh/auth::try-keyboard-interactive
                    transport
                    "alice"
                    (lambda (&rest _) (declare (ignore _)) '("000000")))))
              (true result)
              (is = 2 (length sent))
              (multiple-value-bind (message-type responses)
                  (decode-info-response (second sent))
                (is = +msg-userauth-info-response+ message-type)
                (is equalp (utf-8-to-octets "000000") (first responses))))))
    (is string=
        (concatenate 'string "Welcome^[[2J^G" (string #\Tab) "OK" (string #\Newline))
        stdout)))
(define-test authenticate-supports-keyboard-interactive-callback
  :parent (:ssh/tests ssh/tests)
  (multiple-value-bind (result sent)
      (run-with-mocked-auth-io
       (list (build-userauth-success))
       (lambda (transport)
         (authenticate transport
                       "alice"
                       :keyboard-interactive-callback
                       (lambda (&rest _) (declare (ignore _)) '())
                       :keyboard-interactive-submethods "otp")))
    (true result)
    (multiple-value-bind (_message-type _username _service method _language-tag submethods)
        (decode-initial-keyboard-interactive-request (first sent))
      (declare (ignore _message-type _username _service _language-tag))
      (is string= +auth-keyboard-interactive+ method)
      (is string= "otp" submethods))))
