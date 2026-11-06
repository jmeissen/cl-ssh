(defpackage #:ssh/tests/resource-cleanup
  (:use #:cl #:parachute))
(in-package #:ssh/tests/resource-cleanup)

(defun call-with-functions (bindings function)
  (let ((originals (mapcar (lambda (binding)
                             (cons (car binding) (symbol-function (car binding))))
                           bindings)))
    (unwind-protect
         (progn
           (dolist (binding bindings) (setf (symbol-function (car binding)) (cdr binding)))
           (funcall function))
      (dolist (binding originals) (setf (symbol-function (car binding)) (cdr binding))))))

(defun call-with-session-fixture (operation mode assertion)
  (let* ((connection (ssh/tests/connection::make-test-connection))
         (channel (ssh/tests/connection::add-test-channel connection
                    (ssh/connection::make-channel :connection connection :local-id 3
                                                 :remote-id 7 :open-p t)))
         (other (ssh/tests/connection::add-test-channel connection
                  (ssh/connection::make-channel :connection connection :local-id 4
                                               :remote-id 8 :open-p t :remote-window 4)))
         (failure (make-condition 'simple-error :format-control "session setup failed"))
         (target (ecase operation (:exec "exec") (:env "env") (:pty "pty-req")
                   (:shell "shell") (:subsystem "subsystem")))
         (sent nil) (outcome nil))
    (unwind-protect
         (call-with-functions
          (list (cons 'ssh/connection:open-channel
                      (lambda (&rest args) (declare (ignore args)) channel))
                (cons 'ssh/connection:channel-request
                      (lambda (ch request &rest args)
                        (declare (ignore ch args))
                        (if (string= request target)
                            (ecase mode
                              (:error (error failure))
                              (:unwind (throw 'session-setup-unwind :escaped))
                              (:reject nil)
                              ((:success :exit-signal)
                               (when (eq operation :exec)
                                 (if (eq mode :exit-signal)
                                     (let ((packet (ssh/buffer:make-write-buffer)))
                                       (ssh/buffer:write-byte* packet ssh/constants:+msg-channel-request+)
                                       (ssh/buffer:write-uint32 packet 3)
                                       (ssh/buffer:write-string* packet "exit-signal")
                                       (ssh/buffer:write-byte* packet 0)
                                       (ssh/buffer:write-string* packet "TERM")
                                       (ssh/buffer:write-byte* packet 0)
                                       (ssh/buffer:write-string* packet "")
                                       (ssh/buffer:write-string* packet "")
                                       (ssh/connection::%handle-packet connection
                                        (ssh/buffer:buffer-to-octets packet)))
                                     (setf (ssh/connection:channel-exit-status channel) 42))
                                 (setf (ssh/connection:channel-close-p channel) t)
                                 (ssh/channel-buffer:buffer-accept
                                  (ssh/connection::channel-stdout-input channel)
                                  (ssh/buffer:utf-8-to-octets "out"))
                                 (ssh/channel-buffer:buffer-accept
                                  (ssh/connection::channel-stderr-input channel)
                                  (ssh/buffer:utf-8-to-octets "err")))
                               t))
                            t)))
                (cons 'ssh/transport:transport-send
                      (lambda (transport payload)
                        (declare (ignore transport))
                        (push (aref payload 0) sent)
                        (when (= (aref payload 0) ssh/constants:+msg-channel-close+)
                          (ssh/connection::%handle-packet connection
                            (ssh/tests:octets ssh/constants:+msg-channel-close+ 0 0 0 3))))))
          (lambda ()
            (setf outcome
                  (catch 'session-setup-unwind
                    (handler-case
                        (multiple-value-list
                         (ecase operation
                           (:exec (ssh/session:run-command connection "fixture"))
                           (:env (ssh/session:open-shell connection :environment '(("TEST" . "value"))))
                           (:pty (ssh/session:open-shell connection :pty t))
                           (:shell (ssh/session:open-shell connection))
                           (:subsystem (ssh/session:open-subsystem connection "fixture"))))
                      (error (condition) condition))))
            (funcall assertion outcome failure connection channel other (lambda () (reverse sent)))))
      (when (listp outcome)
        (dolist (value outcome)
          (when (streamp value) (ignore-errors (close value :abort t)))))
      (ssh/connection::%fail-connection connection "fixture cleanup"))))

(define-test invalid-transport-options-do-not-open-a-socket
  :parent (:ssh/tests ssh/tests)
  (dolist (options '((:compression :invalid) (:rekey-byte-limit 0) (:rekey-seconds-limit 0)))
    (let ((opened 0))
      (call-with-functions
       (list (cons 'usocket:socket-connect
                   (lambda (&rest args) (declare (ignore args))
                     (incf opened) (error "Socket allocation should not happen"))))
       (lambda ()
         (of-type 'ssh/transport:transport-error
           (handler-case (apply #'ssh/transport:connect-transport "fixture" options)
             (error (condition) condition)))
         (is = 0 opened))))))

(define-test transport-initialization-errors-close-the-socket
  :parent (:ssh/tests ssh/tests)
  (dolist (cleanup-fails '(nil t))
    (let ((failure (make-condition 'simple-error :format-control "stream setup failed"))
          (closed nil))
      (call-with-functions
       (list (cons 'usocket:socket-connect
                   (lambda (&rest args) (declare (ignore args)) :socket))
             (cons 'usocket:socket-stream
                   (lambda (socket) (declare (ignore socket)) (error failure)))
             (cons 'usocket:socket-close
                   (lambda (socket) (push socket closed)
                     (when cleanup-fails (error "cleanup failed")))))
       (lambda ()
         (is eq failure (handler-case (ssh/transport:connect-transport "fixture")
                          (error (condition) condition)))
         (is equal '(:socket) closed))))))

(define-test transport-handshake-unwinds-close-the-socket
  :parent (:ssh/tests ssh/tests)
  (dolist (nonlocal '(nil t))
    (let* ((failure (make-condition 'simple-error :format-control "KEX failed"))
           (input (ssh/tests/transport::make-input-stream
                   (concatenate 'string "SSH-2.0-fixture" (ssh/tests/transport::crlf))))
           (stream (make-two-way-stream input (make-broadcast-stream)))
           (closed nil))
      (unwind-protect
           (call-with-functions
            (list (cons 'usocket:socket-connect
                        (lambda (&rest args) (declare (ignore args)) :socket))
                  (cons 'usocket:socket-stream (lambda (socket) (declare (ignore socket)) stream))
                  (cons 'usocket:socket-close (lambda (socket) (push socket closed)))
                  (cons 'ssh/packet:send-packet
                        (lambda (&rest args) (declare (ignore args))
                          (if nonlocal (throw 'handshake-unwind :escaped) (error failure)))))
            (lambda ()
              (is eq (if nonlocal :escaped failure)
                  (catch 'handshake-unwind
                    (handler-case (ssh/transport:connect-transport "fixture")
                      (error (condition) condition))))
              (is equal '(:socket) closed)))
        (close stream)))))

(define-test public-connect-releases-untransferred-transports
  :parent (:ssh/tests ssh/tests)
  (dolist (stage '(:authentication-error :authentication-unwind :dispatcher-error :success))
    (let ((transport (ssh/transport::make-transport))
          (failure (make-condition 'simple-error :format-control "setup failed"))
          (disconnected nil))
      (call-with-functions
       (list (cons 'ssh/config:resolve-host
                   (lambda (&rest args) (declare (ignore args)) (ssh/config::make-ssh-config)))
             (cons 'ssh/transport:connect-transport
                   (lambda (&rest args) (declare (ignore args)) transport))
             (cons 'ssh/auth:authenticate
                   (lambda (&rest args) (declare (ignore args))
                     (case stage (:authentication-error (error failure))
                       (:authentication-unwind (throw 'authentication-unwind :escaped))
                       (otherwise t))))
             (cons 'ssh/connection:make-connection
                   (lambda (transport)
                     (when (eq stage :dispatcher-error) (error failure))
                     (ssh/connection::%make-connection :transport transport)))
             (cons 'ssh/transport:transport-disconnect
                   (lambda (transport &optional reason)
                     (declare (ignore reason)) (push transport disconnected))))
       (lambda ()
         (let ((outcome (catch 'authentication-unwind
                          (handler-case (ssh:connect "fixture" :username "fixture")
                            (error (condition) condition)))))
           (case stage
             (:success (of-type 'ssh/ssh::client outcome))
             (:authentication-unwind (is eq :escaped outcome))
             (otherwise (is eq failure outcome)))
           (is equal (unless (eq stage :success) (list transport)) disconnected)))))))

(define-test failed-channel-serialization-releases-the-registration
  :parent (:ssh/tests ssh/tests)
  (let ((connection (ssh/tests/connection::make-test-connection)))
    (of-type 'error
      (handler-case (ssh/connection:open-channel connection :type 123)
        (error (condition) condition)))
    (is = 0 (hash-table-count (ssh/connection::connection-channels connection)))))

(define-test dispatcher-construction-releases-control-sockets
  :parent (:ssh/tests ssh/tests)
  (dolist (stage '(:structure :thread))
    (let ((failure (make-condition 'simple-error :format-control "dispatcher allocation failed"))
          (original-lock (symbol-function 'bt2:make-lock))
          (closed nil))
      (call-with-functions
       (list (cons 'usocket:socket-listen
                   (lambda (&rest args) (declare (ignore args)) :listener))
             (cons 'usocket:get-local-port (lambda (socket) (declare (ignore socket)) 1234))
             (cons 'usocket:socket-connect
                   (lambda (&rest args) (declare (ignore args)) :writer))
             (cons 'usocket:socket-accept
                   (lambda (&rest args) (declare (ignore args)) :reader))
             (cons 'usocket:socket-close (lambda (socket) (push socket closed)))
             (cons 'bt2:make-lock
                   (lambda (&rest args)
                     (when (and (eq stage :structure)
                                (equal (getf args :name) "SSH channel registry"))
                       (error failure))
                     (apply original-lock args)))
             (cons 'bt2:make-thread
                   (lambda (&rest args) (declare (ignore args)) (error failure))))
       (lambda ()
         (is eq failure
             (handler-case (ssh/connection:make-connection (ssh/transport::make-transport))
               (error (condition) condition)))
         (is equal '(:listener :reader :writer) (sort closed #'string< :key #'symbol-name)))))))

(define-test sftp-session-construction-releases-its-subsystem-stream
  :parent (:ssh/tests ssh/tests)
  (let* ((stream (make-instance 'ssh/tests/sftp::mock-sftp-stream
                               :callback #'ssh/tests/sftp::file-server))
         (connection (ssh/tests/connection::make-test-connection
                      (ssh/transport::make-transport :server-version 123))))
    (call-with-functions
     (list (cons 'ssh/session:open-subsystem
                 (lambda (&rest args) (declare (ignore args)) (values stream nil))))
     (lambda ()
       (of-type 'error
         (handler-case (ssh/sftp:open-sftp-session connection)
           (error (condition) condition)))
       (true (ssh/tests/sftp::mock-done stream))
       (false (open-stream-p stream))))
    (close stream)))

(define-test failed-session-setup-closes-only-its-own-channel
  :parent (:ssh/tests ssh/tests)
  (dolist (operation '(:exec :env :pty :shell :subsystem))
    (dolist (mode (if (eq operation :env) '(:error :unwind) '(:reject :error :unwind)))
      (call-with-session-fixture operation mode
        (lambda (outcome failure connection channel other sent)
          (declare (ignore channel))
          (ecase mode
            (:reject (of-type 'ssh/connection:connection-error outcome))
            (:error (is eq failure outcome))
            (:unwind (is eq :escaped outcome)))
          (is equal (list ssh/constants:+msg-channel-close+) (funcall sent))
          (is = 1 (hash-table-count (ssh/connection::connection-channels connection)))
          (is eq other (gethash 4 (ssh/connection::connection-channels connection)))
          (ssh/connection:channel-send-data other (ssh/tests:octets 9))
          (is equal (list ssh/constants:+msg-channel-close+ ssh/constants:+msg-channel-data+)
              (funcall sent)))))))

(define-test successful-command-releases-its-private-channel-and-preserves-values
  :parent (:ssh/tests ssh/tests)
  (call-with-session-fixture :exec :success
    (lambda (outcome failure connection channel other sent)
      (declare (ignore failure channel other))
      (is equal '("out" "err" 42) outcome)
      (is equal (list ssh/constants:+msg-channel-close+) (funcall sent))
      (is = 1 (hash-table-count (ssh/connection::connection-channels connection))))))

(define-test command-terminated-by-signal-returns-nonzero-exit-status
  :parent (:ssh/tests ssh/tests)
  (call-with-session-fixture :exec :exit-signal
    (lambda (outcome failure connection channel other sent)
      (declare (ignore failure channel other))
      (is equal '("out" "err" 128) outcome)
      (is equal (list ssh/constants:+msg-channel-close+) (funcall sent))
      (is = 1 (hash-table-count (ssh/connection::connection-channels connection))))))

(define-test successful-session-setup-transfers-stream-ownership
  :parent (:ssh/tests ssh/tests)
  (dolist (operation '(:shell :pty :subsystem))
    (call-with-session-fixture operation :success
      (lambda (outcome failure connection channel other sent)
        (declare (ignore failure other))
        (is = 3 (length outcome))
        (is eq channel (second outcome))
        (true (open-stream-p (first outcome)))
        (true (open-stream-p (third outcome)))
        (false (funcall sent))
        (is = 2 (hash-table-count (ssh/connection::connection-channels connection)))
        (close (third outcome))
        (close (first outcome) :abort t)
        (is equal (list ssh/constants:+msg-channel-close+) (funcall sent))
        (is = 1 (hash-table-count (ssh/connection::connection-channels connection)))))))

(define-test transport-disconnect-closes-the-socket-even-on-nonlocal-exit
  :parent (:ssh/tests ssh/tests)
  (dolist (nonlocal '(nil t))
    (let ((transport (ssh/transport::make-transport
                      :socket :socket
                      :packet-stream (ssh/packet:make-packet-stream (make-broadcast-stream))))
          (closed nil))
      (call-with-functions
       (list (cons 'ssh/packet:send-packet
                   (lambda (&rest args) (declare (ignore args))
                     (if nonlocal (throw 'disconnect-unwind :escaped) (error "send failed"))))
             (cons 'usocket:socket-close (lambda (socket) (push socket closed))))
       (lambda ()
         (is eq (if nonlocal :escaped t)
             (catch 'disconnect-unwind (ssh/transport:transport-disconnect transport)))
         (is equal '(:socket) closed))))))

(define-test dispatcher-exits-release-the-ssh-and-control-sockets
  :parent (:ssh/tests ssh/tests)
  (dolist (nonlocal '(nil t))
    (let* ((failure (make-condition 'simple-error :format-control "wait failed"))
           (connection (ssh/connection::%make-connection
                         :transport (ssh/transport::make-transport :socket :ssh)
                         :control-reader :reader :control-writer :writer :state :running))
           (closed nil))
      (call-with-functions
       (list (cons 'usocket:wait-for-input
                   (lambda (&rest args) (declare (ignore args))
                     (if nonlocal (throw 'dispatcher-unwind :escaped) (error failure))))
             (cons 'usocket:socket-close (lambda (socket) (push socket closed))))
       (lambda ()
         (let ((outcome (catch 'dispatcher-unwind (ssh/connection::%dispatcher-loop connection))))
           (when nonlocal (is eq :escaped outcome)))
         (is eq :closed (ssh/connection::connection-state connection))
         (is equal '(:reader :ssh :writer) (sort closed #'string< :key #'symbol-name)))))))

(define-test session-cleanup-errors-do-not-replace-the-original-error
  :parent (:ssh/tests ssh/tests)
  (let ((closes 0))
    (call-with-functions
     (list (cons 'ssh/connection:channel-close
                 (lambda (&rest args) (declare (ignore args))
                   (incf closes) (error "cleanup failed"))))
     (lambda ()
       (call-with-session-fixture :exec :error
         (lambda (outcome failure connection channel other sent)
           (declare (ignore connection channel other sent))
           (is eq failure outcome)
           (is = 1 closes)))))))
