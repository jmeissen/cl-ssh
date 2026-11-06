(defpackage :ssh/tests/facade
  (:use :cl :parachute))

(in-package :ssh/tests/facade)

(defun call-with-facade-mocks (function &key fail-at directory missing-target)
  (let ((events nil)
        ;; Mock cross-file calls: ECL can compile calls within ssh.lisp directly.
        ;; A real client lets the facade wrappers reach the connection sentinel.
        (symbols '(ssh:connect ssh/connection:connection-close ssh/sftp:open-sftp-session ssh:close-sftp
                   ssh/session:run-command ssh:sftp-upload ssh:sftp-download ssh:sftp-stat)))
    (let ((originals (mapcar #'symbol-function symbols)))
      (labels ((record (kind &rest args)
                 (push (cons kind args) events)
                 (when (eq kind fail-at) (error "Mock failure at ~A" kind))))
        (unwind-protect
             (progn
               (setf (symbol-function 'ssh:connect)
                     (lambda (host &rest args) (record :connect host args)
                       (ssh::%make-client :connection :client))
                     (symbol-function 'ssh/connection:connection-close)
                     (lambda (client &rest args) (record :disconnect client args) t)
                     (symbol-function 'ssh/sftp:open-sftp-session)
                     (lambda (client &rest args) (record :open client args) :session)
                     (symbol-function 'ssh:close-sftp)
                     (lambda (session &rest args) (record :close session args) t)
                     (symbol-function 'ssh/session:run-command)
                     (lambda (client command &rest args)
                       (record :command client command args)
                       (values "stdout" "stderr" 7))
                     (symbol-function 'ssh:sftp-upload)
                     (lambda (session local remote &rest args)
                       (record :upload session local remote args)
                       (values remote 42))
                     (symbol-function 'ssh:sftp-download)
                     (lambda (session remote local &rest args)
                       (record :download session remote local args)
                       (values (pathname local) 42))
                     (symbol-function 'ssh:sftp-stat)
                     (lambda (session path)
                       (record :stat session path)
                       (when missing-target
                         (error 'ssh:sftp-status-error :code 2 :message "Missing"))
                       (ssh:make-sftp-attributes
                        :permissions (if directory #o040755 #o100644))))
               (let ((result (multiple-value-list (funcall function))))
                 (values result (reverse events))))
          (loop for symbol in symbols for original in originals
                do (setf (symbol-function symbol) original)))))))

(defun call-with-sftp-facade-fixture (function data &key fail-write)
  (let* ((server (ssh/tests/sftp-stream::transfer-server data))
         (writes nil) (session nil) (disconnected nil)
         (stream
           (make-instance 'ssh/tests/sftp::mock-sftp-stream
             :callback
             (lambda (stream type buffer)
               (if (= type 6)
                   (let ((id (ssh/buffer:read-uint32 buffer)))
                     (ssh/buffer:read-string* buffer)
                     (let ((offset (ssh/buffer:read-uint64 buffer))
                           (bytes (ssh/buffer:read-string* buffer)))
                       (push (list offset bytes) writes))
                     (ssh/tests/sftp::status-reply stream id (if fail-write 4 0)))
                   (funcall server stream type buffer)))))
         (symbols '(ssh:connect ssh/sftp:open-sftp-session ssh/connection:connection-close))
         (originals (mapcar #'symbol-function symbols)))
    (unwind-protect
         (progn
           (setf (symbol-function 'ssh:connect)
                 (lambda (&rest args) (declare (ignore args))
                   (ssh::%make-client :connection :client))
                 (symbol-function 'ssh/sftp:open-sftp-session)
                 (lambda (&rest args)
                   (declare (ignore args))
                   (setf session (ssh/sftp::%start-session stream :block-size 2 :max-pending 3)))
                 (symbol-function 'ssh/connection:connection-close)
                 (lambda (&rest args) (declare (ignore args)) (setf disconnected t)))
           (let ((result (multiple-value-list (funcall function))))
             (values result
                     (apply #'concatenate '(vector (unsigned-byte 8))
                            (mapcar #'second (sort writes #'< :key #'first)))
                     disconnected
                     (not (open-stream-p stream))
                     (when session (hash-table-count (ssh/sftp::sftp-session-handles session))))))
      (loop for symbol in symbols for original in originals
            do (setf (symbol-function symbol) original))
      (when session (ignore-errors (ssh:close-sftp session :abort t))))))

(define-test scp-endpoint-parsing
  :parent (:ssh/tests ssh/tests)
  ;; The five SCP-style cases in OpenSSH regress/unittests/misc/test_parse.c.
  (dolist (case '(("someuser@some.host:some/path" "some.host" "someuser" nil "some/path" t)
                  ("someuser@1.22.33.144:some/path" "1.22.33.144" "someuser" nil "some/path" t)
                  ("someuser@[1.22.33.144]:some/path" "1.22.33.144" "someuser" nil "some/path" t)
                  ("someuser@[1.22.33.144]:" "1.22.33.144" "someuser" nil "." t)
                  ("someuser@[::1]:some/path" "::1" "someuser" nil "some/path" t)
                  ("host:/absolute/path" "host" nil nil "/absolute/path" t)
                  ("host:2222/path" "host" nil nil "2222/path" t)
                  ("host:a:b?c#d" "host" nil nil "a:b?c#d" t)
                  ("host:a%20b+c" "host" nil nil "a%20b+c" t)
                  ("alice@realm@host:file" "host" "alice@realm" nil "file" t)
                  ("scp://alice@host:2222/file" "host" "alice" 2222 "file" t)
                  ("scp://alice@[::1]:2222//absolute/file" "::1" "alice" 2222 "/absolute/file" t)
                  ("scp://alice%40realm@host/a%20b%2Bc" "host" "alice@realm" nil "a b+c" t)
                  ("scp://host" "host" nil nil "." t)
                  ("scp://host/" "host" nil nil "." t)
                  ("scp://host//" "host" nil nil "/" t)
                  ("file" nil nil nil "file" nil)
                  ("./a:b" nil nil nil "./a:b" nil)
                  ("/tmp/a:b" nil nil nil "/tmp/a:b" nil)
                  (":file" nil nil nil ":file" nil)
                  ("dir/user@host:file" nil nil nil "dir/user@host:file" nil)))
    (is equal (rest case) (multiple-value-list (ssh::parse-scp-endpoint (first case)))))
  (let ((path #P"host:file"))
    (is equal (list nil nil nil path nil)
        (multiple-value-list (ssh::parse-scp-endpoint path)))))

(define-test scp-propagates-download-errors-and-rejects-remote-directories
  :parent (:ssh/tests ssh/tests)
  (dolist (stage '(:stat :download))
    (multiple-value-bind (result events)
        (call-with-facade-mocks
         (lambda () (handler-case (ssh:scp "host:file" "local.bin")
                      (error (condition) (princ-to-string condition))))
         :fail-at stage)
      (true (search (symbol-name stage) (first result)))
      (is equal '(:abort t) (third (assoc :close events)))
      (is eq :disconnect (first (car (last events))))))
  (multiple-value-bind (result events)
      (call-with-facade-mocks
       (lambda () (handler-case (ssh:scp "host:directory" "local.bin")
                    (error () :directory-rejected)))
       :directory t)
    (is equal '(:directory-rejected) result)
    (false (assoc :download events))))

(define-test scp-real-transfer-failure-and-overwrite-policy
  :parent (:ssh/tests ssh/tests)
  (uiop:with-temporary-file (:pathname local :stream output :direction :output
                             :element-type '(unsigned-byte 8))
    (write-byte 9 output) (finish-output output)
    (multiple-value-bind (result bytes disconnected closed handles)
        (call-with-sftp-facade-fixture
         (lambda () (handler-case (ssh:scp local "host:remote.bin")
                      (ssh:sftp-status-error () :write-failed)))
         (ssh/tests:octets) :fail-write t)
      (declare (ignore bytes))
      (is equal '(:write-failed) result)
      (true disconnected) (true closed) (is = 0 handles)))
  (uiop:with-temporary-file (:pathname local :stream output :direction :output
                             :element-type '(unsigned-byte 8))
    (write-byte 9 output) (finish-output output)
    (multiple-value-bind (result bytes disconnected closed handles)
        (call-with-sftp-facade-fixture
         (lambda () (handler-case (ssh:scp "host:remote.bin" local :if-exists :error)
                      (file-error () :already-exists)))
         (ssh/tests:octets 1 2 3))
      (declare (ignore bytes))
      (is equal '(:already-exists) result)
      (with-open-file (input local :element-type '(unsigned-byte 8))
        (is = 1 (file-length input)) (is = 9 (read-byte input)))
      (true disconnected) (true closed) (is = 0 handles))))

(define-test scp-transfers-real-sftp-bytes-and-closes
  :parent (:ssh/tests ssh/tests)
  (uiop:with-temporary-file (:pathname local :stream output :direction :output
                             :element-type '(unsigned-byte 8))
    (write-sequence (ssh/tests:octets 9 8 7 6 5) output)
    (finish-output output)
    (multiple-value-bind (result bytes disconnected closed handles)
        (call-with-sftp-facade-fixture (lambda () (ssh:scp local "host:remote.bin"))
                                      (ssh/tests:octets))
      (is equal '("remote.bin" 5) result)
      (is equalp (ssh/tests:octets 9 8 7 6 5) bytes)
      (true disconnected) (true closed) (is = 0 handles)))
  (uiop:with-temporary-file (:pathname local)
    (multiple-value-bind (result bytes disconnected closed handles)
        (call-with-sftp-facade-fixture (lambda () (ssh:scp "host:remote.bin" local))
                                      (ssh/tests:octets 1 2 3 4 5))
      (declare (ignore bytes))
      (is equal (list local 5) result)
      (with-open-file (input local :element-type '(unsigned-byte 8))
        (let ((data (make-array 5 :element-type '(unsigned-byte 8))))
          (is = 5 (read-sequence data input))
          (is equalp (ssh/tests:octets 1 2 3 4 5) data)))
      (true disconnected) (true closed) (is = 0 handles))))

(define-test scp-rejects-unsupported-directions-before-connecting
  :parent (:ssh/tests ssh/tests)
  (dolist (pair '(("local" "other") ("host:file" "other:file")
                  ("local" "scp://host:0/file")))
    (multiple-value-bind (result events)
        (call-with-facade-mocks
         (lambda () (handler-case (apply #'ssh:scp pair) (error () :rejected))))
      (is equal '(:rejected) result)
      (false events)))
  (multiple-value-bind (result events)
      (call-with-facade-mocks
       (lambda () (handler-case (ssh:scp (uiop:temporary-directory) "host:dir")
                    (error () :rejected))))
    (is equal '(:rejected) result)
    (false events)))

(define-test scp-directory-targets-and-missing-files
  :parent (:ssh/tests ssh/tests)
  (multiple-value-bind (result events)
      (call-with-facade-mocks (lambda () (ssh:scp "/local/report.bin" "host:/remote"))
                             :directory t)
    (declare (ignore events))
    (is equal '("/remote/report.bin" 42) result))
  (multiple-value-bind (result events)
      (call-with-facade-mocks (lambda () (ssh:scp "local.bin" "host:new.bin"))
                             :missing-target t)
    (declare (ignore events))
    (is equal '("new.bin" 42) result))
  (multiple-value-bind (result events)
      (call-with-facade-mocks
       (lambda () (handler-case (ssh:scp "local.bin" "host:missing/")
                    (error () :rejected)))
       :missing-target t)
    (is equal '(:rejected) result)
    (false (assoc :upload events)))
  (multiple-value-bind (result events)
      (call-with-facade-mocks (lambda () (ssh:scp "host:/remote/report.bin" (uiop:temporary-directory))))
    (declare (ignore events))
    (is equal (merge-pathnames #P"report.bin" (uiop:temporary-directory)) (first result))))

(define-test scp-routes-upload-and-download
  :parent (:ssh/tests ssh/tests)
  (multiple-value-bind (result events)
      (call-with-facade-mocks
       (lambda () (ssh:scp "local.bin" "scp://uri-user@[::1]:2222//remote.bin"
                          :username "explicit" :port 2223 :identity #P"key"
                          :if-exists :error)))
    (is equal '("/remote.bin" 42) result)
    (is equal '(:connect :open :stat :upload :close :disconnect) (mapcar #'first events))
    (is string= "::1" (second (first events)))
    (is equal '(:identity #P"key" :username "explicit" :port 2223)
        (third (first events)))
    (is equal '(:upload :session "local.bin" "/remote.bin"
                (:if-exists :error :progress-function nil)) (assoc :upload events)))
  (multiple-value-bind (result events)
      (call-with-facade-mocks (lambda () (ssh:scp "alice@host:/report.bin" #P"copy.bin")))
    (is equal '(#P"copy.bin" 42) result)
    (is equal '(:connect :open :stat :download :close :disconnect) (mapcar #'first events))
    (is equal '(:username "alice" :port nil) (third (first events)))
    (is equal '(:download :session "/report.bin" #P"copy.bin"
                (:if-exists :supersede :progress-function nil)) (assoc :download events))))

(define-test facade-cleanup-on-failure
  :parent (:ssh/tests ssh/tests)
  (dolist (stage '(:connect :command :disconnect))
    (multiple-value-bind (result events)
        (call-with-facade-mocks
         (lambda () (handler-case (ssh:cmd "host" "false")
                      (error (condition) (princ-to-string condition))))
         :fail-at stage)
      (if (eq stage :disconnect)
          (is equal '("stdout" "stderr" 7) result)
          (true (search (symbol-name stage) (first result))))
      (is equal (if (eq stage :connect) '(:connect) '(:connect :command :disconnect))
          (mapcar #'first events))))
  (dolist (stage '(:open :upload :close))
    (multiple-value-bind (result events)
        (call-with-facade-mocks
         (lambda () (handler-case (ssh:scp "local.bin" "host:file")
                      (error (condition) (princ-to-string condition))))
         :fail-at stage)
      (true (search (symbol-name stage) (first result)))
      (is eq :disconnect (first (car (last events))))
      (let ((close (assoc :close events)))
        (if (eq stage :open)
            (false close)
            (is equal (if (eq stage :upload) '(:abort t) nil) (third close)))))))

(define-test cmd-forwards-options-results-and-command
  :parent (:ssh/tests ssh/tests)
  (multiple-value-bind (result events)
      (call-with-facade-mocks
       (lambda () (ssh:cmd "ssh://alice@host:2222" "printf '%s' '$HOME'"
                        :identity #P"key" :environment '(("LANG" . "C")))))
    (is equal '("stdout" "stderr" 7) result)
    (is equal '(:connect :command :disconnect) (mapcar #'first events))
    (is string= "ssh://alice@host:2222" (second (first events)))
    (is equal '(:identity #P"key") (third (first events)))
    (is string= "printf '%s' '$HOME'" (third (second events)))
    (is equal '(:environment (("LANG" . "C"))) (fourth (second events)))))

(define-test scp-endpoint-invalid
  :parent (:ssh/tests ssh/tests)
  (dolist (input '("" "scp://" "scp://@host/file" "scp://host:0/file"
                   "scp://host:65536/file" "scp://[::1/file"
                   "scp://host/a%00b" "scp://host/a%GG"
                   "scp://host/file?query" "scp://host/file#fragment"
                   "ssh://host/file" "sftp://host/file" "@host:file"
                   "user@:file" "user@[::1]junk:file"))
    (fail (ssh::parse-scp-endpoint input))))
