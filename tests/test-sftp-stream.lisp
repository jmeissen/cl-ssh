(defpackage #:ssh/tests/sftp-stream
  (:use #:cl #:parachute #:ssh/sftp #:ssh/sftp/codec #:ssh/sftp/stream)
  (:import-from #:ssh/tests #:octets)
  (:import-from #:ssh/tests/sftp #:mock-sftp-stream #:file-server #:mock-sent #:status-reply))
(in-package #:ssh/tests/sftp-stream)

(defun transfer-server (data &key reverse-first-batch fail-write)
  (let ((initial-reads nil) (reversed nil))
    (labels ((answer-read (stream id offset requested)
               (if (>= offset (length data))
                   (status-reply stream id 1)
                   (ssh/tests/sftp::reply stream 103 id
                     (lambda (b)
                       ;; Short reads deliberately require the client to fill gaps.
                       (ssh/buffer:write-string* b (subseq data offset
                         (min (length data) (+ offset (min 2 requested))))))))))
      (lambda (stream type buffer)
        (case type
          (8 (ssh/tests/sftp::reply stream 105 (ssh/buffer:read-uint32 buffer)
               (lambda (b) (ssh/sftp/codec::encode-attributes b
                 (make-sftp-attributes :size (length data) :permissions #o100600)))))
          (5 (let ((id (ssh/buffer:read-uint32 buffer)))
               (ssh/buffer:read-string* buffer)
               (let ((offset (ssh/buffer:read-uint64 buffer))
                     (requested (ssh/buffer:read-uint32 buffer)))
                 (if (and reverse-first-batch (not reversed))
                     (progn
                       (push (list id offset requested) initial-reads)
                       (when (= 3 (length initial-reads))
                         (setf reversed t)
                         (dolist (read initial-reads) (apply #'answer-read stream read))))
                     (answer-read stream id offset requested)))))
          (6 (status-reply stream (ssh/buffer:read-uint32 buffer) (if fail-write 4 0)))
          (otherwise (file-server stream type buffer)))))))

(define-test sftp-download-reorders-eof-and-fills-short-read-gaps :parent (:ssh/tests ssh/tests)
  (let* ((data (octets 1 2 3 4 5))
         (transport (make-instance 'mock-sftp-stream :callback
                       (transfer-server data :reverse-first-batch t)))
         (session (ssh/sftp::%start-session transport :block-size 4 :max-pending 3))
         (progress nil) (caller (bt2:current-thread)))
    (unwind-protect
         (uiop:with-temporary-file (:pathname destination)
           (is = 5 (nth-value 1 (sftp-download session "file" destination :if-exists :supersede
             :progress-function (lambda (count total)
               (is eq caller (bt2:current-thread))
               (is = 5 total)
               ;; The callback must not run under the session's state mutex.
               (bt2:with-lock-held ((ssh/sftp::sftp-session-lock session)) (push count progress))))))
           (is equal '(0 2 4 5) (reverse progress))
           (with-open-file (input destination :element-type '(unsigned-byte 8))
             (let ((copy (make-array 5 :element-type '(unsigned-byte 8))))
               (is = 5 (read-sequence copy input)) (is equalp data copy)))
           (is = 0 (hash-table-count (ssh/sftp::sftp-session-pending session)))
           (is = 0 (hash-table-count (ssh/sftp::sftp-session-handles session))))
      (close-sftp session))))

(define-test sftp-download-callback-failure-retains-partial-file :parent (:ssh/tests ssh/tests)
  (let* ((transport (make-instance 'mock-sftp-stream :callback
                       (transfer-server (octets 1 2 3 4 5) :reverse-first-batch t)))
         (session (ssh/sftp::%start-session transport :block-size 4 :max-pending 3)))
    (unwind-protect
         (uiop:with-temporary-file (:pathname destination)
           (fail (sftp-download session "file" destination :if-exists :supersede
                  :progress-function (lambda (count total) (declare (ignore total))
                                       (when (plusp count) (error "Cancel transfer")))))
           (with-open-file (input destination :element-type '(unsigned-byte 8))
             (is = 2 (file-length input)) (is = 1 (read-byte input)) (is = 2 (read-byte input)))
           (is = 0 (hash-table-count (ssh/sftp::sftp-session-pending session)))
           (is = 0 (hash-table-count (ssh/sftp::sftp-session-handles session)))
           (true (sftp-stat session "still usable")))
      (close-sftp session))))

(define-test sftp-upload-error-and-fsync-preflight :parent (:ssh/tests ssh/tests)
  (let* ((transport (make-instance 'mock-sftp-stream :callback
                       (transfer-server (octets) :fail-write t)))
         (session (ssh/sftp::%start-session transport :block-size 2 :max-pending 3))
         (progress nil))
    (unwind-protect
         (uiop:with-temporary-file (:pathname source-path :stream source :direction :output
                                   :element-type '(unsigned-byte 8))
           (write-sequence (octets 1 2 3 4 5) source) (finish-output source)
           (let ((before (length (mock-sent transport))))
             (fail (sftp-upload session source-path "file" :fsync t) 'sftp-unsupported-error)
             (is = before (length (mock-sent transport))))
           (fail (sftp-upload session source-path "file" :progress-function
                   (lambda (count total) (declare (ignore total)) (push count progress))) 'sftp-status-error)
           (is equal '(0) progress)
           (is = 0 (hash-table-count (ssh/sftp::sftp-session-pending session)))
           (is = 0 (hash-table-count (ssh/sftp::sftp-session-handles session)))
           (true (sftp-stat session "still usable")))
      (close-sftp session))))

(define-test sftp-progress-reentry-is-rejected :parent (:ssh/tests ssh/tests)
  (let* ((transport (make-instance 'mock-sftp-stream :callback #'file-server))
         (session (ssh/sftp::%start-session transport)))
    (unwind-protect
         (uiop:with-temporary-file (:pathname destination)
           (fail (sftp-download session "file" destination :if-exists :supersede
                  :progress-function (lambda (count total) (declare (ignore count total))
                                       (sftp-stat session "reentry"))) 'sftp-error)
           (is = 0 (hash-table-count (ssh/sftp::sftp-session-handles session))))
      (close-sftp session))))

(define-test sftp-nested-progress-reentry-is-rejected :parent (:ssh/tests ssh/tests)
  (let* ((a (ssh/sftp::%start-session (make-instance 'mock-sftp-stream :callback #'file-server)))
         (b (ssh/sftp::%start-session (make-instance 'mock-sftp-stream :callback #'file-server)))
         (c (ssh/sftp::%start-session (make-instance 'mock-sftp-stream :callback #'file-server))))
    (unwind-protect
         (progn
           ;; No operation is held here: a broken guard fails assertions rather than hanging.
           (ssh/sftp/stream::%progress
            (lambda (count total)
              (declare (ignore count total))
              (ssh/sftp/stream::%progress
               (lambda (count total)
                 (declare (ignore count total))
                 (dolist (session (list a b))
                   (fail (sftp-stat session "reentry") 'sftp-error)
                   (fail (close-sftp session) 'sftp-error)
                   (fail (close-sftp session :abort t) 'sftp-error))
                 (true (sftp-stat c "unrelated")))
               b 0 nil)
              (fail (sftp-stat a "outer callback") 'sftp-error)
              (true (sftp-stat b "inner callback returned")))
            a 0 nil)
           (dolist (session (list a b c))
             (true (sftp-stat session "callbacks returned"))))
      (close-sftp a :abort t)
      (close-sftp b :abort t)
      (close-sftp c :abort t))))

(define-test sftp-progress-cannot-close-its-own-session :parent (:ssh/tests ssh/tests)
  (let* ((transport (make-instance 'mock-sftp-stream :callback #'file-server))
         (session (ssh/sftp::%start-session transport)))
    (unwind-protect
         (uiop:with-temporary-file (:pathname destination)
           (fail (sftp-download session "file" destination :if-exists :supersede
                  :progress-function (lambda (count total) (declare (ignore count total))
                                       (close-sftp session))) 'sftp-error)
           (true (sftp-stat session "still usable")))
      (close-sftp session))))

(define-test sftp-session-close-flushes-owned-streams :parent (:ssh/tests ssh/tests)
  (let* ((transport (make-instance 'mock-sftp-stream :callback #'file-server))
         (session (ssh/sftp::%start-session transport))
         (output (open-sftp-file session "file" :direction :output)))
    (write-byte 42 output)
    (true (close-sftp session))
    (false (open-stream-p output))
    (is equal '(1 3 6 4) (reverse (mapcar (lambda (frame) (aref frame 4)) (mock-sent transport))))))

(define-test sftp-io-stream-seeks-and-invalidates-read-ahead :parent (:ssh/tests ssh/tests)
  (let* ((writes nil)
         (transport (make-instance 'mock-sftp-stream :callback
           (lambda (stream type buffer)
             (if (= type 6)
                 (let ((id (ssh/buffer:read-uint32 buffer)))
                   (ssh/buffer:read-string* buffer)
                   (let ((offset (ssh/buffer:read-uint64 buffer))
                         (data (ssh/buffer:read-string* buffer)))
                     (push (cons offset data) writes))
                   (status-reply stream id 0))
                 (funcall (transfer-server (octets 1 2 3 4 5)) stream type buffer)))))
         (session (ssh/sftp::%start-session transport)))
    (unwind-protect
         (with-open-sftp-file (stream session "file" :direction :io :if-exists :overwrite)
           (true (input-stream-p stream)) (true (output-stream-p stream))
           (is = 1 (read-byte stream))
           (write-byte 9 stream)
           (is = 2 (file-position stream))
           (is = 3 (read-byte stream))
           (is equalp (list (cons 1 (octets 9))) writes)
           (fail (write-sequence #(8 "bad") stream))
           (is = 3 (file-position stream))
           (true (file-position stream (ash 1 33)))
           (is = (ash 1 33) (file-position stream)))
      (close-sftp session))))

(define-test sftp-stream-read-sequence-follows-short-reads :parent (:ssh/tests ssh/tests)
  (let* ((transport (make-instance 'mock-sftp-stream :callback #'file-server))
         (session (ssh/sftp::%start-session transport)))
    (unwind-protect
         (with-open-sftp-file (stream session "file")
           (let ((out (make-array 10 :element-type '(unsigned-byte 8))))
             (is = 3 (read-sequence out stream))
             (is equalp (octets 1 2 3) (subseq out 0 3))
             (is = 3 (file-position stream))
             (true (file-position stream :start))
             (is = 1 (read-byte stream))))
      (close-sftp session))))

(define-test sftp-stream-open-policies :parent (:ssh/tests ssh/tests)
  (is equal '(:read) (ssh/sftp/stream::%file-flags :input :default :default))
  (is = 42 (ssh/sftp::%open-flags (ssh/sftp/stream::%file-flags :output :default :default)))
  (is = 26 (ssh/sftp::%open-flags (ssh/sftp/stream::%file-flags :output :supersede :create)))
  (is = 2 (ssh/sftp::%open-flags (ssh/sftp/stream::%file-flags :output :overwrite :error)))
  (fail (ssh/sftp/stream::%file-flags :output :error :error))
  (fail (ssh/sftp/stream::%file-flags :io :append :create))
  (fail (ssh/sftp/stream::%file-flags :input :supersede :error)))

(define-test sftp-open-compatible-policies :parent (:ssh/tests ssh/tests)
  (is equal '(:read :create) (ssh/sftp/stream::%stream-open-flags :input :supersede :create))
  (is equal '(:write) (ssh/sftp/stream::%stream-open-flags :output :overwrite :default))
  (is equal '(:write :append) (ssh/sftp/stream::%stream-open-flags :output :append :default))
  (is equal '(:read) (ssh/sftp/stream::%stream-open-flags :probe :default :default))
  (fail (ssh/sftp/stream::%stream-open-flags :output :rename :default))
  (let* ((transport (make-instance 'mock-sftp-stream :callback #'file-server))
         (session (ssh/sftp::%start-session transport)))
    (unwind-protect
         (progn
           (false (open-sftp-file session "file" :direction :output :if-exists nil))
           (let ((probe (open-sftp-file session "file" :direction :probe :if-exists :rename)))
             (false (open-stream-p probe))
             (false (input-stream-p probe))
             (false (output-stream-p probe)))
           (with-open-sftp-file (stream session "file" :if-exists :rename
                                        :element-type '(unsigned-byte 8) :external-format :utf-8)
             (is = 1 (read-byte stream)))
           (fail (open-sftp-file session "file" :element-type 'character))
           (fail (open-sftp-file session "file" :direction :output
                                 :if-exists :error :if-does-not-exist :error))
           (is = 0 (hash-table-count (ssh/sftp::sftp-session-handles session))))
      (close-sftp session))))

(define-test sftp-open-missing-and-permission-policies :parent (:ssh/tests ssh/tests)
  (dolist (code '(2 3))
    (let* ((requests nil)
           (transport (make-instance 'mock-sftp-stream :callback
                        (lambda (stream type buffer)
                          (push type requests)
                          (if (member type '(3 17))
                              (status-reply stream (ssh/buffer:read-uint32 buffer) code)
                              (file-server stream type buffer)))))
           (session (ssh/sftp::%start-session transport)))
      (unwind-protect
           (progn
             (dolist (options '((:if-does-not-exist nil)
                               (:direction :probe)
                               (:direction :output :if-exists :supersede :if-does-not-exist nil)
                               (:direction :output :if-exists nil :if-does-not-exist nil)))
               (if (= code 2)
                   (false (apply #'open-sftp-file session "missing" options))
                   (fail (apply #'open-sftp-file session "denied" options) 'sftp-status-error)))
             (when (= code 2)
               (is eql :body
                   (with-open-sftp-file (stream session "missing" :if-does-not-exist nil)
                     (false stream) :body)))
             (is = 0 (hash-table-count (ssh/sftp::sftp-session-handles session))))
        (close-sftp session)))))

(define-test sftp-output-flush-and-append-position :parent (:ssh/tests ssh/tests)
  (let* ((transport (make-instance 'mock-sftp-stream :callback #'file-server))
         (session (ssh/sftp::%start-session transport)))
    (unwind-protect
         (with-open-sftp-file (stream session "file" :direction :output :if-exists :append)
           (false (file-position stream))
           (false (file-position stream 0))
           (write-sequence (octets 0 255 128) stream)
           (let ((before (length (mock-sent transport))))
             (finish-output stream)
             (is = (1+ before) (length (mock-sent transport)))))
      (close-sftp session))))

(define-test sftp-close-failures-are-visible :parent (:ssh/tests ssh/tests)
  (let* ((transport (make-instance 'mock-sftp-stream
                     :callback (lambda (stream type buffer)
                                 (if (= type 4)
                                     (status-reply stream (ssh/buffer:read-uint32 buffer) 4)
                                     (file-server stream type buffer)))))
         (session (ssh/sftp::%start-session transport)))
    (unwind-protect
         (let ((stream (open-sftp-file session "file" :direction :output)))
           (write-byte 1 stream)
           (fail (close stream) 'sftp-status-error)
           (false (open-stream-p stream)))
      (close-sftp session :abort t))))
