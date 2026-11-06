(defpackage #:ssh/tests/concurrency
  (:use #:cl #:parachute))
(in-package #:ssh/tests/concurrency)

(defun wait-for-state (predicate &optional (seconds 2))
  (let ((deadline (+ (get-internal-real-time)
                     (* seconds internal-time-units-per-second))))
    (loop
      (when (funcall predicate) (return t))
      (when (>= (get-internal-real-time) deadline) (return nil))
      (sleep 0.001))))

(defun join-review-thread (thread)
  (when thread
    (unless (wait-for-state (lambda () (not (bt2:thread-alive-p thread))))
      (bt2:destroy-thread thread)
      (error "Concurrency regression left a blocked test thread"))
    (bt2:join-thread thread)))

(define-test queued-channel-writes-cannot-follow-peer-close
  :parent (:ssh/tests ssh/tests)
  (dolist (operation '(:data :request :eof :window))
    (let* ((connection (ssh/connection::%make-connection
                        :transport (ssh/transport::make-transport)
                        :state :running :dispatcher-thread (bt2:current-thread)))
           (channel (ssh/tests/connection::add-test-channel connection
                      (ssh/connection::make-channel :connection connection :local-id 3
                        :remote-id 7 :remote-window 4 :open-p t)))
           (other (ssh/tests/connection::add-test-channel connection
                    (ssh/connection::make-channel :connection connection :local-id 4
                      :remote-id 8 :remote-window 4 :open-p t)))
           (original (symbol-function 'ssh/transport:transport-send))
           (sent nil) (result nil) (writer nil))
      ;; The test thread pumps the dispatcher queue. No socket wake is needed.
      (setf (ssh/connection::connection-wake-pending-p connection) t)
      (when (eq operation :window)
        (setf (ssh/connection:channel-local-window channel) 2
              (ssh/connection::channel-local-window-maximum channel) 4)
        (ssh/channel-buffer:buffer-accept (ssh/connection::channel-stdout-input channel)
                                        (ssh/tests:octets 1 2)))
      (unwind-protect
           (progn
             (setf (symbol-function 'ssh/transport:transport-send)
                   (lambda (transport payload)
                     (declare (ignore transport))
                     (push (aref payload 0) sent)))
             (setf writer
                   (bt2:make-thread
                    (lambda ()
                      (setf result
                            (handler-case
                                (ecase operation
                                  (:data (ssh/connection:channel-send-data channel (ssh/tests:octets 1)))
                                  (:request (ssh/connection:channel-request channel "env" :want-reply nil))
                                  (:eof (ssh/connection:channel-send-eof channel))
                                  (:window (ssh/connection::%channel-read channel
                                             (ssh/tests:octets 0 0) 0 2 nil t)))
                              (error (condition) condition))))))
             (when (true (wait-for-state
                          (lambda ()
                            (bt2:with-lock-held ((ssh/connection::connection-queue-lock connection))
                              (not (null (ssh/connection::connection-action-head connection)))))))
               ;; CLOSE is handled before the already queued caller action.
               (ssh/connection::%handle-packet connection
                 (ssh/tests:octets ssh/constants:+msg-channel-close+ 0 0 0 3))
               (false (ssh/connection::%process-action connection
                        (ssh/connection::%dequeue-action connection)))
               (join-review-thread writer)
               (if (eq operation :window) (is = 2 result) (of-type 'error result))
               (is equal (list ssh/constants:+msg-channel-close+) (reverse sent))
               (is eq :running (ssh/connection::connection-state connection))
               (ssh/connection:channel-send-data other (ssh/tests:octets 9))
               (is equal (list ssh/constants:+msg-channel-close+ ssh/constants:+msg-channel-data+)
                   (reverse sent))))
        (ssh/connection::%fail-connection connection "concurrency test cleanup")
        (join-review-thread writer)
        (setf (symbol-function 'ssh/transport:transport-send) original)))))

(define-test channel-close-cancels-a-window-blocked-writer
  :parent (:ssh/tests ssh/tests)
  (dolist (abort '(nil t))
    (let* ((connection (ssh/tests/connection::make-test-connection))
           (channel (ssh/tests/connection::add-test-channel connection
                      (ssh/connection::make-channel :connection connection :local-id 3
                        :remote-id 7 :remote-window 0 :open-p t)))
           (stream (make-instance 'ssh/session:ssh-channel-stream
                                 :connection connection :channel channel))
           (gate (bt2:make-lock)) (sent nil)
           (original (symbol-function 'ssh/transport:transport-send))
           (writer nil) (closer nil) (reader nil)
           (writer-result nil) (close-result nil) (reader-result nil))
      (unwind-protect
           (progn
             (setf (symbol-function 'ssh/transport:transport-send)
                   (lambda (transport payload)
                     (declare (ignore transport))
                     (bt2:with-lock-held (gate) (push (aref payload 0) sent))))
             (setf writer (bt2:make-thread
                           (lambda ()
                             (setf writer-result
                                   (handler-case (write-byte 1 stream)
                                     (error (condition) condition))))))
             (when (true (wait-for-state
                          (lambda ()
                            (let ((acquired (bt2:acquire-lock
                                             (ssh/connection:channel-write-lock channel) :wait nil)))
                              (when acquired
                                (bt2:release-lock (ssh/connection:channel-write-lock channel)))
                              (not acquired)))))
               (when abort
                 (setf reader (bt2:make-thread
                               (lambda ()
                                 (setf reader-result
                                       (handler-case (read-byte stream)
                                         (error (condition) condition)))))))
               (setf closer (bt2:make-thread
                             (lambda ()
                               (setf close-result
                                     (handler-case
                                         (if abort (close stream :abort t)
                                             (ssh/connection:channel-close channel))
                                       (error (condition) condition))))))
               (when (true (wait-for-state
                            (lambda ()
                              (bt2:with-lock-held (gate)
                                (member ssh/constants:+msg-channel-close+ sent)))))
                 (if abort
                     ;; Aborting must return without any remote CLOSE reply.
                     (true (wait-for-state (lambda () (not (bt2:thread-alive-p closer)))))
                     (ssh/connection::%handle-packet connection
                       (ssh/tests:octets ssh/constants:+msg-channel-close+ 0 0 0 3)))
                 (join-review-thread closer)
                 (join-review-thread writer)
                 (of-type 'error writer-result)
                 (is eq t close-result)
                 (is equal (if abort (list ssh/constants:+msg-channel-close+)
                               (list ssh/constants:+msg-channel-eof+ ssh/constants:+msg-channel-close+))
                     (reverse sent))
                 (when abort
                   (join-review-thread reader)
                   (of-type 'ssh/session:shell-stream-closed reader-result)
                   (false (open-stream-p stream))))))
        (ssh/connection::%fail-channel channel
          (make-condition 'simple-error :format-control "concurrency test cleanup"))
        (bt2:with-lock-held ((ssh/connection:channel-state-lock channel))
          (setf (ssh/connection:channel-close-p channel) t)
          (bt2:condition-broadcast (ssh/connection:channel-state-condition channel)))
        (join-review-thread writer)
        (join-review-thread closer)
        (join-review-thread reader)
        (setf (symbol-function 'ssh/transport:transport-send) original)))))

(define-test closing-cancels-a-request-and-tolerates-its-late-reply
  :parent (:ssh/tests ssh/tests)
  (let* ((connection (ssh/tests/connection::make-test-connection))
         (channel (ssh/tests/connection::add-test-channel connection
                    (ssh/connection::make-channel :connection connection :local-id 3
                      :remote-id 7 :open-p t)))
         (gate (bt2:make-lock)) (sent nil)
         (original (symbol-function 'ssh/transport:transport-send))
         (requester nil) (closer nil) (request-result nil) (close-result nil))
    (unwind-protect
         (progn
           (setf (symbol-function 'ssh/transport:transport-send)
                 (lambda (transport payload)
                   (declare (ignore transport))
                   (bt2:with-lock-held (gate) (push (aref payload 0) sent))))
           (setf requester
                 (bt2:make-thread
                  (lambda ()
                    (setf request-result
                          (handler-case (ssh/connection:channel-request channel "exec")
                            (error (condition) condition))))))
           (when (true (wait-for-state
                        (lambda ()
                          (bt2:with-lock-held (gate)
                            (member ssh/constants:+msg-channel-request+ sent)))))
             (setf closer
                   (bt2:make-thread
                    (lambda ()
                      (setf close-result
                            (handler-case (ssh/connection:channel-close channel)
                              (error (condition) condition))))))
             (when (true (wait-for-state
                          (lambda ()
                            (bt2:with-lock-held (gate)
                              (member ssh/constants:+msg-channel-close+ sent)))))
               (join-review-thread requester)
               (of-type 'error request-result)
               ;; The peer can answer an already sent request before its CLOSE.
               (dolist (reply (list ssh/constants:+msg-channel-success+
                                    ssh/constants:+msg-channel-failure+))
                 (true (handler-case
                           (progn (ssh/connection::%handle-packet connection
                                    (ssh/tests:octets reply 0 0 0 3)) t)
                         (error () nil))))
               (ssh/connection::%handle-packet connection
                 (ssh/tests:octets ssh/constants:+msg-channel-close+ 0 0 0 3))
               (join-review-thread closer)
               (is eq t close-result)
               (is equal (list ssh/constants:+msg-channel-request+
                               ssh/constants:+msg-channel-eof+
                               ssh/constants:+msg-channel-close+)
                   (reverse sent)))))
      (ssh/connection::%fail-channel channel
        (make-condition 'simple-error :format-control "concurrency test cleanup"))
      (bt2:with-lock-held ((ssh/connection:channel-state-lock channel))
        (setf (ssh/connection:channel-close-p channel) t)
        (bt2:condition-broadcast (ssh/connection:channel-state-condition channel)))
      (join-review-thread requester)
      (join-review-thread closer)
      (setf (symbol-function 'ssh/transport:transport-send) original))))

(define-test concurrent-sftp-closes-share-one-cleanup
  :parent (:ssh/tests ssh/tests)
  (dolist (fail-close '(nil t))
   (let* ((failure (make-condition 'simple-error :format-control "expected close failure"))
          (session (ssh/sftp::%make-session :channel (ssh/connection::make-channel) :state :ready))
         (gate (bt2:make-lock)) (changed (bt2:make-condition-variable))
         (old-close (symbol-function 'ssh/connection:channel-close))
         (old-wait (symbol-function 'bt2:condition-wait))
         (first nil) (second nil) (entered nil) (release-first nil) (start-second nil)
         (second-waiting nil) (second-finished nil) (first-result nil) (second-result nil)
         (closes 0))
    (unwind-protect
         (progn
           (setf (symbol-function 'ssh/connection:channel-close)
                 (lambda (channel &key abort)
                   (declare (ignore channel abort))
                   (bt2:with-lock-held (gate)
                     (incf closes)
                     (setf entered t)
                     (bt2:condition-broadcast changed)
                     (loop until release-first do (bt2:condition-wait changed gate)))
                   (if fail-close (error failure) t))
                 (symbol-function 'bt2:condition-wait)
                 (lambda (condition lock &rest options)
                   ;; Observe the actual wait, rather than guessing from a sleep.
                   (when (and (eq lock (ssh/sftp::sftp-session-lock session))
                              (eq (bt2:current-thread) second))
                     (bt2:with-lock-held (gate)
                       (setf second-waiting t)
                       (bt2:condition-broadcast changed)))
                   (apply old-wait condition lock options)))
           (setf first (bt2:make-thread
                        (lambda ()
                          (setf first-result
                                (handler-case (ssh/sftp:close-sftp session)
                                  (error (condition) condition))))))
           (when (true (wait-for-state (lambda () (bt2:with-lock-held (gate) entered))))
             (setf second (bt2:make-thread
                           (lambda ()
                             (bt2:with-lock-held (gate)
                               (loop until start-second do (bt2:condition-wait changed gate)))
                             (let ((result (handler-case (ssh/sftp:close-sftp session)
                                             (error (condition) condition))))
                               (bt2:with-lock-held (gate)
                                 (setf second-result result second-finished t)
                                 (bt2:condition-broadcast changed))))))
             (bt2:with-lock-held (gate)
               (setf start-second t)
               (bt2:condition-broadcast changed))
             (true (wait-for-state
                    (lambda () (bt2:with-lock-held (gate)
                                 (or second-waiting second-finished)))))
             (bt2:with-lock-held (gate)
               (true second-waiting)
               (false second-finished))
             (is eq :closing (ssh/sftp::sftp-session-state session))
             (bt2:with-lock-held (gate)
               (setf release-first t)
               (bt2:condition-broadcast changed))
             (join-review-thread first)
             (join-review-thread second)
             (is eq (if fail-close failure t) first-result)
             (is eq (if fail-close failure t) second-result)
             (is = 1 closes)
             (is eq :closed (ssh/sftp::sftp-session-state session))
             (true (ssh/sftp:close-sftp session))))
      (bt2:with-lock-held (gate)
        (setf release-first t start-second t)
        (bt2:condition-broadcast changed))
      (join-review-thread first)
      (join-review-thread second)
      (setf (symbol-function 'ssh/connection:channel-close) old-close
            (symbol-function 'bt2:condition-wait) old-wait)))))

(define-test abort-interrupts-a-graceful-sftp-close-waiting-for-an-operation
  :parent (:ssh/tests ssh/tests)
  (let* ((stream (make-instance 'ssh/tests/sftp::mock-sftp-stream
                   :callback (lambda (stream type buffer)
                               ;; Leave READ unanswered to block an active operation.
                               (unless (= type 5)
                                 (ssh/tests/sftp::file-server stream type buffer)))))
         (session (ssh/sftp::%start-session stream))
         (handle (ssh/sftp:sftp-open-file session "file" '(:read)))
         (operation nil) (closer nil) (aborter nil)
         (operation-result nil) (close-result nil) (abort-result nil))
    (unwind-protect
         (progn
           (setf operation
                 (bt2:make-thread
                  (lambda ()
                    (setf operation-result
                          (handler-case (ssh/sftp:sftp-read-at handle 0 1)
                            (error (condition) condition))))))
           (when (true (wait-for-state
                        (lambda ()
                          (bt2:with-lock-held ((ssh/sftp::sftp-session-lock session))
                            (= 1 (hash-table-count (ssh/sftp::sftp-session-pending session)))))))
             (setf closer
                   (bt2:make-thread
                    (lambda ()
                      (setf close-result
                            (handler-case (ssh/sftp:close-sftp session)
                              (error (condition) condition))))))
             (when (true (wait-for-state
                          (lambda ()
                            (bt2:with-lock-held ((ssh/sftp::sftp-session-lock session))
                              (eq closer (ssh/sftp::sftp-session-close-owner session))))))
               (setf aborter
                     (bt2:make-thread
                      (lambda ()
                        (setf abort-result
                              (handler-case (ssh/sftp:close-sftp session :abort t)
                                (error (condition) condition))))))
               (when (true (wait-for-state (lambda () (not (bt2:thread-alive-p aborter)))))
                 (join-review-thread aborter)
                 (join-review-thread closer)
                 (join-review-thread operation)
                 (is eq t abort-result)
                 (of-type 'ssh/sftp/codec:sftp-error close-result)
                 (of-type 'ssh/sftp/codec:sftp-error operation-result)
                 (false (ssh/sftp:sftp-handle-open-p handle))
                 (is eq :closed (ssh/sftp::sftp-session-state session))
                 (is = 0 (hash-table-count (ssh/sftp::sftp-session-pending session)))
                 (false (bt2:thread-alive-p (ssh/sftp::sftp-session-reader session)))))))
      (ssh/sftp::%fail-session session
        (make-condition 'ssh/sftp/codec:sftp-error :message "concurrency test cleanup"))
      (ignore-errors (close stream))
      (join-review-thread operation)
      (join-review-thread closer)
      (join-review-thread aborter))))
