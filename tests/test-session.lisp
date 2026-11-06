;;;; Tests for shell stream helpers.

(defpackage :ssh/tests/session
  (:use :cl :parachute)
  (:import-from :ssh/session
                #:ssh-channel-stream
                #:shell-read-line
                #:shell-read-until
                #:shell-stream-closed))

(in-package :ssh/tests/session)

(define-test stderr-progress-is-independent-of-a-blocked-stdout-reader :parent (:ssh/tests ssh/tests)
  (multiple-value-bind (stdout channel) (make-shell-stream)
    (let* ((stderr (make-instance 'ssh/session::ssh-channel-input-stream :channel channel :stderr-p t))
           (outcome nil) (reader (bt2:make-thread (lambda () (setf outcome (read-byte stdout))))))
      (bt2:with-lock-held ((ssh/connection:channel-state-lock channel))
        (ssh/channel-buffer:buffer-accept (ssh/connection::channel-stderr-input channel)
                                          (ssh/tests:octets 42)))
      (is = 42 (read-byte stderr))
      (append-channel-output channel "x")
      (bt2:join-thread reader)
      (is = (char-code #\x) outcome)
      (true (close stderr))
      (false (ssh/connection:channel-close-p channel)))))

(define-test closing-stderr-wakes-its-reader-and-retains-only-a-tail :parent (:ssh/tests ssh/tests)
  (multiple-value-bind (stdout channel) (make-shell-stream)
    (declare (ignore stdout))
    (let* ((stderr (make-instance 'ssh/session::ssh-channel-input-stream :channel channel :stderr-p t))
           (outcome nil) (reader (bt2:make-thread
             (lambda () (setf outcome (handler-case (read-byte stderr)
                                        (shell-stream-closed (cause) cause)))))))
      (true (close stderr))
      (bt2:join-thread reader)
      (of-type 'shell-stream-closed outcome)
      (let ((tail (ssh/connection::channel-stderr-input channel)))
        (is eq :tail (ssh/channel-buffer:input-buffer-mode tail))
        (ssh/channel-buffer:buffer-accept tail
          (make-array 100000 :element-type '(unsigned-byte 8) :initial-element 42))
        (is = 65536 (ssh/channel-buffer:input-buffer-count tail))
        (true (ssh/channel-buffer:input-buffer-truncated-p tail))))))

(defun make-shell-stream (&key (buffer "") eof-p close-p)
  (let* ((transport (ssh/transport::make-transport))
         (conn (ssh/connection::%make-connection :transport transport))
         (channel (ssh/connection::make-channel))
         (stream (make-instance 'ssh-channel-stream
                                :connection conn
                                :channel channel)))
    (ssh/channel-buffer:buffer-accept (ssh/connection::channel-stdout-input channel)
                                    (ssh/buffer:utf-8-to-octets buffer))
    (setf (ssh/connection::channel-eof-p channel) eof-p
          (ssh/connection::channel-close-p channel) close-p)
    (values stream channel nil)))

(defun append-channel-output (channel string)
  (bt2:with-lock-held ((ssh/connection::channel-state-lock channel))
    (ssh/channel-buffer:buffer-accept (ssh/connection::channel-stdout-input channel)
                                    (ssh/buffer:utf-8-to-octets string))
    (bt2:condition-broadcast (ssh/connection::channel-state-condition channel))))

(define-test shell-stream-consumption-reclaims-channel-output :parent (:ssh/tests ssh/tests)
  (multiple-value-bind (stream channel) (make-shell-stream :buffer "abcdef" :eof-p t)
    (let ((out (make-array 4 :element-type '(unsigned-byte 8))))
      (is = 4 (read-sequence out stream))
      (is equalp (ssh/buffer:utf-8-to-octets "abcd") out)
      (is equalp (ssh/buffer:utf-8-to-octets "ef")
          (ssh/connection:channel-stdout-buffer channel)))))

(define-test shell-text-conversion-uses-utf8 :parent (:ssh/tests ssh/tests)
  (let ((text "ssh-tést-値"))
    (is equalp (ssh/buffer:utf-8-to-octets text)
        (ssh/session::%string-to-octets text))
    (is string= text
        (ssh/session::%octets-to-string (ssh/buffer:utf-8-to-octets text)))))

(define-test shell-read-line-signals-on-eof-when-empty :parent (:ssh/tests ssh/tests)
  (multiple-value-bind (stream channel socket)
      (make-shell-stream :eof-p t)
    (declare (ignore channel socket))
    (of-type 'end-of-file
      (handler-case (progn (shell-read-line stream) nil)
        (end-of-file (c) c)))))

(define-test shell-read-line-returns-eof-value-when-suppressed :parent (:ssh/tests ssh/tests)
  (multiple-value-bind (stream channel socket)
      (make-shell-stream :eof-p t)
    (declare (ignore channel socket))
    (multiple-value-bind (line missing-p)
        (shell-read-line stream :error-p nil)
      (is equalp "" line)
      (is eq :eof missing-p))))

(define-test shell-read-line-returns-partial-line-on-eof :parent (:ssh/tests ssh/tests)
  (multiple-value-bind (stream channel socket)
      (make-shell-stream :buffer "abc" :eof-p t)
    (declare (ignore channel socket))
    (multiple-value-bind (line missing-p)
        (shell-read-line stream :error-p nil)
      (is string= "abc" line)
      (is eq :eof missing-p))))

(define-test shell-read-line-decodes-utf8-text :parent (:ssh/tests ssh/tests)
  (multiple-value-bind (stream channel socket)
      (make-shell-stream :buffer "ssh-tést" :eof-p t)
    (declare (ignore channel socket))
    (multiple-value-bind (line missing-p)
        (shell-read-line stream :error-p nil)
      (is string= "ssh-tést" line)
      (is eq :eof missing-p))))

(define-test shell-read-until-returns-partial-text-on-close :parent
  (:ssh/tests ssh/tests)
  (multiple-value-bind (stream channel socket)
      (make-shell-stream :buffer "pre" :close-p t)
    (declare (ignore channel socket))
    (multiple-value-bind (string found-p)
        (shell-read-until stream "__DONE__" :error-p nil)
      (is string= "pre" string)
      (is eq :closed found-p))))

(define-test shell-read-until-signals-on-close-when-empty :parent
  (:ssh/tests ssh/tests)
  (multiple-value-bind (stream channel socket)
      (make-shell-stream :close-p t)
    (declare (ignore channel socket))
    (of-type 'shell-stream-closed
      (handler-case (progn (shell-read-until stream "__DONE__") nil)
        (shell-stream-closed (c) c)))))

(define-test shell-read-until-unblocked-drains-buffer :parent (:ssh/tests ssh/tests)
  (multiple-value-bind (stream channel socket)
      (make-shell-stream :buffer "abc")
    (declare (ignore channel socket))
    (multiple-value-bind (string status)
        (shell-read-until stream nil :block-p nil)
      (is string= "abc" string)
      (is eq :blocked status)
      (multiple-value-bind (rest rest-status)
          (shell-read-until stream nil :block-p nil)
        (is string= "" rest)
        (is eq :blocked rest-status)))))

(define-test shell-read-until-unblocked-stops-at-marker :parent (:ssh/tests ssh/tests)
  (multiple-value-bind (stream channel socket)
      (make-shell-stream :buffer "pre__DONE__post")
    (declare (ignore channel socket))
    (multiple-value-bind (string status)
        (shell-read-until stream "__DONE__" :block-p nil)
      (is string= "pre" string)
      (is eq :found status)
      (multiple-value-bind (rest rest-status)
          (shell-read-until stream nil :block-p nil)
        (is string= "post" rest)
        (is eq :blocked rest-status)))))

(define-test shell-read-until-matches-utf8-marker :parent (:ssh/tests ssh/tests)
  (multiple-value-bind (stream channel socket)
      (make-shell-stream :buffer "pré終post")
    (declare (ignore channel socket))
    (multiple-value-bind (string status)
        (shell-read-until stream "終" :block-p nil)
      (is string= "pré" string)
      (is eq :found status)
      (multiple-value-bind (rest rest-status)
          (shell-read-until stream nil :block-p nil)
        (is string= "post" rest)
        (is eq :blocked rest-status)))))

(define-test shell-read-until-unblocked-signals-on-close-when-empty :parent
  (:ssh/tests ssh/tests)
  (multiple-value-bind (stream channel socket)
      (make-shell-stream :close-p t)
    (declare (ignore channel socket))
    (of-type 'shell-stream-closed
             (handler-case (progn (shell-read-until stream nil :block-p nil) nil)
               (shell-stream-closed (c) c)))))

(define-test shell-read-until-unblocked-suppresses-eof-when-requested :parent
  (:ssh/tests ssh/tests)
  (multiple-value-bind (stream channel socket)
      (make-shell-stream :eof-p t)
    (declare (ignore channel socket))
    (multiple-value-bind (string found-p)
        (shell-read-until stream nil :error-p nil :block-p nil)
      (is string= "" string)
      (is eq :eof found-p))))

(define-test shell-stream-supports-concurrent-reader-and-writer :parent
  (:ssh/tests ssh/tests)
  (let* ((transport (ssh/transport::make-transport))
         (conn (ssh/connection::%make-connection :transport transport))
         (channel (ssh/connection::make-channel :connection conn
                                                 :remote-id 7
                                                 :remote-window 1024
                                                 :max-packet 1024
                                                 :open-p t))
         (stream (make-instance 'ssh-channel-stream
                                :connection conn
                                :channel channel))
         (reader-result nil)
         (reader-status nil)
         (sent nil)
         (original-send (symbol-function 'ssh/transport:transport-send)))
    (unwind-protect
         (progn
           (setf (symbol-function 'ssh/transport:transport-send)
                 (lambda (_transport payload)
                   (declare (ignore _transport))
                   (push payload sent)))
           (let ((reader
                   (bt2:make-thread
                    (lambda ()
                      (multiple-value-setq (reader-result reader-status)
                        (shell-read-until stream "__DONE__"))))))
             (write-sequence (ssh/buffer:utf-8-to-octets "input") stream)
             (true sent)
             (append-channel-output channel "reply__DONE__")
             (bt2:join-thread reader)
             (is string= "reply" reader-result)
             (is eq :found reader-status)))
      (setf (symbol-function 'ssh/transport:transport-send) original-send))))

(define-test blocked-shell-reader-wakes-on-close :parent (:ssh/tests ssh/tests)
  (multiple-value-bind (stream channel socket)
      (make-shell-stream)
    (declare (ignore socket))
    (let* ((result nil)
           (reader (bt2:make-thread
                    (lambda ()
                      (setf result
                            (handler-case (progn (read-byte stream) nil)
                              (shell-stream-closed (condition) condition)))))))
      (bt2:with-lock-held ((ssh/connection::channel-state-lock channel))
        (setf (ssh/connection::channel-close-p channel) t)
        (bt2:condition-broadcast (ssh/connection::channel-state-condition channel)))
      (bt2:join-thread reader)
      (of-type 'shell-stream-closed result))))

(define-test same-direction-shell-writes-are-serialized :parent
  (:ssh/tests ssh/tests)
  (let* ((transport (ssh/transport::make-transport))
         (connection (ssh/connection::%make-connection :transport transport))
         (channel (ssh/connection::make-channel :connection connection
                                                 :remote-id 7
                                                 :remote-window 2
                                                 :max-packet 1
                                                 :open-p t))
         (stream (make-instance 'ssh-channel-stream
                                :connection connection
                                :channel channel))
         (gate (bt2:make-lock :name "serialized write test"))
         (changed (bt2:make-condition-variable :name "serialized write test"))
         (first-entered nil)
         (second-started nil)
         (release-first nil)
         (calls 0)
         (sent nil)
         (original-send (symbol-function 'ssh/transport:transport-send)))
    (unwind-protect
         (progn
           (setf (symbol-function 'ssh/transport:transport-send)
                 (lambda (_transport payload)
                   (declare (ignore _transport))
                   (bt2:with-lock-held (gate)
                     (incf calls)
                     (when (= calls 1)
                       (setf first-entered t)
                       (bt2:condition-broadcast changed)
                       (loop until release-first
                             do (bt2:condition-wait changed gate)))
                     (setf sent (nconc sent (list payload))))))
           (let ((first (bt2:make-thread
                         (lambda () (write-byte 1 stream))))
                 (second nil))
             (bt2:with-lock-held (gate)
               (loop until first-entered
                     do (bt2:condition-wait changed gate)))
             (setf second
                   (bt2:make-thread
                    (lambda ()
                      (bt2:with-lock-held (gate)
                        (setf second-started t)
                        (bt2:condition-broadcast changed))
                      (write-byte 2 stream))))
             (bt2:with-lock-held (gate)
               (loop until second-started
                     do (bt2:condition-wait changed gate))
               (is = 1 calls)
               (setf release-first t)
               (bt2:condition-broadcast changed))
             (bt2:join-thread first)
             (bt2:join-thread second)
             (is = 2 calls)
             (is equal '(1 2)
                 (mapcar
                  (lambda (payload)
                    (let ((buffer (ssh/buffer:make-read-buffer payload)))
                      (ssh/buffer:read-byte* buffer)
                      (ssh/buffer:read-uint32 buffer)
                      (aref (ssh/buffer:read-string* buffer) 0)))
                  sent))))
      (setf (symbol-function 'ssh/transport:transport-send) original-send))))
