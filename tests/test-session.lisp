;;;; Tests for shell stream helpers.

(defpackage :ssh/tests/session
  (:use :cl :parachute)
  (:import-from :ssh/session
                #:ssh-channel-stream
                #:shell-read-line
                #:shell-read-until
                #:shell-stream-closed))

(in-package :ssh/tests/session)

(defclass fake-shell-socket ()
  ((ready-p :initform t :accessor fake-shell-socket-ready-p)))

(defun make-shell-stream (&key (buffer "") eof-p close-p)
  (let* ((socket (make-instance 'fake-shell-socket))
         (transport (ssh/transport::make-transport :socket socket))
         (conn (ssh/connection:make-connection transport))
         (channel (ssh/connection::make-channel))
         (stream (make-instance 'ssh-channel-stream
                                :connection conn
                                :channel channel)))
    (setf (ssh/connection::channel-stdout-buffer channel) (ssh/buffer:utf-8-to-octets buffer)
          (ssh/connection::channel-eof-p channel) eof-p
          (ssh/connection::channel-close-p channel) close-p)
    (values stream channel socket)))

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

(define-test shell-read-until-unblocked-drains-readable-network-data :parent
  (:ssh/tests ssh/tests)
  (let* ((socket (make-instance 'fake-shell-socket))
         (transport (ssh/transport::make-transport :socket socket))
         (conn (ssh/connection:make-connection transport))
         (channel (ssh/connection::make-channel))
         (stream (make-instance 'ssh-channel-stream
                                :connection conn
                                :channel channel))
         (dispatch-count 0)
         (wait-count 0)
         (original-dispatch (symbol-function 'ssh/connection:channel-dispatch-until))
         (original-wait (symbol-function 'usocket:wait-for-input)))
    (unwind-protect
         (progn
           (setf (symbol-function 'usocket:wait-for-input)
                 (lambda (socket-or-sockets &key timeout ready-only &allow-other-keys)
                   (declare (ignore timeout ready-only))
                   (incf wait-count)
                   (let ((socket (if (listp socket-or-sockets)
                                     (first socket-or-sockets)
                                     socket-or-sockets)))
                     (when (fake-shell-socket-ready-p socket)
                       (setf (fake-shell-socket-ready-p socket) nil)
                       (values (list socket) 0)))))
           (setf (symbol-function 'ssh/connection:channel-dispatch-until)
                 (lambda (conn predicate)
                   (declare (ignore conn predicate))
                   (incf dispatch-count)
                   (loop for byte across (ssh/buffer:utf-8-to-octets "net")
                         do (vector-push-extend byte
                                                (ssh/connection::channel-stdout-buffer
                                                 channel)))
                   #(0)))
           (multiple-value-bind (string found-p)
               (shell-read-until stream nil :block-p nil)
             (is string= "net" string)
             (is eq :blocked found-p)
             (is = 1 dispatch-count)
             (true (> wait-count 0))))
      (setf (symbol-function 'usocket:wait-for-input) original-wait
            (symbol-function 'ssh/connection:channel-dispatch-until)
            original-dispatch))))
