;;;; Deterministic tests for the developer fuzz targets.

(defpackage :ssh/tests/fuzz
  (:use :cl :parachute))

(in-package :ssh/tests/fuzz)

(define-test fuzz-targets
  :parent (:ssh/tests ssh/tests))

(define-test zlib-fuzz-target-is-registered
  :parent (:ssh/tests ssh/tests)
  (is = 10 (length (ssh/fuzz:target-names)))
  (true (member "zlib" (ssh/fuzz:target-names) :test #'string=)))

(define-test sftp-fuzz-target-and-corpus :parent (:ssh/tests ssh/tests)
  (true (member "sftp" (ssh/fuzz:target-names) :test #'string=))
  (let ((root (asdf:system-relative-pathname :ssh "fuzz/corpus/sftp/")))
    (dolist (name '("data" "attributes" "version"))
      (is eq :accepted (ssh/fuzz:run-target "sftp" (merge-pathnames name root))))
    (is eq :rejected (ssh/fuzz:run-target "sftp" (merge-pathnames "oversized" root)))))

(define-test known-hosts-fuzz-tolerates-invalid-utf-8
  :parent (:ssh/tests ssh/tests)
  (let ((path (merge-pathnames (format nil "cl-ssh-fuzz-known-hosts-~A" (gensym))
                               (uiop:temporary-directory))))
    (unwind-protect
         (progn
           (with-open-file (stream path
                                   :direction :output
                                   :if-exists :supersede
                                   :if-does-not-exist :create
                                   :element-type '(unsigned-byte 8))
             (write-byte #xc0 stream))
           (true (member (ssh/fuzz:run-target "known-hosts" path)
                         '(:accepted :rejected))))
      (ignore-errors (delete-file path)))))

(define-test config-fuzz-tolerates-invalid-utf-8
  :parent (:ssh/tests ssh/tests)
  (let ((path (merge-pathnames (format nil "cl-ssh-fuzz-config-~A" (gensym))
                               (uiop:temporary-directory))))
    (unwind-protect
         (progn
           (with-open-file (stream path
                                   :direction :output
                                   :if-exists :supersede
                                   :if-does-not-exist :create
                                   :element-type '(unsigned-byte 8))
             (write-byte #xa0 stream))
           (is eq :accepted (ssh/fuzz:run-target "config" path)))
      (ignore-errors (delete-file path)))))

(define-test private-key-fuzz-rejects-invalid-utf-8
  :parent (:ssh/tests ssh/tests)
  (let ((path (merge-pathnames (format nil "cl-ssh-fuzz-private-key-~A" (gensym))
                               (uiop:temporary-directory))))
    (unwind-protect
         (progn
           (with-open-file (stream path
                                   :direction :output
                                   :if-exists :supersede
                                   :if-does-not-exist :create
                                   :element-type '(unsigned-byte 8))
             (write-byte #xbb stream))
           (is eq :rejected (ssh/fuzz:run-target "private-key" path)))
      (ignore-errors (delete-file path)))))

(define-test private-key-fuzz-rejects-truncated-base64
  :parent (:ssh/tests ssh/tests)
  (is eq :rejected
      (ssh/fuzz:run-target
       "private-key"
       (asdf:system-relative-pathname :ssh
                                     "fuzz/corpus/private-key/truncated-base64"))))

(define-test zlib-fuzz-corpus-replays-deterministically
  :parent (:ssh/tests ssh/tests)
  (let ((corpus
          (asdf:system-relative-pathname :ssh "fuzz/corpus/zlib/")))
    (dolist (input (directory (merge-pathnames "*" corpus)))
      (when (pathname-name input)
        (true (member (ssh/fuzz:run-target "zlib" input)
                      '(:accepted :rejected)))))
    (is eq :accepted
        (ssh/fuzz:run-target "zlib"
                             (merge-pathnames "valid-history" corpus)))
    (is eq :rejected
        (ssh/fuzz:run-target "zlib"
                             (merge-pathnames "output-limit" corpus)))))
