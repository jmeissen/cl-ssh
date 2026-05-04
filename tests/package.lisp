;;;; Test suite root package and root test.
;;;;
;;;; Child test files specify :parent (:ssh/tests ssh/tests) which makes
;;;; Parachute look up the test named "SSH/TESTS" in the SSH/TESTS package,
;;;; i.e. the root suite defined here.

(defpackage :ssh/tests
  (:use :cl :parachute)
  (:export #:octets))

(in-package :ssh/tests)

(defun octets (&rest bytes)
  "Return a simple octet vector from BYTES."
  (coerce bytes '(vector (unsigned-byte 8))))

;;; Root test suite — children reference this via :parent (:ssh/tests ssh/tests)
(define-test ssh/tests)
