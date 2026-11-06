;;;; Developer-only fuzz target package.

(uiop:define-package ssh/fuzz
  (:use #:cl)
  (:export #:run-target
           #:replay-corpus
           #:main
           #:target-names))

(in-package #:ssh/fuzz)
