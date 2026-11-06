;;;; This encoder is derived from Salza2 by Zachary Beane and contributors.
;;;; See ORIGIN.md and LICENSE.txt for provenance and license details.

(defpackage #:ssh/compression/zlib/deflate
  (:use #:cl)
  (:export
   #:make-deflater
   #:deflate-packet))

(in-package #:ssh/compression/zlib/deflate)
