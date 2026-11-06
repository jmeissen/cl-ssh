;;;; Streaming zlib deflater regression tests.

(defpackage #:ssh/tests/zlib-deflate
  (:use #:cl #:parachute)
  (:import-from #:ssh/compression/zlib/deflate
                #:make-deflater
                #:deflate-packet)
  (:import-from #:ssh/compression
                #:make-decompressor
                #:decompress-payload)
  (:import-from #:ssh/constants
                #:+compression-zlib+))

(in-package #:ssh/tests/zlib-deflate)

(defun repeated-octets (length byte)
  (make-array length
              :element-type '(unsigned-byte 8)
              :initial-element byte))

(defun deterministic-octets (length &optional (seed 1))
  (let ((result (make-array length :element-type '(unsigned-byte 8)))
        (state seed))
    (dotimes (index length result)
      (setf state (ldb (byte 32 0)
                       (+ (* state 1103515245) 12345))
            (aref result index) (ldb (byte 8 16) state)))))

(defparameter +salza2-partial-flush-64-fixture+
  (make-array
   71
   :element-type '(unsigned-byte 8)
   :initial-contents
   '(120 156 58 86 215 152 237 253 251 209 239 144 111 123 239 215 200
     60 108 103 220 111 120 47 172 136 223 61 61 173 61 114 85 135 77
     228 171 48 225 234 75 173 11 111 216 132 132 234 155 175 75 141
     190 197 84 57 227 204 99 169 178 190 248 155 51 251 229 237 205 0
     2)))

;; Captured from the installed Salza2 encoder before removing the dependency.
(define-test vendored-deflater-matches-salza2-compressed-data-fixture
  :parent (:ssh/tests ssh/tests)
  (let* ((payload (deterministic-octets 64))
         (fragment (deflate-packet (make-deflater) payload)))
    (is equalp +salza2-partial-flush-64-fixture+ fragment)
    (is equalp payload
        (decompress-payload (make-decompressor +compression-zlib+) fragment))))

;; Adapted from Salza2's partial-flush regression tests. These short packets
;; exercise every bit alignment reached by consecutive RFC 4253 packet flushes.
(define-test vendored-deflater-matches-salza2-partial-flush-fixture
  :parent (:ssh/tests ssh/tests)
  (let ((deflater (make-deflater))
        (decompressor (make-decompressor +compression-zlib+))
        (payload (repeated-octets 1 200))
        (expected-fragments
          '((120 156 58 1 16)
            (64 39 0 2)
            (232 4 64)
            (0 157 0 8)
            (160 19 0 1)
            (116 2 32)
            (128 78 0 4)
            (208 9 128 0))))
    (dolist (expected expected-fragments)
      (let ((fragment (deflate-packet deflater payload)))
        (is equalp (coerce expected 'vector) fragment)
        (is equalp payload (decompress-payload decompressor fragment))))))

;; Adapted from Salza2's dictionary-preservation regression test. A repeated
;; random-looking packet only shrinks on the second pass if history survives
;; the partial flush between SSH packets.
(define-test zlib-partial-flush-preserves-the-dictionary
  :parent (:ssh/tests ssh/tests)
  (let* ((payload (deterministic-octets 4096 7))
         (deflater (make-deflater))
         (decompressor (make-decompressor +compression-zlib+))
         (first-fragment (deflate-packet deflater payload))
         (second-fragment (deflate-packet deflater payload))
         (fresh-fragment (deflate-packet (make-deflater) payload)))
    (is equalp payload (decompress-payload decompressor first-fragment))
    (is equalp payload (decompress-payload decompressor second-fragment))
    (is < (length fresh-fragment) (length second-fragment))))
