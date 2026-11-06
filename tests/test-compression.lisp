;;;; RFC 4253 payload compression tests.

(defpackage :ssh/tests/compression
  (:use :cl :parachute)
  (:import-from :ssh/compression
                #:+maximum-uncompressed-payload-length+
                #:compression-error
                #:make-compressor
                #:make-decompressor
                #:compress-payload
                #:decompress-payload
                #:compressor-algorithm
                #:decompressor-algorithm)
  (:import-from :ssh/constants
                #:+compression-none+
                #:+compression-zlib+
                #:+compression-zlib-openssh+))

(in-package :ssh/tests/compression)

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

(defun raw-zlib-fragment (payload)
  (ssh/compression/zlib/deflate:deflate-packet
   (ssh/compression/zlib/deflate:make-deflater)
   payload))

(defparameter +salza2-finished-64-fixture+
  (make-array
   76
   :element-type '(unsigned-byte 8)
   :initial-contents
   '(120 156 58 86 215 152 237 253 251 209 239 144 111 123 239 215 200
     60 108 103 220 111 120 47 172 136 223 61 61 173 61 114 85 135 77
     228 171 48 225 234 75 173 11 111 216 132 132 234 155 175 75 141
     190 197 84 57 227 204 99 169 178 190 248 155 51 251 229 237 205 0
     3 0 67 77 31 160)))

(define-test none-compression-is-an-identity
  :parent (:ssh/tests ssh/tests)
  (let* ((payload (deterministic-octets 257))
         (compressor (make-compressor +compression-none+))
         (decompressor (make-decompressor +compression-none+)))
    (is string= +compression-none+ (compressor-algorithm compressor))
    (is string= +compression-none+ (decompressor-algorithm decompressor))
    (is equalp payload (compress-payload compressor payload))
    (is equalp payload (decompress-payload decompressor payload))))

(define-test zlib-roundtrips-multiple-packets-with-shared-history
  :parent (:ssh/tests ssh/tests)
  (let* ((compressor (make-compressor +compression-zlib+))
         (decompressor (make-decompressor +compression-zlib+))
         (first (repeated-octets 10000 65))
         (second (repeated-octets 10000 65))
         (first-fragment (compress-payload compressor first))
         (first-result (decompress-payload decompressor first-fragment))
         (second-fragment (compress-payload compressor second))
         (second-result (decompress-payload decompressor second-fragment)))
    (is string= +compression-zlib+ (compressor-algorithm compressor))
    (is string= +compression-zlib+ (decompressor-algorithm decompressor))
    (is equalp first first-result)
    (is equalp second second-result)
    ;; The first fragment contains the zlib header. A later fragment is part of
    ;; the same stream and therefore cannot be decoded by a fresh inflater.
    (fail (decompress-payload (make-decompressor +compression-zlib+)
                              second-fragment)
        'compression-error)))

(define-test openssh-delayed-zlib-uses-the-same-stateful-codec
  :parent (:ssh/tests ssh/tests)
  (let* ((payload (repeated-octets 4096 65))
         (compressor (make-compressor +compression-zlib-openssh+))
         (decompressor (make-decompressor +compression-zlib-openssh+)))
    (is string= +compression-zlib-openssh+
        (compressor-algorithm compressor))
    (is equalp payload
        (decompress-payload decompressor
                            (compress-payload compressor payload)))))

(define-test zlib-inflater-rotates-output-buffers
  :parent (:ssh/tests ssh/tests)
  (let* ((payload (deterministic-octets 32768))
         (compressor (make-compressor +compression-zlib+))
         (decompressor (make-decompressor +compression-zlib+))
         (following-payload (make-array 3
                                        :element-type '(unsigned-byte 8)
                                        :initial-contents '(123 45 67))))
    (is equalp payload
        (decompress-payload decompressor
                            (compress-payload compressor payload)))
    (is equalp following-payload
        (decompress-payload decompressor
                            (compress-payload compressor
                                              following-payload)))))

(define-test zlib-accepts-a-full-channel-data-packet
  :parent (:ssh/tests ssh/tests)
  ;; A 32 KiB channel data string has nine SSH message-field octets around it.
  ;; RFC 4253 requires 32 KiB support but does not require rejecting larger
  ;; payloads, and the existing connection layer legitimately emits this size.
  (let* ((payload (deterministic-octets (+ 32768 9)))
         (compressor (make-compressor +compression-zlib+))
         (decompressor (make-decompressor +compression-zlib+)))
    (is equalp payload
        (decompress-payload decompressor
                            (compress-payload compressor payload)))))

(define-test fresh-context-after-rekey-starts-a-new-zlib-stream
  :parent (:ssh/tests ssh/tests)
  (let* ((payload (deterministic-octets 4096))
         (first-compressor (make-compressor +compression-zlib+))
         (second-compressor (make-compressor +compression-zlib+))
         (first-fragment (compress-payload first-compressor payload))
         (second-fragment (compress-payload second-compressor payload)))
    (is equalp first-fragment second-fragment)
    (is equalp payload
        (decompress-payload (make-decompressor +compression-zlib+)
                            first-fragment))
    (is equalp payload
        (decompress-payload (make-decompressor +compression-zlib+)
                            second-fragment))))

(define-test compression-enforces-uncompressed-payload-limit
  :parent (:ssh/tests ssh/tests)
  (let ((oversized
          (repeated-octets (1+ +maximum-uncompressed-payload-length+) 65)))
    (fail (compress-payload (make-compressor +compression-zlib+) oversized)
        'compression-error)
    (fail (decompress-payload
           (make-decompressor +compression-zlib+)
           (raw-zlib-fragment oversized))
        'compression-error)))

(define-test malformed-or-terminated-zlib-stream-is-rejected
  :parent (:ssh/tests ssh/tests)
  (fail (decompress-payload (make-decompressor +compression-zlib+)
                            (make-array 2
                                        :element-type '(unsigned-byte 8)
                                        :initial-contents '(0 0)))
      'compression-error)
  (fail (decompress-payload
         (make-decompressor +compression-zlib+)
         +salza2-finished-64-fixture+)
      'compression-error))
