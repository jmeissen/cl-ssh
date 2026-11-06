;;;; Zlib decoder regression tests adapted from 3bz tests/core.lisp.
;;;; Original 3bz code is by Bart Botta and distributed under the MIT license.

(defpackage #:ssh/tests/zlib-inflate
  (:use #:cl #:parachute)
  (:import-from #:ssh/compression/zlib/inflate
                #:make-inflater
                #:inflate-chunk))

(in-package #:ssh/tests/zlib-inflate)

(defun octets-from-string (string)
  (let ((result (make-array (length string)
                            :element-type '(unsigned-byte 8))))
    (loop for character across string
          for index from 0
          do (setf (aref result index) (char-code character)))
    result))

(defun as-octets (sequence)
  (coerce sequence '(simple-array (unsigned-byte 8) (*))))

(defparameter +payload+
  (octets-from-string
   (concatenate
    'string
    "The quick brown fox jumps over the lazy dog. "
    "The quick brown fox jumps over the lazy dog. "
    "The quick brown fox jumps over the lazy dog. "
    "The quick brown fox jumps over the lazy dog. ")))

(defparameter +zlib+
  (as-octets
   #(#x78 #x9c #x0b #xc9 #x48 #x55 #x28 #x2c #xcd #x4c #xce #x56 #x48
     #x2a #xca #x2f #xcf #x53 #x48 #xcb #xaf #x50 #xc8 #x2a #xcd #x2d
     #x28 #x56 #xc8 #x2f #x4b #x2d #x52 #x28 #x01 #x4a #xe7 #x24 #x56
     #x55 #x2a #xa4 #xe4 #xa7 #xeb #x29 #x84 #x0c #x0e #xc5 #x00 #xfa
     #x60 #x40 #x9d)))

;; Independently produced zlib fixtures covering DEFLATE block types that the
;; fixed-Huffman SSH encoder does not normally generate itself.
(defparameter +stored-payload+ (octets-from-string "stored block payload"))

(defparameter +stored-zlib+
  (as-octets
   #(120 1 1 20 0 235 255 115 116 111 114 101 100 32 98 108 111 99 107
     32 112 97 121 108 111 97 100 82 62 7 199)))

(defparameter +dynamic-payload+
  (octets-from-string
   (with-output-to-string (stream)
     (loop repeat 100
           do
       (write-string "The quick brown fox jumps over the lazy dog. " stream)))))

(defparameter +dynamic-zlib+
  (as-octets
   #(120 156 237 202 71 1 128 48 16 69 65 43 95 1 106 98 128 178 16 234
     66 32 52 245 152 224 248 230 60 33 154 182 220 215 163 170 228 215
     162 214 111 13 121 94 119 249 105 73 71 52 77 229 251 168 241 174
     80 32 147 201 100 50 153 76 38 147 201 100 50 153 76 38 255 145
     63 29 200 79 151)))

;; Produced from one zlib stream with Z_PARTIAL_FLUSH after the first two
;; payloads and Z_FINISH after the third.
(defparameter +rfc4253-zlib-packets+
  (list
   (as-octets
    #(#x78 #x9c #x0a #x0e #xf6 #x50 #x28 #x48 #x4c #xce #x4e #x2d #x51
      #xc8 #xcf #x4b #xb5 #x52 #xc8 #x48 #xcd #xc9 #xc9 #x57 #x48 #x2b
      #xca #xcf #x55 #x08 #x72 #x73 #x56 #x30 #x31 #x32 #x35 #xd6 #x53
      #x00 #x08))
   (as-octets
    #(#xa0 #x60 #x84 #xa2 #x92 #xf2 #x7c #x85 #xa2 #xd4 #xd2 #xe2 #xd4
      #x62 #x85 #x92 #x8c #x54 #x85 #xe4 #xfc #xdc #x82 #xa2 #xd4 #xe2
      #xe2 #xcc #xfc #x3c #x85 #x8c #xcc #xe2 #x92 #xfc #xa2 #x4a #x3d
      #x05 #x80 #x00))
   (as-octets
    #(#x43 #x56 #x9e #x51 #x94 #x0a #x54 #x95 #x93 #x0f #xd3 #x90 #x96
      #x59 #x51 #x52 #x5a #x94 #xaa #x07 #x00 #x97 #x5d #x29 #xe9))))

(defparameter +rfc4253-payload+
  (octets-from-string
   (concatenate
    'string
    "SSH packet one: hello from RFC 4253. "
    "SSH packet two reuses the compression history. "
    "SSH packet three closes the fixture.")))

(defun partition-vector (vector sizes)
  (loop with offset = 0
        with size-index = 0
        while (< offset (length vector))
        for size = (elt sizes (mod size-index (length sizes)))
        for end = (min (length vector) (+ offset size))
        collect (subseq vector offset end)
        do (setf offset end)
           (incf size-index)))

(defun zlib-fixtures ()
  (list (list +zlib+ +payload+)
        (list +stored-zlib+ +stored-payload+)
        (list +dynamic-zlib+ +dynamic-payload+)))

;; Independently generated zlib streams whose repeated prefixes exercise
;; DEFLATE history distances one through seven.
(defparameter +short-history-distance-zlib+
  (mapcar
   #'as-octets
   '(#(120 218 115 116 164 46 0 0 55 37 20 81)
     #(120 218 115 116 114 28 212 16 0 224 164 40 241)
     #(120 218 115 116 114 118 28 73 8 0 33 243 61 225)
     #(120 218 115 116 114 118 113 28 197 100 99 0 32 76 83 33)
     #(120 218 115 116 114 118 113 117 28 37 6 11 1 0 1 22 104 177)
     #(120 218 115 116 114 118 113 117 115 28 37 135 41 9 0 233 154 126
       145)
     #(120 218 115 116 114 118 113 117 115 119 28 165 70 41 98 40 0 255
       78 148 193))))

(defun short-history-distance-payload (distance)
  (let ((payload (make-array (* distance 80)
                             :element-type '(unsigned-byte 8))))
    (loop for index below (length payload)
          do (setf (aref payload index)
                   (+ (char-code #\A) (mod index distance))))
    payload))

(defun decode-pieces (pieces expected-size &key (output-buffer-size 4096))
  (let ((inflater (make-inflater :output-buffer-size output-buffer-size))
        (parts nil))
    (loop for remaining on pieces
          for piece = (first remaining)
          for lastp = (null (rest remaining))
          do (multiple-value-bind (output status)
                 (inflate-chunk inflater piece)
               (push output parts)
               (if lastp
                   (is eq :finished status)
                   (is eq :needs-input status))))
    (let ((output
            (apply #'concatenate
                   '(simple-array (unsigned-byte 8) (*))
                   (nreverse parts))))
      (is = expected-size (length output))
      output)))

(define-test zlib-inflater-decodes-complete-stream
  :parent (:ssh/tests ssh/tests)
  (is equalp +payload+ (decode-pieces (list +zlib+) (length +payload+))))

(define-test zlib-inflater-decodes-stored-and-dynamic-blocks
  :parent (:ssh/tests ssh/tests)
  (is equalp +stored-payload+
      (decode-pieces (list +stored-zlib+) (length +stored-payload+)))
  (is equalp +dynamic-payload+
      (decode-pieces (list +dynamic-zlib+) (length +dynamic-payload+))))

(define-test zlib-inflater-resumes-after-arbitrary-input-chunks
  :parent (:ssh/tests ssh/tests)
  (is equalp +payload+
      (decode-pieces (partition-vector +zlib+ #(1 3 2 7 4))
                     (length +payload+))))

(define-test zlib-inflater-handles-rfc4253-partial-flush-boundaries
  :parent (:ssh/tests ssh/tests)
  (is equalp +rfc4253-payload+
      (decode-pieces +rfc4253-zlib-packets+
                     (length +rfc4253-payload+))))

(define-test zlib-inflater-rotates-small-output-buffers
  :parent (:ssh/tests ssh/tests)
  (is equalp +payload+
      (decode-pieces (list +zlib+)
                     (length +payload+)
                     :output-buffer-size 17)))

(define-test zlib-inflater-decodes-at-every-input-split
  :parent (:ssh/tests ssh/tests)
  (dolist (fixture (zlib-fixtures))
    (destructuring-bind (compressed expected) fixture
      ;; Include a leading empty chunk, but not a trailing one: the complete
      ;; stream correctly reports :FINISHED as soon as it is consumed.
      (loop for split below (length compressed)
            do (is equalp expected
                   (decode-pieces
                    (list (subseq compressed 0 split)
                          (subseq compressed split))
                    (length expected)))))))

(define-test zlib-inflater-decodes-byte-at-a-time
  :parent (:ssh/tests ssh/tests)
  (dolist (fixture (zlib-fixtures))
    (destructuring-bind (compressed expected) fixture
      (is equalp expected
          (decode-pieces (partition-vector compressed #(1))
                         (length expected))))))

(define-test zlib-inflater-handles-word-boundary-output-buffers
  :parent (:ssh/tests ssh/tests)
  (dolist (output-buffer-size '(1 2 3 4 7 8 15 16 17 31 32 33 63 64 65))
    (is equalp +payload+
        (decode-pieces (list +zlib+)
                       (length +payload+)
                       :output-buffer-size output-buffer-size))))

(define-test zlib-inflater-expands-short-history-distances
  :parent (:ssh/tests ssh/tests)
  (loop for compressed in +short-history-distance-zlib+
        for distance from 1
        for expected = (short-history-distance-payload distance)
        do (is equalp expected
               (decode-pieces (list compressed) (length expected)))))

(define-test zlib-inflater-reports-truncated-streams-as-needing-input
  :parent (:ssh/tests ssh/tests)
  (dolist (fixture (zlib-fixtures))
    (let ((compressed (first fixture)))
      (loop for end below (length compressed)
            do (multiple-value-bind (output status)
                   (inflate-chunk (make-inflater) (subseq compressed 0 end))
                 (declare (ignore output))
                 (is eq :needs-input status))))))

(define-test zlib-inflater-rejects-an-invalid-adler32
  :parent (:ssh/tests ssh/tests)
  (let ((corrupted (copy-seq +zlib+)))
    (setf (aref corrupted (1- (length corrupted)))
          (logxor 1 (aref corrupted (1- (length corrupted)))))
    (fail (inflate-chunk (make-inflater) corrupted) 'error)))
