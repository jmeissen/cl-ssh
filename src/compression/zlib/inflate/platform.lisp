;;;; Derived from 3bz; see ORIGIN.md for provenance and license.
(in-package #:ssh/compression/zlib/inflate)

;; Keep offsets within a range where the arithmetic used by the decoder stays
;; efficient.
(deftype size-t ()
  '(unsigned-byte
    #.(let ((fixnum-bits (integer-length most-positive-fixnum)))
        (if (> fixnum-bits 32)
            (min 60 (1- fixnum-bits))
            (min 30 fixnum-bits)))))

;; Slightly larger so incrementing a SIZE-T still fits.
(deftype offset-t ()
  '(unsigned-byte
    #.(let ((fixnum-bits (integer-length most-positive-fixnum)))
        (if (> fixnum-bits 32)
            (min 61 fixnum-bits)
            (min 31 fixnum-bits)))))

;;; some tuning parameters, and functions used in #+#.(...) to control
;;; features used by code

;;; A fixnum reservoir avoids boxing at state, closure, and
;;; multiple-value boundaries. The largest combined DEFLATE read is 55
;;; bits, so retain the old wide-integer path on implementations whose
;;; positive fixnums cannot hold that value.
(defun use-fixnum-bit-buffer ()
  '#.(if (>= (integer-length most-positive-fixnum) 55)
         '(:and)
         '(:or)))

(defconstant +bit-buffer-bits+
  (if (>= (integer-length most-positive-fixnum) 55)
      (integer-length most-positive-fixnum)
      64))

(deftype bit-buffer ()
  '#.(if (>= (integer-length most-positive-fixnum) 55)
         'non-negative-fixnum
         '(unsigned-byte 64)))

;;; similarly, adler32 checksum accumulates as many bytes as possible
;;; before doing mod, so we can either use :ub64, :ub32 or :fixnum
;;; versions of adler32 code depending on which is fastest
(defun use-adler32 (version)
  (if (eql version
           ;; ub64 is fastest on 64bit sbcl, and seems better on mezzano too now
           #+ (or mezzano (and sbcl x86-64))
           :ub64
           ;; for now, just using fixnum elsewhere until there are
           ;; proper benchmarks. not sure if ub32 is faster than
           ;; fixnum anywhere, or if fixnum is good enough
           #- (or mezzano abcl (and sbcl x86-64))
           :fixnum
           #+ abcl
           :ub32
           )
      '(:and)
      '(:or)))
;;; adler32 checksum is unrolled a bit to reduce loop overhead, this
;;; specifies how many iterations to unroll
;; todo: set this for more combinations of cpu/implementation once
;; there are benchmarks
(defconstant +adler32-unroll+
  #+mezzano 16
  #+sbcl 32
  #- (or sbcl mezzano) 8)

(deftype ub16 () '(unsigned-byte 16))
(deftype ub32 () '(unsigned-byte 32))
(deftype ub64 () '(unsigned-byte 64))

;; Mezzano likes (INTEGER 0 MOST-POSITIVE-FIXNUM) better than
;; (AND FIXNUM UNSIGNED-BYTE).
(deftype non-negative-fixnum () `(integer 0 ,most-positive-fixnum))
