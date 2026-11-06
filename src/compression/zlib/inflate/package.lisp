;;;; This SSH zlib inflater is derived from 3bz by Bart Botta.
;;;; See ORIGIN.md for the upstream source, revision, and license.

(defpackage #:ssh/compression/zlib/inflate
  (:use :cl)
  (:import-from #:nibbles
                #:ub16ref/le
                #:ub32ref/le
                #:ub64ref/le)
  (:export
   #:make-inflater
   #:inflate-chunk))
