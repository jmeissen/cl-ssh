;;;; This encoder is derived from Salza2 by Zachary Beane and contributors.
;;;; See ORIGIN.md and LICENSE.txt for provenance and license details.

;;;
;;; Copyright (c) 2007 Zachary Beane, All Rights Reserved
;;;
;;; Redistribution and use in source and binary forms, with or without
;;; modification, are permitted provided that the following conditions
;;; are met:
;;;
;;;   * Redistributions of source code must retain the above copyright
;;;     notice, this list of conditions and the following disclaimer.
;;;
;;;   * Redistributions in binary form must reproduce the above
;;;     copyright notice, this list of conditions and the following
;;;     disclaimer in the documentation and/or other materials
;;;     provided with the distribution.
;;;
;;; THIS SOFTWARE IS PROVIDED BY THE AUTHOR 'AS IS' AND ANY EXPRESSED
;;; OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
;;; WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
;;; ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
;;; DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
;;; DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
;;; GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
;;; INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
;;; WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
;;; NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
;;; SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;;;

(in-package #:ssh/compression/zlib/deflate)

(defun hash-value (history position)
  (+ (* #.+rolling-hash-factor+ (aref history position))
     (* #.+rolling-hash-radix+ (aref history (logand #.+history-mask+ (+ position 1))))
     (aref history (logand #.+history-mask+ (+ position 2)))))

(declaim (inline reduce-hash))
(defun reduce-hash (z)
  (declare (type (integer 0 3057705) z))
  (let ((zz (+ (ash z -13) (logand #x1FFF z))))
    (if (< zz #x1FFF)
        zz
        (- zz #x1FFF))))

(defun update-dictionary (history hash-heads previous-positions start count)
  (declare (type history-buffer history)
           (type hash-head-buffer hash-heads)
           (type position-chain-buffer previous-positions)
           (type history-index start)
           (type (integer 0 #.+window-size+) count)
           (optimize speed))
  (when (< count 3)
    (return-from update-dictionary))
  (let* ((hash (hash-value history start))
         (p0 start)
         (p1 (logand (+ start 2) #.+history-mask+)))
    (declare (type (integer 0 3057705) hash))
    (loop
     (let ((hash-index (reduce-hash hash)))
       ;; Stuff the old hash index into previous-positions at p0
       (setf (aref previous-positions p0) (aref hash-heads hash-index))
       ;; Stuff p0 into the hash-heads
       (setf (aref hash-heads hash-index) p0)
       ;; Tentatively advance; if we hit the end, don't do the rest of
       ;; the hash update
       (setf p1 (logand (1+ p1) #.+history-mask+))
       (decf count)
       (when (= count 2)
         (return))
       ;; We're not at the end, so lop off the high, shift left, and
       ;; add the low to form a new hash value
       (setf hash (- hash (* (aref history p0) #.+rolling-hash-factor+)))
       (setf hash (* hash #.+rolling-hash-radix+))
       (setf p0 (logand (1+ p0) #.+history-mask+))
       (setf hash (+ hash (aref history p1)))))))


(defconstant +maximum-match-length+ 258
  "The maximum match length allowed.")

(defconstant +maximum-match-distance+ 32768
  "The maximum distance for a match.")

(declaim (inline match-length))
(defun match-length (p1 p2 history end)
  "Returns the length of the match between positions p1 and p2 in
HISTORY; END is a sentinel position that ends the match length
check if reached."
  (declare (type history-index p1 p2 end)
           (type history-buffer history)
           (optimize speed))
  (let ((length 0))
    (loop
     (when (or (/= (aref history p1) (aref history p2))
               (= length +maximum-match-length+)
               (= p1 end))
       (return length))
     (setf p1 (logand (1+ p1) #.+history-mask+)
           p2 (logand (1+ p2) #.+history-mask+)
           length (logand #xFFF (1+ length))))))

(defun longest-match (p1 history previous-positions end max-tests)
  (declare (type history-index p1 end)
           (type history-buffer history)
           (type position-chain-buffer previous-positions)
           (type (integer 0 32) max-tests)
           (optimize speed))
  (let ((match-length 0)
        (p2 (aref previous-positions p1))
        (test-count 0)
        (distance 0))
    (declare (type (integer 0 258) match-length)
             (type (integer 0 32) test-count))
    (loop
     (when (or (= match-length +maximum-match-length+)
               (= test-count max-tests)
               (= p2 p1)
               (= p2 (aref previous-positions p2)))
       (return (values match-length distance)))
     (let ((step (logand (- p1 p2) #.+history-mask+)))
       (when (< +maximum-match-distance+ step)
         (return (values match-length distance)))
       (let ((possible-length (match-length p1 p2 history end)))
         (when (and (< 2 possible-length)
                    (< match-length possible-length))
           (setf distance step
                 match-length possible-length))
         (setf p2 (aref previous-positions p2)))
       (incf test-count)))))



(defun encode-lz77-range (history previous-positions start end
                          literal-fun length-fun distance-fun)
  (declare (type history-buffer history)
           (type position-chain-buffer previous-positions)
           (type history-index start end)
           (type function literal-fun length-fun distance-fun)
           (optimize speed))
  (let ((p start))
    (loop
     (when (= p end)
       (return))
     (multiple-value-bind (length distance)
         (longest-match p history previous-positions end 4)
       (declare (type (integer 0 258) length)
                (type (integer 0 #.+window-size+) distance))
       (cond ((zerop length)
              (funcall literal-fun (aref history p))
              (setf p (logand (+ p 1) #.+history-mask+)))
             (t
              (funcall length-fun length)
              (funcall distance-fun distance)
              (setf p (logand (+ p length) #.+history-mask+))))))))
