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

(defun missing-output-callback (&rest arguments)
  (declare (ignore arguments))
  (error "No output callback was supplied to the DEFLATE bit writer"))

(defun merge-bits (code size buffer bit-count callback)
  (declare (type (unsigned-byte 32) code)
           (type (integer 0 32) size)
           (type bit-writer-bit-count bit-count)
           (type bit-writer-buffer buffer)
           (type function callback)
           (optimize speed))
  (let ((buffer-index (ash bit-count -3))
        (bit-offset (logand #b111 bit-count)))
    (let ((merge-byte
            (if (plusp bit-offset)
                (aref buffer buffer-index)
                0))
          (end #.+bit-writer-buffer-size+)
          (result (+ bit-count size)))
      (dotimes (index (ceiling (+ bit-offset size) 8))
        (let ((shift (+ bit-offset (* index -8)))
              (output-index (+ buffer-index index)))
          (when (= output-index end)
            (funcall callback buffer output-index))
          (setf (aref buffer
                      (logand #.+bit-writer-buffer-mask+ output-index))
                (logior (logand #xFF (ash code shift))
                        merge-byte))
          (setf merge-byte 0)))
      (when (= result #.+bit-writer-buffer-bits+)
        (funcall callback buffer #.+bit-writer-buffer-size+))
      (logand #.+bit-writer-buffer-bitmask+ result))))

(defun merge-octet (octet buffer bit-count callback)
  (declare (type octet octet)
           (type bit-writer-buffer buffer)
           (type bit-writer-bit-count bit-count)
           (type function callback)
           (optimize speed))
  (let ((offset (ceiling bit-count 8)))
    (when (= offset #.+bit-writer-buffer-size+)
      (funcall callback buffer #.+bit-writer-buffer-size+)
      (setf offset 0
            bit-count 0))
    (setf (aref buffer offset) octet
          bit-count (+ bit-count 8))
    (when (= (1+ offset) #.+bit-writer-buffer-size+)
      (funcall callback buffer #.+bit-writer-buffer-size+)
      (setf bit-count 0))
    bit-count))

(defstruct (bit-writer (:constructor %make-bit-writer))
  (buffer
    (make-array +bit-writer-buffer-size+ :element-type 'octet)
    :type bit-writer-buffer)
  (bit-count 0 :type bit-writer-bit-count)
  (callback #'missing-output-callback :type function))

(defun make-bit-writer (callback)
  (%make-bit-writer :callback callback))

(defun write-bits (code size writer)
  (setf (bit-writer-bit-count writer)
        (merge-bits code
                    size
                    (bit-writer-buffer writer)
                    (bit-writer-bit-count writer)
                    (bit-writer-callback writer))))

(defun write-octet (octet writer)
  (setf (bit-writer-bit-count writer)
        (merge-octet octet
                     (bit-writer-buffer writer)
                     (bit-writer-bit-count writer)
                     (bit-writer-callback writer))))

(defun flush-aligned-octets (writer)
  (multiple-value-bind (end remaining-bits)
      (floor (bit-writer-bit-count writer) 8)
    (let* ((buffer (bit-writer-buffer writer))
           (partial-octet
             (when (plusp remaining-bits)
               (logand (1- (ash 1 remaining-bits))
                       (aref buffer end)))))
      (when (plusp end)
        (funcall (bit-writer-callback writer) buffer end))
      (when partial-octet
        (setf (aref buffer 0) partial-octet))
      (setf (bit-writer-bit-count writer) remaining-bits))))
