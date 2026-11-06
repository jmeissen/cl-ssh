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

(defun make-output-buffer ()
  (make-array 128
              :element-type 'octet
              :adjustable t
              :fill-pointer 0))

(defun append-output-octets (output buffer end)
  (dotimes (index end)
    (vector-push-extend (aref buffer index) output)))

(defun drain-output-buffer (output)
  (prog1 (copy-seq output)
    (setf (fill-pointer output) 0)))

(defun make-history-buffer ()
  (make-array +history-size+ :element-type 'octet))

(defun make-previous-positions ()
  (make-array +history-size+
              :element-type '(unsigned-byte 16)
              :initial-element 0))

(defun make-hash-heads ()
  (make-array +hash-table-size+
              :element-type '(unsigned-byte 16)
              :initial-element 0))

(defstruct (deflater (:constructor %make-deflater))
  (history-buffer (make-history-buffer) :type history-buffer)
  (previous-positions
    (make-previous-positions)
    :type position-chain-buffer)
  (hash-heads (make-hash-heads) :type hash-head-buffer)
  (pending-start 0 :type history-index)
  (write-position 0 :type history-index)
  (pending-count 0 :type (integer 0 #.+window-size+))
  (block-open-p nil :type boolean)
  (bit-writer nil :type bit-writer)
  output-buffer
  (write-literal nil :type function)
  (write-length nil :type function)
  (write-distance nil :type function))

(defun start-fixed-block (deflater)
  (let ((writer (deflater-bit-writer deflater)))
    (write-bits +non-final-block+ 1 writer)
    (write-bits +fixed-huffman-block+ 2 writer)
    (setf (deflater-block-open-p deflater) t)))

(defun end-fixed-block (deflater)
  (when (deflater-block-open-p deflater)
    (funcall (deflater-write-literal deflater) 256)
    (setf (deflater-block-open-p deflater) nil)))

(defun emit-empty-fixed-block (deflater)
  (start-fixed-block deflater)
  (end-fixed-block deflater))

(defun make-deflater ()
  (let* ((output (make-output-buffer))
         (writer
           (make-bit-writer
            (lambda (buffer end)
              (append-output-octets output buffer end))))
         (deflater
           (%make-deflater
            :bit-writer writer
            :output-buffer output
            :write-literal
            (make-code-writer *fixed-huffman-codes* writer)
            :write-length
            (make-code-writer *length-codes* writer)
            :write-distance
            (make-code-writer *distance-codes* writer))))
    ;; RFC 1950 CMF/FLG for DEFLATE with a 32 KiB window and default level.
    (write-octet #x78 writer)
    (write-octet #x9C writer)
    (start-fixed-block deflater)
    deflater))

(defun encode-input-range (deflater history start count)
  (update-dictionary history
                     (deflater-hash-heads deflater)
                     (deflater-previous-positions deflater)
                     start
                     count)
  (encode-lz77-range
   history
   (deflater-previous-positions deflater)
   start
   (logand +history-mask+ (+ start count))
   (deflater-write-literal deflater)
   (deflater-write-length deflater)
   (deflater-write-distance deflater)))

(defun encode-pending-input (deflater)
  (let ((count (deflater-pending-count deflater)))
    (when (plusp count)
      (encode-input-range deflater
                          (deflater-history-buffer deflater)
                          (deflater-pending-start deflater)
                          count)
      (setf (deflater-pending-start deflater)
            (deflater-write-position deflater)
            (deflater-pending-count deflater) 0))))

(defun buffer-input (deflater payload)
  (declare (type octet-vector payload))
  (let ((history (deflater-history-buffer deflater))
        (input-offset 0)
        (remaining (length payload))
        (write-position (deflater-write-position deflater))
        (pending-start (deflater-pending-start deflater))
        (pending-count (deflater-pending-count deflater)))
    (loop while (plusp remaining)
          for copy-count =
            (min remaining
                 (- +window-size+ pending-count)
                 (- +history-size+ write-position))
          do (replace history payload
                      :start1 write-position
                      :start2 input-offset
                      :end2 (+ input-offset copy-count))
             (incf input-offset copy-count)
             (decf remaining copy-count)
             (incf pending-count copy-count)
             (setf write-position
                   (logand +history-mask+ (+ write-position copy-count)))
             (when (= pending-count +window-size+)
               (encode-input-range deflater
                                   history
                                   pending-start
                                   pending-count)
               (setf pending-start write-position
                     pending-count 0)))
    (setf (deflater-write-position deflater) write-position
          (deflater-pending-start deflater) pending-start
          (deflater-pending-count deflater) pending-count)))

(defun partial-flush (deflater)
  (when (deflater-block-open-p deflater)
    (encode-pending-input deflater)
    (end-fixed-block deflater)
    ;; RFC 4253 requires at least eight bits from the start of the current
    ;; end-of-block code to the end of the packet. This ten-bit empty fixed
    ;; block provides the required trailing bits without ending the stream.
    (emit-empty-fixed-block deflater))
  (flush-aligned-octets (deflater-bit-writer deflater)))

(defun deflate-packet (deflater payload)
  (when (plusp (length payload))
    (unless (deflater-block-open-p deflater)
      (start-fixed-block deflater))
    (buffer-input deflater payload))
  (partial-flush deflater)
  (drain-output-buffer (deflater-output-buffer deflater)))
