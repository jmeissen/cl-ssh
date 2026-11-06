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

(deftype octet ()
  '(unsigned-byte 8))

(deftype octet-vector ()
  '(simple-array (unsigned-byte 8) (*)))

(deftype history-index ()
  '(unsigned-byte 16))

(deftype history-buffer ()
  `(simple-array (unsigned-byte 8) (,+history-size+)))

(deftype position-chain-buffer ()
  `(simple-array (unsigned-byte 16) (,+history-size+)))

(deftype hash-head-buffer ()
  `(simple-array (unsigned-byte 16) (,+hash-table-size+)))

(deftype hash-index ()
  `(integer 0 ,+hash-table-size+))

(deftype bit-writer-buffer ()
  `(simple-array (unsigned-byte 8) (,+bit-writer-buffer-size+)))

(deftype bit-writer-bit-count ()
  `(integer 0 ,+bit-writer-buffer-bits+))
