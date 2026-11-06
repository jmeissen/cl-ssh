;;;; SSH payload compression — RFC 4253 section 6.2.

(uiop:define-package ssh/compression
  (:use #:cl)
  (:import-from #:ssh/constants
                #:+compression-none+
                #:+compression-zlib+
                #:+compression-zlib-openssh+)
  (:import-from #:ssh/compression/zlib/deflate
                #:make-deflater
                #:deflate-packet)
  (:import-from #:ssh/compression/zlib/inflate
                #:make-inflater
                #:inflate-chunk)
  (:export
   #:+maximum-uncompressed-payload-length+
   #:compression-error
   #:compression-error-message
   #:make-compressor
   #:make-decompressor
   #:compress-payload
   #:decompress-payload
   #:compressor-algorithm
   #:decompressor-algorithm))

(in-package #:ssh/compression)

(defconstant +maximum-uncompressed-payload-length+ 35000
  "Maximum decompressed SSH payload accepted by this implementation.")

(define-condition compression-error (error)
  ((message :initarg :message :reader compression-error-message))
  (:report (lambda (condition stream)
             (format stream "SSH compression error: ~A"
                     (compression-error-message condition)))))

(defstruct (compressor (:constructor %make-compressor))
  algorithm
  engine)

(defstruct (decompressor (:constructor %make-decompressor))
  algorithm
  engine)

(defun zlib-compression-p (algorithm)
  (or (string= algorithm +compression-zlib+)
      (string= algorithm +compression-zlib-openssh+)))

(defun make-compressor (algorithm)
  "Create a fresh outbound compression context for ALGORITHM.
ALGORITHM is a supported SSH compression algorithm name.
Returns a stateful compressor context."
  (cond
    ((string= algorithm +compression-none+)
     (%make-compressor :algorithm algorithm))
    ((zlib-compression-p algorithm)
     (%make-compressor
      :algorithm algorithm
      :engine (make-deflater)))
    (t
     (error 'compression-error
            :message (format nil "unsupported compression algorithm: ~S"
                             algorithm)))))

(defun make-decompressor (algorithm)
  "Create a fresh inbound decompression context for ALGORITHM.
ALGORITHM is a supported SSH compression algorithm name.
Returns a stateful decompressor context."
  (cond
    ((string= algorithm +compression-none+)
     (%make-decompressor :algorithm algorithm))
    ((zlib-compression-p algorithm)
     (%make-decompressor
      :algorithm algorithm
      :engine (make-inflater)))
    (t
     (error 'compression-error
            :message (format nil "unsupported decompression algorithm: ~S"
                             algorithm)))))

(defun ensure-payload-length (payload)
  (when (> (length payload) +maximum-uncompressed-payload-length+)
    (error 'compression-error
           :message (format nil "uncompressed payload length ~D exceeds ~D"
                            (length payload)
                            +maximum-uncompressed-payload-length+))))

(defun compress-payload (compressor payload)
  "Compress one SSH packet payload without ending the compression stream.
COMPRESSOR retains RFC 4253 history between packets.
PAYLOAD is an octet vector containing one uncompressed SSH payload.
Returns the compressed payload octets for one SSH packet."
  (cond
    ((string= (compressor-algorithm compressor) +compression-none+)
     payload)
    ((zlib-compression-p (compressor-algorithm compressor))
     (ensure-payload-length payload)
     (handler-case
         (deflate-packet (compressor-engine compressor) payload)
       (error (condition)
         (error 'compression-error
                :message (format nil "zlib compression failed: ~A" condition)))))
    (t
     (error 'compression-error
            :message "invalid compressor state"))))

(defun decompress-zlib-payload (decompressor payload)
  (handler-case
      (multiple-value-bind (result status)
          (inflate-chunk
           (decompressor-engine decompressor)
           payload
           :maximum-output-length +maximum-uncompressed-payload-length+)
        (ecase status
          (:needs-input result)
          (:finished
           (error 'compression-error
                  :message "peer terminated the SSH zlib stream"))))
    (compression-error (condition)
      (error condition))
    (error (condition)
      (error 'compression-error
             :message (format nil "zlib decompression failed: ~A" condition)))))

(defun decompress-payload (decompressor payload)
  "Decompress one authenticated SSH packet payload.
DECOMPRESSOR retains RFC 4253 history between packets.
PAYLOAD is an octet vector containing one compressed SSH payload.
Returns the uncompressed SSH payload octets."
  (cond
    ((string= (decompressor-algorithm decompressor) +compression-none+)
     payload)
    ((zlib-compression-p (decompressor-algorithm decompressor))
     (decompress-zlib-payload decompressor payload))
    (t
     (error 'compression-error
            :message "invalid decompressor state"))))
