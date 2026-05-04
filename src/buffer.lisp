;;;; SSH binary codec — RFC 4251 data types.
;;;;
;;;; Provides two buffer abstractions:
;;;;   write-buffer  — append-only, for building outgoing payloads
;;;;   read-buffer   — position-tracked, for parsing incoming payloads
;;;;
;;;; All multi-byte integers are big-endian as required by the SSH wire format.

(uiop:define-package ssh/buffer
  (:use #:cl)
  (:export
   ;; Conditions
   #:buffer-underflow
   #:buffer-format-error
   ;; Write buffer
   #:make-write-buffer
   #:write-byte*
   #:write-boolean
   #:write-uint32
   #:write-uint64
   #:write-raw-bytes
   #:write-string*
   #:write-mpint
   #:write-name-list
   #:buffer-to-octets
   ;; Read buffer
   #:make-read-buffer
   #:read-byte*
   #:read-boolean
   #:read-uint32
   #:read-uint64
   #:read-raw-bytes
   #:read-string*
   #:read-mpint
   #:read-name-list
   #:read-remaining-bytes
   #:read-buffer-length
   #:read-buffer-pos))

(in-package #:ssh/buffer)

;;;; Conditions

(define-condition buffer-underflow (error)
  ((requested  :initarg :requested  :reader buffer-underflow-requested)
   (available  :initarg :available  :reader buffer-underflow-available))
  (:report (lambda (c s)
             (format s "SSH buffer underflow: requested ~A byte~:P but only ~A available"
                     (buffer-underflow-requested c)
                     (buffer-underflow-available c)))))

(define-condition buffer-format-error (error)
  ((message :initarg :message :reader buffer-format-error-message))
  (:report (lambda (c s)
             (format s "SSH buffer format error: ~A"
                     (buffer-format-error-message c)))))

;;;; Helpers

(defun ascii-to-octets (string)
  "Encode STRING as ASCII octets.  Signals an error on non-ASCII characters."
  (let ((result (make-array (length string) :element-type '(unsigned-byte 8))))
    (dotimes (i (length string) result)
      (let ((code (char-code (char string i))))
        (unless (< code 128)
          (error 'buffer-format-error
                 :message (format nil "non-ASCII character ~S at index ~D" (char string i) i)))
        (setf (aref result i) code)))))

(defun octets-to-ascii (octets)
  "Decode ASCII octets to a string."
  (map 'string #'code-char octets))

;;;; Write buffer

(defstruct (write-buffer (:constructor %make-write-buffer))
  (data (make-array 256 :element-type '(unsigned-byte 8)
                        :adjustable t :fill-pointer 0)
        :type (array (unsigned-byte 8) (*))))

(defun make-write-buffer ()
  "Return a fresh, empty write buffer."
  (%make-write-buffer))

(declaim (inline write-byte*))
(defun write-byte* (buf byte)
  "Append a single octet to BUF."
  (declare (type write-buffer buf)
           (type (unsigned-byte 8) byte))
  (vector-push-extend byte (write-buffer-data buf)))

(defun write-boolean (buf value)
  "Append an SSH boolean (RFC 4251 §5): 0 for false, 1 for true."
  (write-byte* buf (if value 1 0)))

(defun write-uint32 (buf n)
  "Append a 32-bit unsigned integer in big-endian (RFC 4251 §5)."
  (declare (type (integer 0 #xFFFFFFFF) n))
  (write-byte* buf (ldb (byte 8 24) n))
  (write-byte* buf (ldb (byte 8 16) n))
  (write-byte* buf (ldb (byte 8  8) n))
  (write-byte* buf (ldb (byte 8  0) n)))

(defun write-uint64 (buf n)
  "Append a 64-bit unsigned integer in big-endian (RFC 4251 §5)."
  (declare (type (integer 0 #xFFFFFFFFFFFFFFFF) n))
  (write-byte* buf (ldb (byte 8 56) n))
  (write-byte* buf (ldb (byte 8 48) n))
  (write-byte* buf (ldb (byte 8 40) n))
  (write-byte* buf (ldb (byte 8 32) n))
  (write-byte* buf (ldb (byte 8 24) n))
  (write-byte* buf (ldb (byte 8 16) n))
  (write-byte* buf (ldb (byte 8  8) n))
  (write-byte* buf (ldb (byte 8  0) n)))

(defun write-raw-bytes (buf octets &key (start 0) (end (length octets)))
  "Append raw bytes from OCTETS[START:END] without a length prefix."
  (loop for i from start below end
        do (write-byte* buf (aref octets i))))

(defun write-string* (buf data)
  "Append an SSH string (RFC 4251 §5): uint32 length followed by raw bytes.
   DATA may be an octet vector or a character string (encoded as ASCII)."
  (let ((bytes (etypecase data
                 ((vector (unsigned-byte 8)) data)
                 (string (ascii-to-octets data)))))
    (write-uint32 buf (length bytes))
    (write-raw-bytes buf bytes)))

(defun write-mpint (buf integer)
  "Append an SSH mpint (RFC 4251 §5).

   Zero encodes as a zero-length string.  Positive values use big-endian
   bytes with a leading #x00 if the high bit of the first byte is set.
   Negative values use two's-complement with a leading #xFF if needed."
  (cond
    ((zerop integer)
     (write-uint32 buf 0))

    ((plusp integer)
     (let* ((byte-count (ceiling (integer-length integer) 8))
            ;; High bit of most-significant byte
            (msb (ldb (byte 8 (* 8 (1- byte-count))) integer))
            (needs-zero (logbitp 7 msb))
            (total (if needs-zero (1+ byte-count) byte-count)))
       (write-uint32 buf total)
       (when needs-zero (write-byte* buf 0))
       (loop for i from (1- byte-count) downto 0
             do (write-byte* buf (ldb (byte 8 (* 8 i)) integer)))))

    (t ; negative — two's complement
     (let* ((magnitude (- integer))
            (byte-count (ceiling (integer-length magnitude) 8))
            (twos (- (ash 1 (* 8 byte-count)) magnitude))
            ;; High bit must be set; prepend #xFF if it is not
            (msb (ldb (byte 8 (* 8 (1- byte-count))) twos))
            (needs-ff (not (logbitp 7 msb)))
            (total (if needs-ff (1+ byte-count) byte-count)))
       (write-uint32 buf total)
       (when needs-ff (write-byte* buf #xFF))
       (loop for i from (1- byte-count) downto 0
             do (write-byte* buf (ldb (byte 8 (* 8 i)) twos)))))))

(defun write-name-list (buf names)
  "Append an SSH name-list (RFC 4251 §5): comma-separated ASCII names
   encoded as an SSH string."
  (write-string* buf (format nil "~{~A~^,~}" names)))

(defun buffer-to-octets (buf)
  "Return a simple octet vector containing a copy of BUF's contents."
  (let* ((data   (write-buffer-data buf))
         (len    (length data))
         (result (make-array len :element-type '(unsigned-byte 8))))
    (replace result data)
    result))

;;;; Read buffer

(defstruct (read-buffer (:constructor %make-read-buffer))
  (data (make-array 0 :element-type '(unsigned-byte 8))
        :type (simple-array (unsigned-byte 8) (*)))
  (pos  0 :type fixnum))

(defun make-read-buffer (octets &key (start 0) (end (length octets)))
  "Return a read buffer wrapping a copy of OCTETS[START:END]."
  (let* ((len  (- end start))
         (data (make-array len :element-type '(unsigned-byte 8))))
    (replace data octets :start2 start :end2 end)
    (%make-read-buffer :data data :pos 0)))

(defun read-buffer-length (buf)
  "Total number of bytes in BUF."
  (length (read-buffer-data buf)))

(defun read-remaining-bytes (buf)
  "Number of bytes not yet consumed."
  (- (length (read-buffer-data buf)) (read-buffer-pos buf)))

(defun %ensure-bytes (buf n)
  "Signal BUFFER-UNDERFLOW unless at least N bytes remain."
  (let ((avail (read-remaining-bytes buf)))
    (when (< avail n)
      (error 'buffer-underflow :requested n :available avail))))

(declaim (inline read-byte*))
(defun read-byte* (buf)
  "Consume and return a single octet."
  (declare (type read-buffer buf))
  (%ensure-bytes buf 1)
  (prog1 (aref (read-buffer-data buf) (read-buffer-pos buf))
    (incf (read-buffer-pos buf))))

(defun read-boolean (buf)
  "Consume an SSH boolean.  Any non-zero value is true (RFC 4251 §5)."
  (not (zerop (read-byte* buf))))

(defun read-uint32 (buf)
  "Consume a 32-bit big-endian unsigned integer."
  (%ensure-bytes buf 4)
  (let ((b0 (read-byte* buf))
        (b1 (read-byte* buf))
        (b2 (read-byte* buf))
        (b3 (read-byte* buf)))
    (logior (ash b0 24) (ash b1 16) (ash b2 8) b3)))

(defun read-uint64 (buf)
  "Consume a 64-bit big-endian unsigned integer."
  (%ensure-bytes buf 8)
  (let ((hi (read-uint32 buf))
        (lo (read-uint32 buf)))
    (logior (ash hi 32) lo)))

(defun read-raw-bytes (buf n)
  "Consume N bytes and return them as a fresh simple octet vector."
  (%ensure-bytes buf n)
  (let* ((data   (read-buffer-data buf))
         (pos    (read-buffer-pos buf))
         (result (make-array n :element-type '(unsigned-byte 8))))
    (replace result data :start2 pos :end2 (+ pos n))
    (incf (read-buffer-pos buf) n)
    result))

(defun read-string* (buf)
  "Consume an SSH string and return its contents as a simple octet vector."
  (let ((len (read-uint32 buf)))
    (read-raw-bytes buf len)))

(defun read-mpint (buf)
  "Consume an SSH mpint and return a Common Lisp integer (RFC 4251 §5).

   Handles positive values (optional leading #x00), zero (empty payload),
   and negative values (two's complement)."
  (let ((len (read-uint32 buf)))
    (when (zerop len)
      (return-from read-mpint 0))
    (let* ((bytes  (read-raw-bytes buf len))
           (result 0))
      (loop for b across bytes
            do (setf result (logior (ash result 8) b)))
      ;; If the high bit of the first byte is set, the value is negative
      (when (logbitp 7 (aref bytes 0))
        (decf result (ash 1 (* 8 len))))
      result)))

(defun read-name-list (buf)
  "Consume an SSH name-list and return a list of name strings."
  (let ((raw (read-string* buf)))
    (if (zerop (length raw))
        '()
        (let ((csv (octets-to-ascii raw)))
          (loop for start = 0 then (1+ end)
                for end   = (position #\, csv :start start)
                collect (subseq csv start end)
                while end)))))
