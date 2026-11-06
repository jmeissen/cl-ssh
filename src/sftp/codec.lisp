;;;; SFTP v3 wire rules: draft-spaghetti-sshm-filexfer-00 sections 3-8.
(uiop:define-package #:ssh/sftp/codec
  (:use #:cl #:ssh/buffer)
  (:import-from #:babel #:octets-to-string)
  (:export #:sftp-error #:sftp-protocol-error #:sftp-status-error
           #:sftp-unsupported-error #:sftp-no-progress-error
           #:sftp-error-message #:sftp-error-operation #:sftp-error-path
           #:sftp-error-request-id #:sftp-error-code #:sftp-error-server-message
           #:sftp-error-language #:sftp-error-cause
           #:sftp-attributes #:make-sftp-attributes #:sftp-attributes-size
           #:sftp-attributes-uid #:sftp-attributes-gid #:sftp-attributes-permissions
           #:sftp-attributes-atime #:sftp-attributes-mtime #:sftp-attributes-extended
           #:sftp-entry #:sftp-entry-filename #:sftp-entry-longname #:sftp-entry-attributes
           #:sftp-name-string #:path-octets #:encode-attributes #:decode-attributes
           #:encode-frame #:read-frame #:decode-response #:decode-version
           #:response #:response-type #:response-id #:response-value
           #:response-code #:response-message #:response-language))
(in-package #:ssh/sftp/codec)

(define-condition sftp-error (error)
  ((message :initarg :message :initform "SFTP operation failed" :reader sftp-error-message)
   (operation :initarg :operation :initform nil :reader sftp-error-operation)
   (path :initarg :path :initform nil :reader sftp-error-path)
   (request-id :initarg :request-id :initform nil :reader sftp-error-request-id)
   (code :initarg :code :initform nil :reader sftp-error-code)
   (server-message :initarg :server-message :initform nil :reader sftp-error-server-message)
   (language :initarg :language :initform nil :reader sftp-error-language)
   (cause :initarg :cause :initform nil :reader sftp-error-cause))
  (:report (lambda (condition stream)
             (format stream "~A~@[ (~A)~]~@[: ~A~]"
                     (sftp-error-message condition) (sftp-error-operation condition)
                     (sftp-error-server-message condition)))))
(define-condition sftp-protocol-error (sftp-error) ())
(define-condition sftp-status-error (sftp-error) ())
(define-condition sftp-unsupported-error (sftp-error) ())
(define-condition sftp-no-progress-error (sftp-error) ())

(defstruct sftp-attributes size uid gid permissions atime mtime extended)
(defstruct sftp-entry filename longname attributes)
(defstruct response type id value code message language)

(defmacro %decoding (&body body)
  `(handler-case (progn ,@body)
     (sftp-protocol-error (condition) (error condition))
     (error (condition)
       (error 'sftp-protocol-error :message "Malformed SFTP packet" :cause condition))))

(defun %uint (value bits)
  (unless (typep value `(unsigned-byte ,bits))
    (error 'type-error :datum value :expected-type `(unsigned-byte ,bits)))
  value)

(defun %finish-buffer (buffer)
  (unless (zerop (read-remaining-bytes buffer))
    (error 'sftp-protocol-error :message "Trailing SFTP packet data")))

(defun path-octets (path)
  "Encode a remote path without applying local filesystem syntax.
PATH is a UTF-8 string or a raw octet vector, including an empty path.
Returns a fresh octet vector."
  (etypecase path
    (string (utf-8-to-octets path))
    ((vector (unsigned-byte 8)) (copy-seq path))))

(defun sftp-name-string (name)
  "Decode a remote name explicitly as UTF-8.
NAME is a raw filename or longname octet vector.
Returns a string, signaling a decoding error if NAME is not UTF-8."
  (babel:octets-to-string name :encoding :utf-8))

(defun encode-attributes (buffer attributes)
  "Encode optional v3 file attributes.
BUFFER is an SSH write buffer.
ATTRIBUTES is a SFTP-ATTRIBUTES record or NIL for no attributes.
Returns BUFFER."
  (let* ((attrs (or attributes (make-sftp-attributes)))
         (flags 0))
    (check-type attrs sftp-attributes)
    (unless (eq (null (sftp-attributes-uid attrs)) (null (sftp-attributes-gid attrs)))
      (error "SFTP UID and GID must be supplied together"))
    (unless (eq (null (sftp-attributes-atime attrs)) (null (sftp-attributes-mtime attrs)))
      (error "SFTP access and modification times must be supplied together"))
    (when (sftp-attributes-size attrs) (incf flags 1))
    (when (sftp-attributes-uid attrs) (incf flags 2))
    (when (sftp-attributes-permissions attrs) (incf flags 4))
    (when (sftp-attributes-atime attrs) (incf flags 8))
    (when (sftp-attributes-extended attrs) (incf flags #x80000000))
    (write-uint32 buffer flags)
    (when (logbitp 0 flags) (write-uint64 buffer (%uint (sftp-attributes-size attrs) 64)))
    (when (logbitp 1 flags)
      (write-uint32 buffer (%uint (sftp-attributes-uid attrs) 32))
      (write-uint32 buffer (%uint (sftp-attributes-gid attrs) 32)))
    (when (logbitp 2 flags) (write-uint32 buffer (%uint (sftp-attributes-permissions attrs) 32)))
    (when (logbitp 3 flags)
      (write-uint32 buffer (%uint (sftp-attributes-atime attrs) 32))
      (write-uint32 buffer (%uint (sftp-attributes-mtime attrs) 32)))
    (when (logbitp 31 flags)
      (write-uint32 buffer (%uint (length (sftp-attributes-extended attrs)) 32))
      (dolist (pair (sftp-attributes-extended attrs))
        (write-string* buffer (path-octets (car pair)))
        (write-string* buffer (path-octets (cdr pair)))))
    buffer))

(defun decode-attributes (buffer)
  "Decode v3 file attributes with presence and flag validation.
BUFFER is an SSH read buffer containing ATTRS.
Returns a SFTP-ATTRIBUTES record."
  (%decoding
    (let ((flags (read-uint32 buffer)) (attrs (make-sftp-attributes)))
      (unless (zerop (logand flags #x7ffffff0))
        (error 'sftp-protocol-error :message "Unsupported SFTP attribute flags"))
      (when (logbitp 0 flags) (setf (sftp-attributes-size attrs) (read-uint64 buffer)))
      (when (logbitp 1 flags)
        (setf (sftp-attributes-uid attrs) (read-uint32 buffer)
              (sftp-attributes-gid attrs) (read-uint32 buffer)))
      (when (logbitp 2 flags) (setf (sftp-attributes-permissions attrs) (read-uint32 buffer)))
      (when (logbitp 3 flags)
        (setf (sftp-attributes-atime attrs) (read-uint32 buffer)
              (sftp-attributes-mtime attrs) (read-uint32 buffer)))
      (when (logbitp 31 flags)
        (let ((count (read-uint32 buffer)))
          (when (> count (floor (read-remaining-bytes buffer) 8))
            (error 'sftp-protocol-error :message "Impossible extended attribute count"))
          (setf (sftp-attributes-extended attrs)
                (loop repeat count collect (cons (read-string* buffer) (read-string* buffer))))))
      attrs)))

(defun encode-frame (type payload)
  "Frame an SFTP message independently of SSH channel packet boundaries.
TYPE is the message octet.
PAYLOAD contains the message fields after TYPE.
Returns the complete length-prefixed octet vector."
  (let ((buffer (make-write-buffer)))
    (write-uint32 buffer (%uint (1+ (length payload)) 32))
    (write-byte* buffer (%uint type 8))
    (write-raw-bytes buffer payload)
    (buffer-to-octets buffer)))

(defun %read-exactly (stream count)
  (let ((data (make-array count :element-type '(unsigned-byte 8))))
    (loop with start = 0 while (< start count)
          for end = (read-sequence data stream :start start)
          do (when (= end start)
               (error 'sftp-protocol-error :message "Truncated SFTP frame"))
             (setf start end))
    data))

(defun read-frame (stream &key (max-packet-length 1048576))
  "Read and validate one complete SFTP frame.
STREAM is the binary subsystem input stream.
MAX-PACKET-LENGTH bounds the complete frame including its four-byte length.
Returns the type octet and payload octets."
  (let ((length (read-uint32 (make-read-buffer (%read-exactly stream 4)))))
    (unless (<= 1 length (- max-packet-length 4))
      (error 'sftp-protocol-error :message "Invalid or oversized SFTP frame"))
    (let ((data (%read-exactly stream length)))
      (values (aref data 0) (subseq data 1)))))

(defun decode-response (type payload)
  "Decode a v3 response and reject malformed or trailing data.
TYPE identifies the SFTP response message.
PAYLOAD contains fields after TYPE.
Returns a RESPONSE record."
  (%decoding
    (let* ((buffer (make-read-buffer payload))
           (response (make-response :type type :id (read-uint32 buffer))))
      (setf (response-value response)
            (case type
              (101
               (setf (response-code response) (read-uint32 buffer)
                     (response-message response) (sftp-name-string (read-string* buffer))
                     (response-language response) (sftp-name-string (read-string* buffer)))
               (when (member (response-code response) '(6 7))
                 (error 'sftp-protocol-error :message "Server sent a client-only pseudo-status"))
               nil)
              (102
               (let ((handle (read-string* buffer)))
                 (when (> (length handle) 256)
                   (error 'sftp-protocol-error :message "SFTP handle exceeds 256 bytes"))
                 handle))
              (103 (read-string* buffer))
              (104
               (let ((count (read-uint32 buffer)))
                 (when (> count (floor (read-remaining-bytes buffer) 12))
                   (error 'sftp-protocol-error :message "Impossible SFTP NAME count"))
                 (loop repeat count
                       collect (make-sftp-entry :filename (read-string* buffer)
                                                :longname (read-string* buffer)
                                                :attributes (decode-attributes buffer)))))
              (105 (decode-attributes buffer))
              (201 (read-raw-bytes buffer (read-remaining-bytes buffer)))
              (otherwise (error 'sftp-protocol-error :message "Unknown SFTP response type"))))
      (%finish-buffer buffer)
      response)))

(defun decode-version (payload)
  "Decode the server version and its extension announcements.
PAYLOAD contains VERSION fields, without a request identifier.
Returns the version integer and an association list of raw name/data pairs."
  (%decoding
    (let* ((buffer (make-read-buffer payload)) (version (read-uint32 buffer)))
      (values version
              (loop while (plusp (read-remaining-bytes buffer))
                    collect (cons (read-string* buffer) (read-string* buffer)))))))
