(uiop:define-package #:ssh/sftp/stream
  (:use #:cl #:trivial-gray-streams #:ssh/sftp #:ssh/sftp/codec)
  (:export #:sftp-file-stream #:open-sftp-file #:with-open-sftp-file
           #:sftp-download #:sftp-upload))
(in-package #:ssh/sftp/stream)

(defclass sftp-file-stream ()
  ((handle :initarg :handle :reader %handle)
   (append-p :initarg :append-p :initform nil :reader %append-p)
   (position :initform 0 :accessor %position)
   (read-buffer :initform (make-array 0 :element-type '(unsigned-byte 8)) :accessor %read-buffer)
   (read-position :initform 0 :accessor %read-position)
   (eof :initform nil :accessor %eof)
   (output :initarg :output :accessor %output)
   (failure :initform nil :accessor %failure)
   (lock :initform (bt2:make-lock :name "SFTP file stream") :reader %lock)))
(defclass sftp-input-stream (sftp-file-stream fundamental-binary-input-stream) ())
(defclass sftp-output-stream (sftp-file-stream fundamental-binary-output-stream) ())
(defclass sftp-io-stream (sftp-input-stream sftp-output-stream) ())

(defclass sftp-probe-stream (sftp-file-stream fundamental-stream) ())

(defun %file-flags (direction if-exists if-does-not-exist)
  (check-type direction (member :input :output :io))
  (if (eq direction :input)
      (progn
        (unless (and (eq if-exists :default) (member if-does-not-exist '(:default :error)))
          (error "Input SFTP streams require an existing file and no output policies"))
        '(:read))
      (let ((exists (if (eq if-exists :default) :error if-exists))
            (missing (if (eq if-does-not-exist :default) :create if-does-not-exist)))
        (check-type exists (member :error :supersede :overwrite :append))
        (check-type missing (member :error :create))
        (when (and (eq exists :error) (eq missing :error))
          (error "Both SFTP existence policies cannot be :ERROR"))
        (when (and (eq direction :io) (eq exists :append))
          (error "Append SFTP streams are output-only"))
        (append (if (eq direction :io) '(:read :write) '(:write))
                (when (eq missing :create) '(:create))
                (case exists (:error '(:exclusive)) (:supersede '(:truncate)) (:append '(:append)))))))

(defun %stream-open-flags (direction exists missing)
  (check-type direction (member :input :output :io :probe))
  (when (member direction '(:input :probe)) (setf exists :default))
  (when (eq exists :default) (setf exists :error))
  (check-type exists (member :error :supersede :overwrite :append nil))
  (when (eq missing :default)
    (setf missing (cond ((eq direction :probe) nil)
                        ((or (eq direction :input) (member exists '(:overwrite :append))) :error)
                        (t :create))))
  (check-type missing (member :error :create nil))
  (when (and (eq direction :io) (eq exists :append))
    (error "Append SFTP streams are output-only"))
  (values
   (append (case direction (:output '(:write)) (:io '(:read :write)) (t '(:read)))
           (when (eq missing :create) '(:create))
           (when (member direction '(:output :io))
             (case exists
               ((:error nil) (when (eq missing :create) '(:exclusive)))
               (:supersede '(:truncate))
               (:append '(:append)))))
   exists missing))

(defun %check-stream (stream)
  (unless (open-stream-p stream) (error 'stream-error :stream stream))
  (when (%failure stream) (error (%failure stream)))
  (ssh/sftp::%check-handle (%handle stream) :file))

(defmacro %with-file ((stream) &body body)
  `(ssh/sftp::%with-operation ((ssh/sftp::sftp-handle-session (%handle ,stream)))
     (bt2:with-lock-held ((%lock ,stream))
       (%check-stream ,stream)
       ,@body)))

(defun %discard-input (stream)
  (setf (%read-buffer stream) (make-array 0 :element-type '(unsigned-byte 8))
        (%read-position stream) 0 (%eof stream) nil))

(defun %flush (stream)
  (let ((output (%output stream)))
    (when (plusp (length output))
      (handler-case
          (sftp-write-at (%handle stream) (- (%position stream) (length output)) output)
        (error (condition)
          ;; A failed write may already have changed the remote file. Never replay it.
          (setf (fill-pointer output) 0 (%failure stream) condition)
          (error condition)))
      (setf (fill-pointer output) 0))))

(defun %fill (stream)
  (when (< (%read-position stream) (length (%read-buffer stream))) (return-from %fill t))
  (%flush stream)
  (unless (%eof stream)
    (multiple-value-bind (data eof) (sftp-read-at (%handle stream) (%position stream)
                                               (ssh/sftp::%read-size (%handle stream)))
      (setf (%read-buffer stream) data (%read-position stream) 0 (%eof stream) eof)))
  (< (%read-position stream) (length (%read-buffer stream))))

(defmethod stream-element-type ((stream sftp-file-stream)) '(unsigned-byte 8))

(defmethod stream-read-byte ((stream sftp-input-stream))
  (%with-file (stream)
    (if (%fill stream)
        (prog1 (aref (%read-buffer stream) (%read-position stream))
          (incf (%read-position stream)) (incf (%position stream)))
        :eof)))

(defmethod stream-read-sequence ((stream sftp-input-stream) sequence start end &key &allow-other-keys)
  (%with-file (stream)
    (loop with index = start
          while (and (< index end) (%fill stream))
          for count = (min (- end index) (- (length (%read-buffer stream)) (%read-position stream)))
          do (replace sequence (%read-buffer stream) :start1 index :end1 (+ index count)
                      :start2 (%read-position stream))
             (incf index count) (incf (%read-position stream) count) (incf (%position stream) count)
          finally (return index))))

(defmethod stream-listen ((stream sftp-input-stream))
  (%with-file (stream) (< (%read-position stream) (length (%read-buffer stream)))))

(defmethod stream-write-sequence ((stream sftp-output-stream) sequence start end &key &allow-other-keys)
  (%with-file (stream)
    (unless (and (integerp start) (integerp end) (<= 0 start end (length sequence)))
      (error "Invalid SFTP output sequence bounds"))
    (unless (or (typep sequence '(vector (unsigned-byte 8)))
                (every (lambda (byte) (typep byte '(unsigned-byte 8))) (subseq sequence start end)))
      (error "SFTP output sequences must contain octets"))
    (ssh/sftp/codec::%uint (+ (%position stream) (- end start)) 64)
    (%discard-input stream)
    (loop with index = start while (< index end)
          for output = (%output stream)
          for old = (length output)
          for count = (min (- end index) (- (array-total-size output) old))
          do (setf (fill-pointer output) (+ old count))
             (replace output sequence :start1 old :end1 (+ old count) :start2 index)
             (incf (%position stream) count) (incf index count)
             (when (= (length output) (array-total-size output)) (%flush stream)))
    sequence))

(defmethod stream-write-byte ((stream sftp-output-stream) byte)
  (let ((data (make-array 1 :element-type '(unsigned-byte 8) :initial-element byte)))
    (stream-write-sequence stream data 0 1))
  byte)

(defmethod stream-force-output ((stream sftp-output-stream))
  (%with-file (stream) (%flush stream)) nil)

(defmethod stream-finish-output ((stream sftp-output-stream))
  (stream-force-output stream))

(defmethod stream-file-position ((stream sftp-file-stream))
  (%with-file (stream) (unless (%append-p stream) (%position stream))))

(defmethod (setf stream-file-position) (position (stream sftp-file-stream))
  (%with-file (stream)
    (cond
      ((%append-p stream) nil)
      (t
       (unless (or (member position '(:start :end)) (typep position '(unsigned-byte 64)))
         (error "Invalid SFTP file position"))
       (%flush stream)
       (let ((offset (case position
                       (:start 0)
                       (:end (or (sftp-attributes-size (sftp-fstat (%handle stream)))
                                 (error 'sftp-error :message "Server omitted the size needed for seeking to end")))
                       (otherwise position))))
         (%discard-input stream) (setf (%position stream) offset))
       t))))

(defmethod close ((stream sftp-file-stream) &key abort)
  (unless (open-stream-p stream) (return-from close t))
  (let* ((handle (%handle stream)) (session (ssh/sftp::sftp-handle-session handle)) (failure nil))
    (unwind-protect
         (handler-case
             (if (eq (ssh/sftp::sftp-session-state session) :ready)
                 (ssh/sftp::%with-operation (session)
                   (bt2:with-lock-held ((%lock stream))
                     (unless abort
                       (handler-case
                           (progn (when (%failure stream) (error (%failure stream))) (%flush stream))
                         (error (cause) (setf failure cause))))
                     (setf (fill-pointer (%output stream)) 0)
                     (handler-case (sftp-close-handle handle)
                       (error (cause) (setf failure (or failure cause))))))
                 (unless abort
                   (setf failure (or (ssh/sftp::sftp-session-failure session)
                                     (make-condition 'sftp-error :message "SFTP session is closed")))))
           (error (cause) (setf failure (or failure cause))))
      (setf (fill-pointer (%output stream)) 0)
      (%discard-input stream)
      (call-next-method))
    (when (and failure (not abort)) (error failure))
    t))

(defun open-sftp-file (session remote-path
                       &key (direction :input) (element-type '(unsigned-byte 8))
                         (if-exists :default) (if-does-not-exist :default)
                         (external-format :default) attributes)
  "Open a buffered binary stream for a remote file using CL:OPEN existence policies.
SESSION is the SFTP session that owns the stream.
REMOTE-PATH is a UTF-8 string or raw path octets, without local pathname processing.
DIRECTION is :INPUT, :OUTPUT, :IO, or :PROBE.
ELEMENT-TYPE must be equivalent to (UNSIGNED-BYTE 8), or :DEFAULT.
IF-EXISTS supports :ERROR (default), :SUPERSEDE, :OVERWRITE, :APPEND, or NIL.
IF-DOES-NOT-EXIST supports :ERROR, :CREATE, or NIL, with CL:OPEN defaults.
EXTERNAL-FORMAT is ignored because streams are binary.
ATTRIBUTES supplies remote creation attributes.
Returns a binary SFTP-FILE-STREAM (closed for :PROBE), or NIL for a NIL existence policy."
  (declare (ignore external-format))
  (unless (or (eq element-type :default)
              (and (subtypep element-type '(unsigned-byte 8))
                   (subtypep '(unsigned-byte 8) element-type)))
    (error "SFTP streams support only (UNSIGNED-BYTE 8) elements"))
  (multiple-value-bind (flags exists missing)
      (%stream-open-flags direction if-exists if-does-not-exist)
    (ssh/sftp::%with-operation (session)
      ;; SFTP v3 has no conditional OPEN returning a distinct EXISTS status.
      ;; Do not infer existence from its generic FAILURE reply.
      (when (and (member direction '(:output :io))
                 (or (null exists) (and (eq exists :error) (not (eq missing :create)))))
        (let ((present
                (handler-case (progn (sftp-stat session remote-path) t)
                  (sftp-status-error (condition)
                    (if (eql 2 (sftp-error-code condition)) nil (error condition))))))
          (cond
            (present
             (if (null exists)
                 (return-from open-sftp-file nil)
                 (error 'sftp-error :operation :open :path remote-path
                        :message "Remote file already exists")))
            ((null missing) (return-from open-sftp-file nil))
            ((eq missing :error)
             (error 'sftp-error :operation :open :path remote-path
                    :message "Remote file does not exist")))))
      (let ((handle
              (handler-case
                  (sftp-open-file session remote-path flags :attributes attributes)
                (sftp-status-error (condition)
                  (if (and (null missing) (eql 2 (sftp-error-code condition)))
                      (return-from open-sftp-file nil)
                      (error condition)))))
            (stream nil))
        (unwind-protect
             (progn
               (setf stream
                     (make-instance
                      (case direction
                        (:output 'sftp-output-stream) (:io 'sftp-io-stream)
                        (:probe 'sftp-probe-stream) (t 'sftp-input-stream))
                      :handle handle :append-p (not (null (member :append flags)))
                      :output (make-array
                               (if (member direction '(:input :probe)) 0 (ssh/sftp::%write-size handle))
                               :element-type '(unsigned-byte 8) :fill-pointer 0)))
               (setf (ssh/sftp::sftp-handle-close-function handle) (lambda () (close stream)))
               (when (eq direction :probe) (close stream))
               stream)
          (unless stream (ignore-errors (sftp-close-handle handle))))))))

(defmacro with-open-sftp-file ((stream session remote-path &rest options) &body body)
  "Evaluate a body with a remote binary file stream and close it on exit.
STREAM names the binding created with SESSION, REMOTE-PATH, and OPTIONS.
BODY supplies the forms to execute; abnormal exits discard unsent output.
Returns the values of BODY, signaling normal flush or close failures."
  (let ((normal (gensym "NORMAL")))
    `(let ((,stream (open-sftp-file ,session ,remote-path ,@options)) (,normal nil))
       (unwind-protect
            (multiple-value-prog1 (progn ,@body) (setf ,normal t))
         (when ,stream (if ,normal (close ,stream) (ignore-errors (close ,stream :abort t))))))))

(defun %progress (function session transferred total)
  (when function
    (let ((ssh/sftp::*active-session* nil) (ssh/sftp::*callback-sessions* (cons session ssh/sftp::*callback-sessions*)))
      (funcall function transferred total))))

(defun %optional-stat (handle)
  (handler-case (sftp-fstat handle) (sftp-status-error () nil)))

(defun %regular-file-p (attributes)
  (let ((mode (and attributes (sftp-attributes-permissions attributes))))
    (and mode (= (logand mode #o170000) #o100000))))

(defun %call-with-handle (handle function)
  (let ((normal nil))
    (unwind-protect
         (multiple-value-prog1 (funcall function handle)
           (sftp-close-handle handle) (setf normal t))
      (unless normal (ignore-errors (sftp-close-handle handle))))))

(defun %download-bytes (handle destination width progress total)
  (let* ((session (ssh/sftp::sftp-handle-session handle))
         (size (ssh/sftp::%read-size handle)) (next-offset 0) (transferred 0) (done nil))
    (unwind-protect
         (progn
           (loop until done
                 do (let ((batch nil))
                      (dotimes (i width)
                        (push (list next-offset size (ssh/sftp::%submit-read handle next-offset size)) batch)
                        (incf next-offset size))
                      (dolist (item (nreverse batch))
                        (destructuring-bind (offset remaining request) item
                          (if done
                              (ssh/sftp::%result session request :eof-ok t)
                              (loop
                                (multiple-value-bind (data eof) (ssh/sftp::%result session request :eof-ok t)
                                  (when eof (setf done t) (return))
                                  (write-sequence data destination)
                                  (incf transferred (length data))
                                  (%progress progress session transferred total)
                                  (incf offset (length data))
                                  (decf remaining (length data))
                                  (when (zerop remaining) (return))
                                  ;; The consumed reply freed one slot for this missing range.
                                  (setf request (ssh/sftp::%submit-read handle offset remaining)))))))))
           transferred)
      (ssh/sftp::%drain-requests session))))

(defun %upload-bytes (handle source width progress total)
  (let* ((session (ssh/sftp::sftp-handle-session handle))
         (size (ssh/sftp::%write-size handle))
         (buffer (make-array size :element-type '(unsigned-byte 8)))
         (offset 0) (transferred 0) (done nil))
    (unwind-protect
         (progn
           (loop until done
                 do (let ((batch nil))
                      (dotimes (i width)
                        (let ((count (read-sequence buffer source)))
                          (when (zerop count) (setf done t) (return))
                          (push (cons count (ssh/sftp::%submit-write handle offset buffer 0 count)) batch)
                          (incf offset count)
                          (when (< count size) (setf done t) (return))))
                      (dolist (item (nreverse batch))
                        (ssh/sftp::%result session (cdr item))
                        (incf transferred (car item))
                        (%progress progress session transferred total))))
           transferred)
      (ssh/sftp::%drain-requests session))))

(defun sftp-download (session remote-path local-path &key (if-exists :error) progress-function)
  "Download one remote file into a local binary file.
SESSION is the SFTP session to use.
REMOTE-PATH is a UTF-8 string or raw path octets.
LOCAL-PATH designates the destination file; parent directories must exist.
IF-EXISTS is :ERROR or :SUPERSEDE.
PROGRESS-FUNCTION receives completed bytes and an advisory total or NIL.
Returns the destination pathname and byte count after successful transfer and closes."
  (check-type if-exists (member :error :supersede))
  (ssh/sftp::%with-operation (session)
    (%call-with-handle
     (sftp-open-file session remote-path '(:read))
     (lambda (handle)
       (let* ((attrs (%optional-stat handle))
              (total (and attrs (sftp-attributes-size attrs)))
              (width (if (%regular-file-p attrs) (ssh/sftp::sftp-session-max-pending session) 1))
              (output (open local-path :direction :output :element-type '(unsigned-byte 8)
                            :if-exists if-exists :if-does-not-exist :create))
              (normal nil))
         (unwind-protect
              (progn
                (%progress progress-function session 0 total)
                (let ((count (%download-bytes handle output width progress-function total)))
                  (close output) (setf normal t)
                  (values (pathname local-path) count)))
           ;; Unlike WITH-OPEN-FILE's abnormal cleanup, retain the partial destination.
           (unless normal (ignore-errors (close output :abort nil)))))))))

(defun sftp-upload (session local-path remote-path &key (if-exists :error)
                        (if-does-not-exist :create) attributes fsync progress-function)
  "Upload one local binary file into a remote file.
SESSION is the SFTP session to use.
LOCAL-PATH designates the existing source file.
REMOTE-PATH is a UTF-8 string or raw path octets; parent directories must exist.
IF-EXISTS is :ERROR, :SUPERSEDE, :OVERWRITE, or :APPEND.
IF-DOES-NOT-EXIST is :CREATE or :ERROR.
ATTRIBUTES supplies remote creation attributes only.
FSYNC requires the advertised fsync extension before modifying the destination.
PROGRESS-FUNCTION receives acknowledged bytes and an advisory total or NIL.
Returns REMOTE-PATH and the acknowledged byte count after successful writes and close."
  (let ((flags (%file-flags :output if-exists if-does-not-exist)))
    (ssh/sftp::%with-operation (session)
      (with-open-file (source local-path :direction :input :element-type '(unsigned-byte 8)
                                        :if-does-not-exist :error)
        (when fsync (ssh/sftp::%require-extension session "fsync@openssh.com"))
        (%call-with-handle
         (sftp-open-file session remote-path flags :attributes attributes)
         (lambda (handle)
           (let* ((total (ignore-errors (file-length source)))
                  (width (if (or (member :append flags) (null total)) 1
                             (ssh/sftp::sftp-session-max-pending session))))
             (%progress progress-function session 0 total)
             (let ((count (%upload-bytes handle source width progress-function total)))
               (when fsync (sftp-fsync handle))
               (values remote-path count)))))))))
