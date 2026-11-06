;;;; SFTP session and filesystem operations over a multiplexed SSH subsystem.
(uiop:define-package #:ssh/sftp
  (:use #:cl #:ssh/buffer #:ssh/sftp/codec)
  (:import-from #:ssh/session #:open-subsystem)
  (:import-from #:ssh/connection #:connection-transport #:channel-close)
  (:import-from #:ssh/transport)
  (:export #:sftp-session
           #:sftp-handle
           #:sftp-handle-kind
           #:sftp-handle-open-p
           #:open-sftp-session
           #:close-sftp
           #:sftp-session-extensions
           #:sftp-session-limits
           #:sftp-extension-p
           #:sftp-diagnostics
           #:sftp-open-file
           #:sftp-close-handle
           #:sftp-read-at
           #:sftp-write-at
           #:sftp-open-directory
           #:sftp-read-directory
           #:sftp-list-directory
           #:sftp-stat
           #:sftp-lstat
           #:sftp-fstat
           #:sftp-setstat
           #:sftp-fsetstat
           #:sftp-mkdir
           #:sftp-rmdir
           #:sftp-remove
           #:sftp-rename
           #:sftp-realpath
           #:sftp-readlink
           #:sftp-symlink
           #:sftp-posix-rename
           #:sftp-fsync))

(in-package #:ssh/sftp)

(defstruct (sftp-session (:constructor %make-session))
  stream channel reader (state :new) failure
  (lock (bt2:make-lock :name "SFTP session state"))
  (condition (bt2:make-condition-variable :name "SFTP response"))
  operation-owner close-owner close-error
  (pending (make-hash-table :test #'eql)) (next-id 0)
  (handles (make-hash-table :test #'eq))
  (block-size 32768) (max-pending 16) (max-packet-length 1048576)
  (outbound-limit 34000) (read-limit 32768) (write-limit 32768)
  extensions limits (symlink-order :draft))

(defstruct (sftp-handle (:constructor %make-handle (session bytes kind flags path)))
  (session nil :read-only t) (bytes nil :read-only t)
  (kind nil :read-only t) (flags nil :read-only t) (path nil :read-only t)
  (open-p t) close-function)

(defstruct pending-request id expected operation path max-data response)
(defvar *active-session* nil)
(defvar *callback-sessions* nil)

(defmacro %with-operation ((session) &body body)
  `(%call-with-operation ,session (lambda () ,@body)))

(defun %check-handle (handle &optional kind flag)
  (check-type handle sftp-handle)
  (let ((session (sftp-handle-session handle)))
    (bt2:with-lock-held ((sftp-session-lock session))
      (%ensure-ready session)
      (unless (and (sftp-handle-open-p handle)
                   (gethash handle (sftp-session-handles session))
                   (or (null kind) (eq kind (sftp-handle-kind handle)))
                   (or (null flag) (member flag (sftp-handle-flags handle))))
        (error 'sftp-error :message "Closed, wrong-kind, or incompatible SFTP handle")))))

(defun %check-handle-limit (session)
  (bt2:with-lock-held ((sftp-session-lock session))
    (%ensure-ready session)
    (let ((limit (getf (sftp-session-limits session) :max-open-handles)))
      (when (and limit (plusp limit) (>= (hash-table-count (sftp-session-handles session)) limit))
        (error 'sftp-error :message "Advertised SFTP open handle limit reached")))))

(defun %open-flags (flags)
  (let ((bits 0))
    (dolist (flag flags)
      (setf bits (logior bits (ecase flag
                               (:read 1) (:write 2) (:append 4)
                               (:create 8) (:truncate 16) (:exclusive 32)))))
    (unless (or (member :read flags) (member :write flags)) (error "SFTP open needs READ or WRITE"))
    (when (and (or (member :append flags) (member :truncate flags)) (not (member :write flags)))
      (error "SFTP APPEND/TRUNCATE requires WRITE"))
    (when (and (member :exclusive flags) (not (member :create flags)))
      (error "SFTP EXCLUSIVE requires CREATE"))
    bits))

(defun %register-handle (session bytes kind flags path)
  (bt2:with-lock-held ((sftp-session-lock session))
    (%ensure-ready session)
    (let ((handle (%make-handle session (copy-seq bytes) kind flags path)))
      (setf (gethash handle (sftp-session-handles session)) t)
      handle)))

(defun %read-size (handle)
  (let* ((session (sftp-handle-session handle))
         (size (min (sftp-session-block-size session) (sftp-session-read-limit session)
                    (- (sftp-session-max-packet-length session) 13)
                    (- (sftp-session-outbound-limit session) 13))))
    (unless (plusp size) (error 'sftp-error :message "Server packet limit cannot carry SFTP data"))
    size))

(defun %write-size (handle)
  (let* ((session (sftp-handle-session handle))
         (size (min (sftp-session-block-size session) (sftp-session-write-limit session)
                    (- (sftp-session-outbound-limit session) 25 (length (sftp-handle-bytes handle))))))
    (unless (plusp size) (error 'sftp-error :message "Server packet limit cannot carry SFTP data"))
    size))

(defun %submit-read (handle offset length)
  (%check-handle handle :file :read)
  (let ((count (min length (%read-size handle))))
    (%submit (sftp-handle-session handle) 5
             (lambda (b) (write-string* b (sftp-handle-bytes handle))
                         (write-uint64 b (ssh/sftp/codec::%uint offset 64))
                         (write-uint32 b count))
             103 :operation :read :path (sftp-handle-path handle) :max-data count)))

(defun %submit-write (handle offset data start end)
  (%check-handle handle :file :write)
  (%submit (sftp-handle-session handle) 6
           (lambda (b) (write-string* b (sftp-handle-bytes handle))
                       (write-uint64 b (ssh/sftp/codec::%uint offset 64))
                       (write-uint32 b (- end start))
                       (write-raw-bytes b data :start start :end end))
           101 :operation :write :path (sftp-handle-path handle)))

(defun %path-request (session type path expected operation &optional writer)
  (%request session type (lambda (b) (write-string* b (path-octets path))
                                    (when writer (funcall writer b)))
            expected :operation operation :path path))

(defun %extended (session name writer &key path)
  (%require-extension session name)
  (%request session 200 (lambda (b) (write-string* b name) (funcall writer b))
            101 :operation name :path path))

(defun %one-name (session entries)
  (unless (= (length entries) 1)
    (error (%fail-session session (make-condition 'sftp-protocol-error
                                  :message "REALPATH/READLINK must return exactly one name"))))
  (sftp-entry-filename (first entries)))

(defun sftp-open-file (session path flags &key attributes)
  "Open or create a remote file with explicit v3 flags.
SESSION is the SFTP session.
PATH is a remote UTF-8 string or raw octet vector.
FLAGS is a list of :READ, :WRITE, :APPEND, :CREATE, :TRUNCATE, and :EXCLUSIVE keywords.
ATTRIBUTES contains the optional v3 attributes to send.
Returns a session-owned file handle."
  (%with-operation (session)
    (%check-handle-limit session)
    (let ((bits (%open-flags flags)))
      (%register-handle session
        (%request session 3 (lambda (b) (write-string* b (path-octets path))
                                       (write-uint32 b bits) (encode-attributes b attributes))
                  102 :operation :open :path path)
        :file (copy-list flags) path))))

(defun sftp-close-handle (handle)
  "Close a remote file or directory handle exactly once.
HANDLE is a live handle owned by its SFTP session.
Returns true after the close acknowledgement."
  (check-type handle sftp-handle)
  (unless (sftp-handle-open-p handle) (return-from sftp-close-handle t))
  (let ((session (sftp-handle-session handle)))
    (%with-operation (session)
      (%check-handle handle)
      (bt2:with-lock-held ((sftp-session-lock session))
        (setf (sftp-handle-open-p handle) nil)
        (remhash handle (sftp-session-handles session)))
      (%request session 4 (lambda (b) (write-string* b (sftp-handle-bytes handle)))
                101 :operation :close :path (sftp-handle-path handle)))))

(defun sftp-read-at (handle offset length)
  "Read one bounded block at an explicit remote byte offset.
HANDLE is a live handle owned by its SFTP session.
OFFSET is an unsigned 64-bit byte offset.
LENGTH is the maximum number of bytes requested.
Returns octets and an EOF flag; a short block alone is not EOF."
  (check-type handle sftp-handle)
  (let ((session (sftp-handle-session handle)))
    (%with-operation (session)
      (%check-handle handle :file :read)
      (ssh/sftp/codec::%uint offset 64)
      (ssh/sftp/codec::%uint length 32)
      (if (zerop length)
          (values (make-array 0 :element-type '(unsigned-byte 8)) nil)
          (multiple-value-bind (data eof) (%result session (%submit-read handle offset length) :eof-ok t)
            (values (or data (make-array 0 :element-type '(unsigned-byte 8))) eof))))))

(defun sftp-write-at (handle offset data &key (start 0) (end (length data)))
  "Write binary data at an explicit remote byte offset.
HANDLE is a live handle owned by its SFTP session.
OFFSET is an unsigned 64-bit byte offset; append handles ignore write offsets.
DATA is an octet vector.
START is the inclusive index in DATA.
END is the exclusive index in DATA.
Returns the acknowledged byte count."
  (check-type handle sftp-handle)
  (check-type data (vector (unsigned-byte 8)))
  (unless (<= 0 start end (length data)) (error "Invalid SFTP data slice"))
  (ssh/sftp/codec::%uint offset 64)
  (let ((session (sftp-handle-session handle)))
    (%with-operation (session)
      (%check-handle handle :file :write)
      (loop with total = (- end start)
            for position from start below end by (%write-size handle)
            for count = (min (- end position) (%write-size handle))
            do (%result session (%submit-write handle (+ offset (- position start)) data position (+ position count)))
            finally (return total)))))

(defun sftp-open-directory (session path)
  "Open a remote directory for batch reading.
SESSION is the SFTP session.
PATH is a remote UTF-8 string or raw octet vector.
Returns a session-owned directory handle."
  (%with-operation (session)
    (%check-handle-limit session)
    (%register-handle session
                      (%request session 11
                                (lambda (b)
                                  (write-string* b (path-octets path)))
                                102
                                :operation :opendir
                                :path path)
                      :directory
                      nil
                      path)))

(defun sftp-read-directory (handle)
  "Read the next batch of remote directory entries.
HANDLE is a live handle owned by its SFTP session.
Returns entry records and an EOF flag."
  (check-type handle sftp-handle)
  (let ((session (sftp-handle-session handle)))
    (%with-operation (session)
      (%check-handle handle :directory)
      (multiple-value-bind (entries eof)
          (%request session
                    12
                    (lambda (b)
                      (write-string* b (sftp-handle-bytes handle)))
                    104
                    :operation :readdir
                    :path (sftp-handle-path handle)
                    :eof-ok t)
        (when (and (null entries) (not eof))
          (error 'sftp-no-progress-error :message "SFTP READDIR returned no entries without EOF"))
        (values entries eof)))))

(defun sftp-list-directory (session path)
  "Collect all remote directory entry batches and close their handle.
SESSION is the SFTP session.
PATH is a remote UTF-8 string or raw octet vector.
Returns a list of entries in server order."
  (%with-operation (session)
    (let ((handle (sftp-open-directory session path))
          (batches nil)
          (completed nil))
      (unwind-protect
           (progn
             (loop
               (multiple-value-bind (entries eof)
                   (sftp-read-directory handle)
                 (when eof (return))
                 (push entries batches)))
             (sftp-close-handle handle)
             (setf completed t)
             (mapcan #'identity (nreverse batches)))
        (unless completed
          (ignore-errors (sftp-close-handle handle)))))))

(defun sftp-stat (session path)
  "Retrieve attributes, following remote symbolic links.
SESSION is the SFTP session.
PATH is a remote UTF-8 string or raw octet vector.
Returns a SFTP-ATTRIBUTES record."
  (%with-operation (session)
    (%path-request session 17 path 105 :stat)))

(defun sftp-lstat (session path)
  "Retrieve attributes without following the final symbolic link.
SESSION is the SFTP session.
PATH is a remote UTF-8 string or raw octet vector.
Returns a SFTP-ATTRIBUTES record."
  (%with-operation (session)
    (%path-request session 7 path 105 :lstat)))

(defun sftp-fstat (handle)
  "Retrieve attributes of an open remote file.
HANDLE is a live handle owned by its SFTP session.
Returns a SFTP-ATTRIBUTES record."
  (check-type handle sftp-handle)
  (let ((session (sftp-handle-session handle)))
    (%with-operation (session)
      (%check-handle handle :file)
      (%request session 8 (lambda (b) (write-string* b (sftp-handle-bytes handle)))
                105 :operation :fstat :path (sftp-handle-path handle)))))

(defun sftp-setstat (session path attributes)
  "Modify selected attributes of an existing remote path.
SESSION is the SFTP session.
PATH is a remote UTF-8 string or raw octet vector.
ATTRIBUTES contains the optional v3 attributes to send.
Returns true after acknowledgement."
  (%with-operation (session)
    (%path-request session 9 path 101 :setstat (lambda (b) (encode-attributes b attributes)))))

(defun sftp-fsetstat (handle attributes)
  "Modify selected attributes of an open remote file.
HANDLE is a live handle owned by its SFTP session.
ATTRIBUTES contains the optional v3 attributes to send.
Returns true after acknowledgement."
  (check-type handle sftp-handle)
  (let ((session (sftp-handle-session handle)))
    (%with-operation (session)
      (%check-handle handle :file)
      (%request session 10 (lambda (b) (write-string* b (sftp-handle-bytes handle))
                                      (encode-attributes b attributes))
                101 :operation :fsetstat :path (sftp-handle-path handle)))))

(defun sftp-mkdir (session path &key attributes)
  "Create one remote directory without creating missing parents.
SESSION is the SFTP session.
PATH is a remote UTF-8 string or raw octet vector.
ATTRIBUTES contains the optional v3 attributes to send.
Returns true after acknowledgement."
  (%with-operation (session)
    (%path-request session 14 path 101 :mkdir (lambda (b) (encode-attributes b attributes)))))

(defun sftp-rmdir (session path)
  "Remove one empty remote directory.
SESSION is the SFTP session.
PATH is a remote UTF-8 string or raw octet vector.
Returns true after acknowledgement."
  (%with-operation (session)
    (%path-request session 15 path 101 :rmdir)))

(defun sftp-remove (session path)
  "Remove a remote file, not a directory.
SESSION is the SFTP session.
PATH is a remote UTF-8 string or raw octet vector.
Returns true after acknowledgement."
  (%with-operation (session)
    (%path-request session 13 path 101 :remove)))

(defun sftp-rename (session oldpath newpath)
  "Rename a remote path without replacing an existing destination.
SESSION is the SFTP session.
OLDPATH is the existing remote path.
NEWPATH is the destination remote path.
Returns true after acknowledgement."
  (%with-operation (session)
    (%path-request session 18 oldpath 101
                   :rename (lambda (b)
                             (write-string* b (path-octets newpath))))))

(defun sftp-posix-rename (session oldpath newpath)
  "Rename a remote path using the advertised POSIX replacement extension.
SESSION is the SFTP session.
OLDPATH is the existing remote path.
NEWPATH is the destination remote path.
Returns true after acknowledgement."
  (%with-operation (session)
    (%extended session "posix-rename@openssh.com"
               (lambda (b) (write-string* b (path-octets oldpath))
                 (write-string* b (path-octets newpath)))
               :path oldpath)))

(defun sftp-realpath (session path)
  "Ask the server to canonicalize a remote path.
SESSION is the SFTP session.
PATH is a remote UTF-8 string or raw octet vector.
Returns the canonical path as raw octets."
  (%with-operation (session)
    (%one-name session
               (%path-request session 16 path 104 :realpath))))

(defun sftp-readlink (session path)
  "Read the target of a remote symbolic link.
SESSION is the SFTP session.
PATH is a remote UTF-8 string or raw octet vector.
Returns the target as raw octets."
  (%with-operation (session)
    (%one-name session
               (%path-request session 19 path 104 :readlink))))

(defun sftp-symlink (session linkpath targetpath)
  "Create a symbolic link using the session's configured wire ordering.
SESSION is the SFTP session.
LINKPATH names the symbolic link to create.
TARGETPATH is the symbolic link target.
Returns true after acknowledgement."
  (%with-operation (session)
    (%request session 20
              (lambda (b)
                (dolist (path (if (eq (sftp-session-symlink-order session) :openssh)
                                  (list targetpath linkpath) (list linkpath targetpath)))
                  (write-string* b (path-octets path))))
              101 :operation :symlink :path linkpath)))

(defun sftp-fsync (handle)
  "Synchronize an open remote file using the advertised fsync extension.
HANDLE is a live handle owned by its SFTP session.
Returns true after acknowledgement."
  (check-type handle sftp-handle)
  (let ((session (sftp-handle-session handle)))
    (%with-operation (session)
      (%check-handle handle :file)
      (%extended session "fsync@openssh.com" (lambda (b) (write-string* b (sftp-handle-bytes handle)))
                 :path (sftp-handle-path handle)))))

(defun %ensure-ready (session)
  (when (sftp-session-failure session) (error (sftp-session-failure session)))
  (unless (eq (sftp-session-state session) :ready)
    (error 'sftp-error :message "SFTP session is not open")))

(defun %call-with-operation (session function)
  (when (member session *callback-sessions* :test #'eq)
    (error 'sftp-error :message "SFTP progress callbacks cannot reenter their session"))
  (if (eq *active-session* session)
      (funcall function)
      (progn
        (bt2:with-lock-held ((sftp-session-lock session))
          (loop
            (%ensure-ready session)
            (unless (or (sftp-session-operation-owner session)
                        (and (sftp-session-close-owner session)
                             (not (eq (sftp-session-close-owner session)
                                      (bt2:current-thread)))))
              (setf (sftp-session-operation-owner session) (bt2:current-thread))
              (return))
            (bt2:condition-wait (sftp-session-condition session) (sftp-session-lock session))))
        (unwind-protect
             (let ((*active-session* session)) (funcall function))
          (bt2:with-lock-held ((sftp-session-lock session))
            (setf (sftp-session-operation-owner session) nil)
            (bt2:condition-broadcast (sftp-session-condition session)))))))

(defun %abort-io (session cause)
  (let ((channel (sftp-session-channel session)))
    (if channel
        (progn
          (ssh/connection::%fail-channel channel cause)
          ;; Failure wakes a flow-control-blocked writer. Order CLOSE after its
          ;; final in-flight packet, without waiting for the peer's close reply.
          (ignore-errors
            (bt2:with-lock-held ((ssh/connection::channel-write-lock channel))
              (ssh/connection::%channel-send-close-locked channel))))
        (ignore-errors (close (sftp-session-stream session) :abort t)))))

(defun %fail-session (session cause)
  (let ((changed nil))
    (bt2:with-lock-held ((sftp-session-lock session))
      (unless (member (sftp-session-state session) '(:failed :closed))
        (setf (sftp-session-state session) :failed
              (sftp-session-failure session) cause changed t)
        (maphash (lambda (handle value)
                   (declare (ignore value)) (setf (sftp-handle-open-p handle) nil))
                 (sftp-session-handles session))
        (clrhash (sftp-session-handles session))
        (bt2:condition-broadcast (sftp-session-condition session))))
    (when changed (%abort-io session cause))
    cause))

(defun %reader-loop (session)
  (handler-case
      (loop
        (multiple-value-bind (type payload)
            (read-frame (sftp-session-stream session)
                        :max-packet-length (sftp-session-max-packet-length session))
          (let ((response (decode-response type payload)))
            (bt2:with-lock-held ((sftp-session-lock session))
              (when (member (sftp-session-state session) '(:failed :closed)) (return))
              (let ((request (gethash (response-id response) (sftp-session-pending session))))
                (unless (and request (null (pending-request-response request)))
                  (error 'sftp-protocol-error :message "Unknown or duplicate SFTP response ID"))
                (unless (or (= type (pending-request-expected request))
                            (and (= type 101) (not (zerop (response-code response)))))
                  (error 'sftp-protocol-error :message "Unexpected SFTP response type"))
                (when (and (= type 103)
                           (> (length (response-value response)) (pending-request-max-data request)))
                  (error 'sftp-protocol-error :message "SFTP DATA exceeds requested length"))
                (setf (pending-request-response request) response)
                (bt2:condition-broadcast (sftp-session-condition session)))))))
    (error (cause)
      (unless (bt2:with-lock-held ((sftp-session-lock session))
                (and (member (sftp-session-state session) '(:closing :closed))
                     (zerop (hash-table-count (sftp-session-pending session)))))
        (%fail-session
         session
         (if (typep cause 'sftp-error) cause
             (make-condition 'sftp-error :message "SFTP channel failed or closed unexpectedly"
                             :cause (or (and (sftp-session-channel session)
                                             (ssh/connection:channel-failure (sftp-session-channel session)))
                                        cause))))))))

(defun %submit (session type writer expected &key operation path max-data)
  (let ((fields (make-write-buffer)) (buffer (make-write-buffer)) request frame)
    (funcall writer fields)
    (bt2:with-lock-held ((sftp-session-lock session))
      (%ensure-ready session)
      (when (>= (hash-table-count (sftp-session-pending session)) (sftp-session-max-pending session))
        (error 'sftp-error :message "SFTP outstanding request limit reached"))
      (loop for id = (sftp-session-next-id session)
            do (setf (sftp-session-next-id session) (logand #xffffffff (1+ id)))
            unless (gethash id (sftp-session-pending session))
              do (setf request (make-pending-request :id id :expected expected
                                :operation operation :path path :max-data max-data)) (return))
      (write-uint32 buffer (pending-request-id request))
      (write-raw-bytes buffer (buffer-to-octets fields))
      (setf frame (encode-frame type (buffer-to-octets buffer)))
      (when (> (length frame) (sftp-session-outbound-limit session))
        (error 'sftp-error :message "SFTP request exceeds the outbound packet limit"))
      (setf (gethash (pending-request-id request) (sftp-session-pending session)) request))
    (handler-case
        (progn (write-sequence frame (sftp-session-stream session))
               (force-output (sftp-session-stream session)))
      (error (cause)
        (error (%fail-session session (make-condition 'sftp-error
                                      :message "SFTP request transmission failed" :cause cause)))))
    request))

(defun %await (session request)
  (bt2:with-lock-held ((sftp-session-lock session))
    (loop until (pending-request-response request)
          do (when (sftp-session-failure session) (error (sftp-session-failure session)))
             (bt2:condition-wait (sftp-session-condition session) (sftp-session-lock session)))
    (remhash (pending-request-id request) (sftp-session-pending session))
    (pending-request-response request)))

(defun %drain-requests (session)
  (let ((requests (bt2:with-lock-held ((sftp-session-lock session))
                    (loop for request being the hash-values of (sftp-session-pending session)
                          collect request))))
    (dolist (request requests)
      (unless (sftp-session-failure session) (ignore-errors (%await session request))))))

(defun %result (session request &key eof-ok)
  (let ((response (%await session request)))
    (if (= (response-type response) 101)
        (case (response-code response)
          (0 (values t nil))
          (1 (if eof-ok (values nil t) (%status-error request response)))
          (otherwise (%status-error request response)))
        (progn
          (when (and (= (response-type response) 103)
                     (plusp (pending-request-max-data request))
                     (zerop (length (response-value response))))
            (error 'sftp-no-progress-error :operation (pending-request-operation request)
                   :message "SFTP read returned no data without EOF"))
          (values (response-value response) nil)))))

(defun %status-error (request response)
  (error 'sftp-status-error :operation (pending-request-operation request)
         :path (pending-request-path request) :request-id (pending-request-id request)
         :code (response-code response) :server-message (response-message response)
         :language (response-language response)))

(defun %request (session type writer expected &key operation path max-data eof-ok)
  (%result session (%submit session type writer expected :operation operation :path path :max-data max-data)
           :eof-ok eof-ok))

(defun sftp-extension-p (session name &optional (version "1"))
  "Check an exact SFTP extension name and supported version announcement.
SESSION is the negotiated session.
NAME and VERSION are strings or octet vectors; repeated announcements are supported.
Returns true when the requested name/version pair was advertised."
  (let ((name (path-octets name)) (version (path-octets version)))
    (not (null (find-if (lambda (pair) (and (equalp name (car pair)) (equalp version (cdr pair))))
                        (sftp-session-extensions session))))))

(defun %require-extension (session name)
  (unless (sftp-extension-p session name)
    (error 'sftp-unsupported-error :operation name :code 8 :message "Required SFTP extension is unavailable")))

(defun %refresh-limits (session)
  (when (sftp-extension-p session "limits@openssh.com")
    (handler-case
        (let* ((raw (%request session 200 (lambda (b) (write-string* b "limits@openssh.com"))
                              201 :operation :limits))
               (buffer (make-read-buffer raw)))
          (unless (= (length raw) 32)
            (error 'sftp-protocol-error :message "Malformed SFTP limits reply"))
          (let ((packet (read-uint64 buffer)) (read (read-uint64 buffer))
                (write (read-uint64 buffer)) (handles (read-uint64 buffer)))
            (setf (sftp-session-limits session) (list :max-packet-length packet :max-read-length read
                                                     :max-write-length write :max-open-handles handles)
                  (sftp-session-outbound-limit session)
                  (min (sftp-session-max-packet-length session)
                       (if (zerop packet) 34000 packet))
                  (sftp-session-read-limit session) (if (zerop read) 32768 read)
                  (sftp-session-write-limit session) (if (zerop write) 32768 write))))
      (sftp-status-error () nil))))

(defun %start-session (stream &key channel banner (block-size 32768)
                                  (max-pending 16) (max-packet-length 1048576)
                                  (symlink-order :auto))
  (check-type block-size (integer 1 #xffffffff))
  (check-type max-pending (integer 1 #xffffffff))
  (check-type max-packet-length (integer 34000 #xffffffff))
  (check-type symlink-order (member :auto :draft :openssh))
  (let ((session (%make-session :stream stream :channel channel :block-size block-size
                                :max-pending max-pending :max-packet-length max-packet-length
                                :symlink-order (if (eq symlink-order :auto)
                                                   (if (and banner (or (search "SSH-2.0-OpenSSH_" banner)
                                                                       (search "SSH-1.99-OpenSSH_" banner)))
                                                       :openssh :draft)
                                                   symlink-order))))
    (handler-case
        (progn
          (let ((buffer (make-write-buffer)))
            (write-uint32 buffer 3)
            (write-sequence (encode-frame 1 (buffer-to-octets buffer)) stream)
            (force-output stream))
          (multiple-value-bind (type payload) (read-frame stream :max-packet-length max-packet-length)
            (unless (= type 2) (error 'sftp-protocol-error :message "Expected SFTP VERSION"))
            (multiple-value-bind (version extensions) (decode-version payload)
              (unless (= version 3) (error 'sftp-unsupported-error :message "Only SFTP version 3 is supported"))
              (setf (sftp-session-extensions session) extensions)))
          (setf (sftp-session-state session) :ready
                (sftp-session-reader session) (bt2:make-thread (lambda () (%reader-loop session))
                                                             :name "SFTP response reader"))
          (%with-operation (session) (%refresh-limits session))
          session)
      (error (cause)
        (%fail-session session cause)
        (let ((reader (sftp-session-reader session)))
          (when reader (bt2:join-thread reader)))
        (error cause)))))

(defun open-sftp-session (connection &key (block-size 32768) (max-pending 16)
                                        (max-packet-length 1048576) (symlink-order :auto))
  "Negotiate an SFTP v3 session on a fresh multiplexed subsystem channel.
CONNECTION is the authenticated shared SSH connection.
BLOCK-SIZE bounds each transfer data block in bytes.
MAX-PENDING bounds both outstanding requests and retained undelivered replies.
MAX-PACKET-LENGTH bounds a complete received SFTP frame, including its header.
SYMLINK-ORDER is :AUTO, :DRAFT, or :OPENSSH; :AUTO uses the server identification.
Returns a ready SFTP-SESSION."
  (check-type block-size (integer 1 #xffffffff))
  (check-type max-pending (integer 1 #xffffffff))
  (check-type max-packet-length (integer 34000 #xffffffff))
  (check-type symlink-order (member :auto :draft :openssh))
  (multiple-value-bind (stream channel) (open-subsystem connection "sftp" :stderr-tail t)
    (let ((transferred-p nil))
      (unwind-protect
           (prog1
               (%start-session stream :channel channel
                 :banner (ssh/transport::transport-server-version (connection-transport connection))
                 :block-size block-size :max-pending max-pending
                 :max-packet-length max-packet-length :symlink-order symlink-order)
             (setf transferred-p t))
        (unless transferred-p
          (ignore-errors (close stream :abort t)))))))

(defun sftp-diagnostics (session)
  "Inspect the bounded subsystem stderr diagnostics.
SESSION is the SFTP session whose diagnostics are requested.
Returns the last 64 KiB of stderr as octets and a truncation indicator."
  (let ((channel (sftp-session-channel session)))
    (if channel
        (bt2:with-lock-held ((ssh/connection:channel-state-lock channel))
          (let ((buffer (ssh/connection::channel-stderr-input channel)))
            (values (ssh/channel-buffer:buffer-snapshot buffer)
                    (ssh/channel-buffer:input-buffer-truncated-p buffer))))
        (values (make-array 0 :element-type '(unsigned-byte 8)) nil))))

(defun close-sftp (session &key abort)
  "Close SFTP handles and the subsystem without disconnecting the SSH client.
SESSION is the session to close; simultaneous closers share one cleanup result.
ABORT cancels pending work without waiting for the peer or promising rollback.
Returns true after cleanup, signaling normal cleanup errors to waiting closers."
  (when (member session *callback-sessions* :test #'eq)
    (error 'sftp-error :message "SFTP progress callbacks cannot close their session"))
  (let ((owner-p nil))
    (bt2:with-lock-held ((sftp-session-lock session))
      (when (eq (sftp-session-state session) :closed)
        (return-from close-sftp t))
      (when (eq (sftp-session-close-owner session) (bt2:current-thread))
        (error 'sftp-error :message "Recursive SFTP session close"))
      (unless (sftp-session-close-owner session)
        (setf (sftp-session-close-owner session) (bt2:current-thread)
              owner-p t)))
    (unless owner-p
      ;; An abort may interrupt the owner, but never takes over its cleanup.
      (when abort
        (%fail-session session (make-condition 'sftp-error :message "SFTP session aborted")))
      (bt2:with-lock-held ((sftp-session-lock session))
        (loop until (eq (sftp-session-state session) :closed)
              do (bt2:condition-wait (sftp-session-condition session)
                                     (sftp-session-lock session)))
        (when (and (not abort) (sftp-session-close-error session))
          (error (sftp-session-close-error session))))
      (return-from close-sftp t))
    (let ((failure (and (not abort) (sftp-session-failure session))))
      (unwind-protect
           (handler-case
               (if (or abort (sftp-session-failure session))
                   (%fail-session session (or (sftp-session-failure session)
                                              (make-condition 'sftp-error :message "SFTP session aborted")))
                   (%with-operation (session)
                     (dolist (handle
                               (bt2:with-lock-held ((sftp-session-lock session))
                                 (loop for handle being the hash-keys of (sftp-session-handles session)
                                       collect handle)))
                       (handler-case
                           (if (sftp-handle-close-function handle)
                               (funcall (sftp-handle-close-function handle))
                               (sftp-close-handle handle))
                         (error (cause) (unless failure (setf failure cause)))))
                     (bt2:with-lock-held ((sftp-session-lock session))
                       (setf (sftp-session-state session) :closing))
                     (handler-case
                         (if (sftp-session-channel session)
                             (channel-close (sftp-session-channel session))
                             (close (sftp-session-stream session)))
                       (error (cause)
                         (setf failure (or failure cause))
                         (%abort-io session cause)))))
             (error (cause)
               (setf failure (or failure cause))
               (%fail-session session cause)))
        ;; Publish CLOSED only after the response reader has released its resources.
        (unwind-protect
             (let ((reader (sftp-session-reader session)))
               (when (and reader (not (eq reader (bt2:current-thread))))
                 (handler-case (bt2:join-thread reader)
                   (error (cause) (setf failure (or failure cause))))))
          (bt2:with-lock-held ((sftp-session-lock session))
            (setf (sftp-session-state session) :closed
                  (sftp-session-close-error session) failure
                  (sftp-session-close-owner session) nil)
            (maphash (lambda (handle value)
                       (declare (ignore value))
                       (setf (sftp-handle-open-p handle) nil))
                     (sftp-session-handles session))
            (clrhash (sftp-session-handles session))
            (clrhash (sftp-session-pending session))
            (bt2:condition-broadcast (sftp-session-condition session)))))
      (when (and failure (not abort)) (error failure))
      t)))
