;;;; ~/.ssh/known_hosts management.
;;;;
;;;; Supports:
;;;;   - Plain hostname entries:   hostname key-type base64-key [comment]
;;;;   - Hashed hostname entries:  |1|<base64-salt>|<base64-hash> key-type base64-key
;;;;   - Strict checking: reject unknown and changed host keys
;;;;   - Policy-controlled TOFU and permissive changed-key updates
;;;;
;;;; Does not yet support:
;;;;   - Multiple hostnames in a single entry (comma-separated)
;;;;   - @cert-authority / @revoked markers
;;;;   - Port-qualified entries ([host]:port)

(uiop:define-package ssh/known-hosts
  (:use #:cl)
  (:import-from #:ssh/config)
  (:import-from #:ssh/keys
                #:public-key-fingerprint
                #:key-error)
  (:export
   #:host-key-revoked-error
   #:host-key-revoked-error-hostname
   #:host-key-revoked-error-received-fingerprint
   #:check-host-key
   #:normalize-host-key-policy
   #:unknown-host-key-error
   #:unknown-host-key-error-hostname
   #:unknown-host-key-error-key-type
   #:unknown-host-key-error-received-fingerprint
   #:host-key-changed-error
   #:host-key-changed-error-hostname
   #:host-key-changed-error-expected-fingerprint
   #:host-key-changed-error-received-fingerprint))

(in-package #:ssh/known-hosts)

;;;; Conditions

(define-condition host-key-changed-error (error)
  ((hostname             :initarg :hostname             :reader host-key-changed-error-hostname)
   (expected-fingerprint :initarg :expected-fingerprint :reader host-key-changed-error-expected-fingerprint)
   (received-fingerprint :initarg :received-fingerprint :reader host-key-changed-error-received-fingerprint))
  (:report (lambda (c s)
             (format s "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!~%~
                        Host key for ~A has changed.~%~
                        Expected fingerprint: ~A~%~
                        Received fingerprint: ~A~%~
                        Possible MITM attack. Connection refused."
                     (host-key-changed-error-hostname c)
                     (host-key-changed-error-expected-fingerprint c)
                     (host-key-changed-error-received-fingerprint c)))))

(define-condition unknown-host-key-error (error)
  ((hostname
    :initarg :hostname
    :reader unknown-host-key-error-hostname)
   (key-type
    :initarg :key-type
    :reader unknown-host-key-error-key-type)
   (received-fingerprint
    :initarg :received-fingerprint
    :reader unknown-host-key-error-received-fingerprint))
  (:report
   (lambda (condition stream)
     (format stream
             "No trusted host key is recorded for ~A (~A). Received fingerprint: ~A. Connection refused."
             (unknown-host-key-error-hostname condition)
             (unknown-host-key-error-key-type condition)
             (unknown-host-key-error-received-fingerprint condition)))))

(define-condition host-key-revoked-error (error)
  ((hostname :initarg :hostname :reader host-key-revoked-error-hostname)
   (received-fingerprint :initarg :received-fingerprint
                         :reader host-key-revoked-error-received-fingerprint))
  (:report (lambda (condition stream)
             (format stream "Host key for ~A is revoked (~A). Connection refused."
                     (host-key-revoked-error-hostname condition)
                     (host-key-revoked-error-received-fingerprint condition)))))

(define-condition known-hosts-lock-error (error)
  ((path :initarg :path :reader known-hosts-lock-error-path))
  (:report (lambda (c s)
             (format s "Timed out while waiting for known_hosts lock ~A"
                     (known-hosts-lock-error-path c)))))

(defparameter *known-hosts-lock-timeout-seconds* 10
  "Maximum seconds to wait for another process to release the known_hosts lock.")

(defparameter *known-hosts-lock-retry-delay-seconds* 1/20
  "Seconds to wait between known_hosts lock acquisition attempts.")

;;;; Default known_hosts path

(defun default-known-hosts-path ()
  "Return the pathname to ~/.ssh/known_hosts."
  (merge-pathnames #p".ssh/known_hosts" (user-homedir-pathname)))

;;;; Base64

(defun base64-decode (string)
  "Decode a base64 string to a simple octet vector."
  (let* ((clean (remove-if (lambda (c)
                              (member c '(#\Newline #\Return #\Space #\Tab)))
                            string))
         (len   (length clean))
         (table "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
         (out   (make-array (* 3 (ceiling len 4)) :element-type '(unsigned-byte 8)
                                                  :fill-pointer 0)))
    (flet ((v (c)
             (if (char= c #\=) 0
                 (or (position c table)
                     (error "invalid base64 character: ~S" c)))))
      (loop for i from 0 below len by 4
            for c0 = (v (char clean i))
            for c1 = (v (char clean (min (+ i 1) (1- len))))
            for c2 = (if (< (+ i 2) len) (v (char clean (+ i 2))) 0)
            for c3 = (if (< (+ i 3) len) (v (char clean (+ i 3))) 0)
            do (vector-push (logior (ash c0 2) (ash c1 -4)) out)
               (unless (and (< (+ i 2) len) (char= (char clean (+ i 2)) #\=))
                 (vector-push (logior (ash (logand c1 15) 4) (ash c2 -2)) out))
               (unless (and (< (+ i 3) len) (char= (char clean (+ i 3)) #\=))
                 (vector-push (logior (ash (logand c2 3) 6) c3) out))))
    (let ((result (make-array (length out) :element-type '(unsigned-byte 8))))
      (replace result out)
      result)))

(defun base64-encode (octets)
  "Encode OCTETS as a base64 string (standard alphabet, no line wrapping)."
  (let ((table "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"))
    (with-output-to-string (s)
      (loop for i from 0 below (length octets) by 3
            for remaining = (- (length octets) i)
            for b0 = (aref octets i)
            for b1 = (if (> remaining 1) (aref octets (+ i 1)) 0)
            for b2 = (if (> remaining 2) (aref octets (+ i 2)) 0)
            do (write-char (char table (ash b0 -2)) s)
               (write-char (char table (logior (ash (logand b0 3) 4) (ash b1 -4))) s)
               (if (> remaining 1)
                   (write-char (char table (logior (ash (logand b1 15) 2) (ash b2 -6))) s)
                   (write-char #\= s))
               (if (> remaining 2)
                   (write-char (char table (logand b2 63)) s)
                   (write-char #\= s))))))

;;;; Hashed hostname matching (|1|salt|hash format)

(defun hashed-hostname-matches-p (entry-hostname hostname)
  "Return true if ENTRY-HOSTNAME is a |1|salt|hash entry matching HOSTNAME."
  (when (and (>= (length entry-hostname) 3)
             (char= (char entry-hostname 0) #\|))
    (let ((parts (loop for start = 1 then (1+ end)
                       for end   = (position #\| entry-hostname :start start)
                       collect (subseq entry-hostname start (or end (length entry-hostname)))
                       while end)))
      ;; parts = ("1" "<base64-salt>" "<base64-hash>")
      (when (and (= (length parts) 3)
                 (string= (first parts) "1"))
        (let* ((salt     (base64-decode (second parts)))
               (hash     (base64-decode (third parts)))
               (host-utf (map '(vector (unsigned-byte 8)) #'char-code hostname))
               (expected (let ((mac (ironclad:make-mac :hmac salt :sha1)))
                           (ironclad:update-mac mac host-utf)
                           (ironclad:produce-mac mac))))
          (ironclad:constant-time-equal hash expected))))))

(defun hostname-matches-entry-p (entry-hostname hostname)
  (if (and (plusp (length entry-hostname))
           (char= (char entry-hostname 0) #\|))
      (handler-case (hashed-hostname-matches-p entry-hostname hostname)
        (error () nil))
      (ssh/config::patterns-match-p
       (uiop:split-string entry-hostname :separator '(#\,)) hostname)))

(defun canonical-host-key-type (key-type)
  (if (member key-type '("rsa-sha2-256" "rsa-sha2-512") :test #'string=)
      "ssh-rsa"
      key-type))

;;;; Known hosts file parsing

(defstruct known-hosts-entry
  raw-hostname
  key-type
  key-blob
  comment
  marker)

; may be NIL

(defun parse-known-hosts-line (line)
  (let* ((trimmed (string-trim '(#\Space #\Tab) line))
         (tokens (remove "" (uiop:split-string trimmed :separator '(#\Space #\Tab))
                         :test #'string=))
         (marker nil))
    (when (or (null tokens) (char= (char (first tokens) 0) #\#))
      (return-from parse-known-hosts-line nil))
    (when (char= (char (first tokens) 0) #\@)
      (unless (string= (pop tokens) "@revoked")
        (return-from parse-known-hosts-line nil))
      (setf marker :revoked))
    (when (>= (length tokens) 3)
      (make-known-hosts-entry
       :raw-hostname (first tokens)
       :key-type (canonical-host-key-type (second tokens))
       :key-blob (handler-case (base64-decode (third tokens))
                   (error () (return-from parse-known-hosts-line nil)))
       :comment (fourth tokens)
       :marker marker))))

(defun load-known-hosts (path)
  "Read PATH and return a list of KNOWN-HOSTS-ENTRY structures."
  (unless (probe-file path)
    (return-from load-known-hosts '()))
  (with-open-file (stream path
                          :direction :input
                          :element-type '(unsigned-byte 8))
    (let* ((octets (make-array (file-length stream)
                               :element-type '(unsigned-byte 8)))
           (octet-count (read-sequence octets stream)))
      (loop for start = 0 then (1+ newline)
            while (<= start octet-count)
            for newline = (position #x0a octets :start start :end octet-count)
            for raw-end = (or newline octet-count)
            for end = (if (and (> raw-end start)
                               (= (aref octets (1- raw-end)) #x0d))
                          (1- raw-end)
                          raw-end)
            for line = (handler-case
                           (babel:octets-to-string octets
                                                  :encoding :utf-8
                                                  :start start
                                                  :end end)
                         (babel-encodings:character-decoding-error () nil))
            for entry = (and line (parse-known-hosts-line line))
            when entry collect entry
            while newline))))

;;;; Appending a new entry (TOFU)

(defun known-hosts-lock-path (path)
  (merge-pathnames (format nil ".~A.lock" (file-namestring path)) path))

(defun try-create-known-hosts-lock (lock-path)
  (let ((stream (open lock-path
                      :direction :output
                      :if-exists nil
                      :if-does-not-exist :create)))
    (when stream
      (unwind-protect
           (progn
             (format stream "~D~%" (get-universal-time))
             t)
        (close stream)))))

(defun call-with-known-hosts-lock (path thunk)
  (ensure-directories-exist path)
  (let ((lock-path (known-hosts-lock-path path))
        (deadline (+ (get-universal-time)
                     *known-hosts-lock-timeout-seconds*)))
    (loop
      (when (try-create-known-hosts-lock lock-path)
        (return
          (unwind-protect
               (funcall thunk)
            (ignore-errors
             (delete-file lock-path)))))
      (when (>= (get-universal-time) deadline)
        (error 'known-hosts-lock-error :path lock-path))
      (sleep *known-hosts-lock-retry-delay-seconds*))))

(defun add-known-host-unlocked (path hostname key-type key-blob)
  (ensure-directories-exist path)
  (with-open-file (f path :direction :output
                          :if-exists :append
                          :if-does-not-exist :create)
    (format f "~A ~A ~A~%" hostname key-type (base64-encode key-blob))))

(defun add-known-host (path hostname key-type key-blob)
  "Append a new entry to the known_hosts file at PATH."
  (call-with-known-hosts-lock
   path
   (lambda ()
     (add-known-host-unlocked path hostname key-type key-blob))))

(defun known-hosts-entry->line (entry)
  "Render ENTRY back to a known_hosts line."
  (format nil "~A ~A ~A~@[ ~A~]"
          (known-hosts-entry-raw-hostname entry)
          (known-hosts-entry-key-type entry)
          (base64-encode (known-hosts-entry-key-blob entry))
          (known-hosts-entry-comment entry)))

(defun update-known-hosts-unlocked (path hostname key-type key-blob)
  (let ((staging (merge-pathnames
                  (format nil ".~A.tmp" (gensym "KNOWN-HOSTS-")) path)))
    (unwind-protect
         (progn
           (with-open-file (in path :direction :input)
             (with-open-file (out staging :direction :output
                                          :if-exists :supersede
                                          :if-does-not-exist :create)
               (let ((written nil))
                 (loop for line = (read-line in nil nil)
                       while line
                       for entry = (parse-known-hosts-line line)
                       do (cond
                            ((and entry
                                  (null (known-hosts-entry-marker entry))
                                  (hostname-matches-entry-p
                                   (known-hosts-entry-raw-hostname entry) hostname)
                                  (string= (known-hosts-entry-key-type entry) key-type))
                             (let ((pattern (known-hosts-entry-raw-hostname entry)))
                               (cond
                                 ((or (string-equal pattern hostname)
                                      (char= (char pattern 0) #\|))
                                  (setf (known-hosts-entry-key-blob entry) key-blob)
                                  (write-line (known-hosts-entry->line entry) out)
                                  (setf written t))
                                 (t
                                  ;; Retain a shared pin for its other hosts.
                                  (setf (known-hosts-entry-raw-hostname entry)
                                        (format nil "~A,!~A" pattern hostname))
                                  (write-line (known-hosts-entry->line entry) out)))))
                            (t (write-line line out))))
                 (unless written
                   (format out "~A ~A ~A~%" hostname key-type (base64-encode key-blob))))))
           (uiop:rename-file-overwriting-target staging path)
           (setf staging nil))
      (when staging
        (ignore-errors (delete-file staging))))))

(defun update-known-hosts (path hostname key-type key-blob)
  "Rewrite matching known_hosts entries at PATH with KEY-BLOB."
  (call-with-known-hosts-lock
   path
   (lambda ()
     (update-known-hosts-unlocked path hostname key-type key-blob))))

;;;; Main entry point

(defun normalize-host-key-policy (value)
  "Normalize VALUE to a host-key checking policy.
VALUE accepts T or :YES for strict checking, NIL or :NO for permissive
checking, and :ACCEPT-NEW for trust on first use without changed-key updates.
The configuration sentinels :UNSET, :DEFAULT, and :ASK select strict checking.
Returns :YES, :ACCEPT-NEW, or :NO."
  (cond
    ((member value '(t :yes :unset :default :ask)) :yes)
    ((member value '(nil :no)) :no)
    ((eq value :accept-new) :accept-new)
    (t
     (error "Invalid strict host-key checking policy: ~S" value))))

(defun check-host-key-unlocked
    (hostname key-type host-key-blob known-hosts-path policy)
  (let ((entries (load-known-hosts known-hosts-path))
        (received-fp (public-key-fingerprint host-key-blob)))
    (let ((matches
            (remove-if-not
             (lambda (entry)
               (and
                (hostname-matches-entry-p
                 (known-hosts-entry-raw-hostname entry)
                 hostname)
                (string= (known-hosts-entry-key-type entry) key-type)))
             entries)))
      ;; A matching revocation overrides every positive pin and every policy.
      (when (some (lambda (entry)
                    (and (eq :revoked (known-hosts-entry-marker entry))
                         (ironclad:constant-time-equal
                          (known-hosts-entry-key-blob entry) host-key-blob)))
                  matches)
        (error 'host-key-revoked-error :hostname hostname
               :received-fingerprint received-fp))
      (setf matches (remove-if #'known-hosts-entry-marker matches))
      (cond
        ((null matches)
         (if (eq policy :yes)
             (error 'unknown-host-key-error
                    :hostname hostname
                    :key-type key-type
                    :received-fingerprint received-fp)
             (progn
               (format
                *error-output*
                "~&Warning: permanently added '~A' (~A) to the list of known hosts.~%"
                hostname key-type)
               (add-known-host-unlocked
                known-hosts-path hostname key-type host-key-blob)
               :accepted-tofu)))
        ((some
          (lambda (entry)
            (ironclad:constant-time-equal
             (known-hosts-entry-key-blob entry)
             host-key-blob))
          matches)
         :accepted-known)
        (t
         (let ((expected-fp
                 (public-key-fingerprint
                  (known-hosts-entry-key-blob (first matches)))))
           (if (eq policy :no)
               (progn
                 (format
                  *error-output*
                  "~&Warning: host key for '~A' has changed.~%~
                    Expected: ~A~%~
                    Received: ~A~%~
                    Proceeding (strict checking is disabled).~%"
                  hostname expected-fp received-fp)
                 (update-known-hosts-unlocked
                  known-hosts-path hostname key-type host-key-blob)
                 :accepted-changed)
               (error 'host-key-changed-error
                      :hostname hostname
                      :expected-fingerprint expected-fp
                      :received-fingerprint received-fp))))))))

(defun check-host-key
    (hostname key-type host-key-blob
     &key (known-hosts-path (default-known-hosts-path)) (strict :yes))
  "Verify HOST-KEY-BLOB according to the selected known_hosts policy.
HOSTNAME is the server hostname string.
KEY-TYPE is the key format or negotiated algorithm; RSA SHA-2 uses ssh-rsa pins.
Matching @revoked entries are rejected under every policy.
HOST-KEY-BLOB is the server's raw public key blob.
KNOWN-HOSTS-PATH names the known_hosts file.
STRICT accepts :YES/T, :ACCEPT-NEW, or :NO/NIL.
Returns :ACCEPTED-KNOWN, :ACCEPTED-TOFU, or :ACCEPTED-CHANGED."
  (let ((policy (normalize-host-key-policy strict)))
    (call-with-known-hosts-lock
     known-hosts-path
     (lambda ()
       (check-host-key-unlocked
        hostname (canonical-host-key-type key-type) host-key-blob known-hosts-path policy)))))
