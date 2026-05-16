;;;; ~/.ssh/known_hosts management.
;;;;
;;;; Supports:
;;;;   - Plain hostname entries:   hostname key-type base64-key [comment]
;;;;   - Hashed hostname entries:  |1|<base64-salt>|<base64-hash> key-type base64-key
;;;;   - TOFU (trust on first use): add new hosts automatically
;;;;   - Strict checking: reject changed host keys
;;;;
;;;; Does not yet support:
;;;;   - Multiple hostnames in a single entry (comma-separated)
;;;;   - @cert-authority / @revoked markers
;;;;   - Port-qualified entries ([host]:port)

(uiop:define-package ssh/known-hosts
  (:use #:cl)
  (:import-from #:ssh/keys
                #:public-key-fingerprint
                #:key-error)
  (:export
   #:check-host-key
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
  "Return true if ENTRY-HOSTNAME (from a known_hosts line) matches HOSTNAME."
  (or (string= entry-hostname hostname)
      (hashed-hostname-matches-p entry-hostname hostname)))

;;;; Known hosts file parsing

(defstruct known-hosts-entry
  raw-hostname   ; the string as it appears in the file
  key-type       ; e.g. "ssh-ed25519"
  key-blob       ; raw decoded octet vector
  comment)       ; may be NIL

(defun parse-known-hosts-line (line)
  "Parse one line from known_hosts.  Returns a KNOWN-HOSTS-ENTRY or NIL
   if the line is blank, a comment, or unrecognised."
  (let ((trimmed (string-trim '(#\Space #\Tab) line)))
    (when (or (zerop (length trimmed))
              (char= (char trimmed 0) #\#))
      (return-from parse-known-hosts-line nil))
    ;; Skip @marker lines (cert-authority / revoked)
    (when (char= (char trimmed 0) #\@)
      (return-from parse-known-hosts-line nil))
    (let ((tokens (loop for start = 0 then (1+ end)
                        for end   = (position-if (lambda (c) (member c '(#\Space #\Tab)))
                                                  trimmed :start start)
                        for tok   = (subseq trimmed start (or end (length trimmed)))
                        unless (zerop (length tok)) collect tok
                        while end)))
      (when (>= (length tokens) 3)
        (make-known-hosts-entry
         :raw-hostname (first tokens)
         :key-type     (second tokens)
         :key-blob     (handler-case (base64-decode (third tokens))
                         (error () (return-from parse-known-hosts-line nil)))
         :comment      (when (>= (length tokens) 4) (fourth tokens)))))))

(defun load-known-hosts (path)
  "Read PATH and return a list of KNOWN-HOSTS-ENTRY structures."
  (unless (probe-file path)
    (return-from load-known-hosts '()))
  (with-open-file (f path :direction :input)
    (loop for line = (read-line f nil nil)
          while line
          for entry = (parse-known-hosts-line line)
          when entry collect entry)))

;;;; Appending a new entry (TOFU)

(defun add-known-host (path hostname key-type key-blob)
  "Append a new entry to the known_hosts file at PATH."
  (ensure-directories-exist path)
  (with-open-file (f path :direction :output
                          :if-exists :append
                          :if-does-not-exist :create)
    (format f "~A ~A ~A~%" hostname key-type (base64-encode key-blob))))

(defun known-hosts-entry->line (entry)
  "Render ENTRY back to a known_hosts line."
  (format nil "~A ~A ~A~@[ ~A~]"
          (known-hosts-entry-raw-hostname entry)
          (known-hosts-entry-key-type entry)
          (base64-encode (known-hosts-entry-key-blob entry))
          (known-hosts-entry-comment entry)))

(defun update-known-hosts (path hostname key-type key-blob)
  "Rewrite matching known_hosts entries at PATH with KEY-BLOB."
  (let ((staging (merge-pathnames
                  (format nil ".~A.tmp" (gensym "KNOWN-HOSTS-"))
                  path)))
    (unwind-protect
         (progn
           (with-open-file (in path :direction :input)
             (with-open-file (out staging :direction :output
                                          :if-exists :supersede
                                          :if-does-not-exist :create)
               (loop for line = (read-line in nil nil)
                     while line
                     for entry = (parse-known-hosts-line line)
                     do (if (and entry
                                 (hostname-matches-entry-p
                                  (known-hosts-entry-raw-hostname entry) hostname)
                                 (string= (known-hosts-entry-key-type entry)
                                          key-type))
                            (write-line (known-hosts-entry->line
                                         (make-known-hosts-entry
                                          :raw-hostname (known-hosts-entry-raw-hostname entry)
                                          :key-type (known-hosts-entry-key-type entry)
                                          :key-blob key-blob
                                          :comment (known-hosts-entry-comment entry)))
                                        out)
                            (write-line line out)))))
           (uiop:rename-file-overwriting-target staging path)
           (setf staging nil))
      (when staging
        (ignore-errors
         (delete-file staging))))))

;;;; Main entry point

(defun check-host-key (hostname key-type host-key-blob
                       &key (known-hosts-path (default-known-hosts-path))
                         (strict t))
  "Verify HOST-KEY-BLOB against the known_hosts file.

   HOSTNAME         — the server hostname string
   KEY-TYPE         — the negotiated host-key algorithm string
   HOST-KEY-BLOB    — the server's raw public key blob bytes
   KNOWN-HOSTS-PATH — pathname to the known_hosts file
   STRICT           — if true (default), reject changed keys; if false,
                      only warn and accept the new key

   Behaviour:
     - If the host is not known: TOFU — add it and proceed.
     - If the host is known with the same key: accept.
     - If the host is known with a different key: signal HOST-KEY-CHANGED-ERROR
       (when STRICT) or warn and update the entry (when not STRICT).

   Returns :accepted-known, :accepted-tofu, or :accepted-changed."
  (let ((entries (load-known-hosts known-hosts-path))
        (received-fp (public-key-fingerprint host-key-blob)))
    ;; Find all entries for this hostname and key type
    (let ((matches (remove-if-not
                    (lambda (e)
                      (and (hostname-matches-entry-p (known-hosts-entry-raw-hostname e) hostname)
                           (string= (known-hosts-entry-key-type e) key-type)))
                    entries)))
      (cond
        ;; No entry for this host+type: TOFU
        ((null matches)
         (format *error-output*
                 "~&Warning: permanently added '~A' (~A) to the list of known hosts.~%"
                 hostname key-type)
         (add-known-host known-hosts-path hostname key-type host-key-blob)
         :accepted-tofu)

        ;; At least one entry exists — check if any matches the received key
        ((some (lambda (e)
                 (ironclad:constant-time-equal (known-hosts-entry-key-blob e) host-key-blob))
               matches)
         :accepted-known)

        ;; Entry exists but key differs
        (t
         (let ((expected-fp (public-key-fingerprint
                             (known-hosts-entry-key-blob (first matches)))))
           (if strict
               (error 'host-key-changed-error
                      :hostname hostname
                      :expected-fingerprint expected-fp
                      :received-fingerprint received-fp)
               (progn
                 (format *error-output*
                         "~&Warning: host key for '~A' has changed.~%~
                           Expected: ~A~%~
                           Received: ~A~%~
                           Proceeding (strict checking is disabled).~%"
                         hostname expected-fp received-fp)
                 (update-known-hosts known-hosts-path hostname key-type host-key-blob)
                 :accepted-changed))))))))
