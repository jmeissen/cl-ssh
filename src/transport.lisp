;;;; SSH transport layer — RFC 4253.
;;;;
;;;; Drives the full setup sequence:
;;;;   1. TCP connection (via usocket)
;;;;   2. Version string exchange
;;;;   3. SSH_MSG_KEXINIT send and receive
;;;;   4. Algorithm negotiation
;;;;   5. Key exchange (curve25519-sha256)
;;;;   6. Host-key verification (known_hosts)
;;;;   7. SSH_MSG_NEWKEYS — install symmetric keys
;;;;   8. Service request (ssh-userauth)
;;;;
;;;; After setup, callers use TRANSPORT-SEND and TRANSPORT-RECV to
;;;; exchange encrypted application-layer packets.

(uiop:define-package ssh/transport
  (:use #:cl)
  (:import-from #:ssh/constants
                #:+msg-kexinit+
                #:+msg-newkeys+
                #:+msg-ext-info+
                #:+msg-newcompress+
                #:+msg-service-request+
                #:+msg-service-accept+
                #:+msg-userauth-success+
                #:+msg-disconnect+
                #:+msg-ignore+
                #:+msg-debug+
                #:+msg-unimplemented+
                #:+service-userauth+
                #:+cipher-aes128-ctr+
                #:+cipher-aes256-ctr+
                #:+cipher-aes128-gcm-openssh+
                #:+cipher-aes256-gcm-openssh+
                #:+aead-aes128-gcm+
                #:+aead-aes256-gcm+
                #:+mac-hmac-sha2-256+
                #:+mac-hmac-sha2-512+
                #:+client-version-string+
                #:+ext-info-c+
                #:+ext-info-s+
                #:+extension-delay-compression+
                #:+compression-none+
                #:+compression-zlib-openssh+
                #:+disconnect-protocol-error+
                #:+disconnect-key-exchange-failed+
                #:+disconnect-compression-error+)
  (:import-from #:ssh/buffer
                #:octets-to-ascii
                #:make-write-buffer #:write-byte* #:write-uint32 #:write-string*
                #:write-name-list
                #:buffer-to-octets
                #:make-read-buffer #:read-byte* #:read-uint32 #:read-string*
                #:read-remaining-bytes #:read-name-list)
  (:import-from #:ssh/packet
                #:make-packet-stream #:send-packet #:recv-packet
                #:install-keys #:install-gcm-keys #:install-compression
                #:make-hmac-mac-fn #:ssh-protocol-error
                #:packet-stream-packets-out #:packet-stream-packets-in
                #:packet-stream-bytes-out #:packet-stream-bytes-in)
  (:import-from #:ssh/algorithms
                #:kexinit-payload #:parse-kexinit #:kexinit-kex-algorithms
                #:kexinit-compression-algorithms-c2s
                #:kexinit-compression-algorithms-s2c
                #:negotiate-algorithms
                #:+preferred-compression+
                #:+preferred-delay-compression+
                #:gcm-cipher-p
                #:negotiated-kex #:negotiated-host-key
                #:negotiated-cipher-c2s #:negotiated-cipher-s2c
                #:negotiated-mac-c2s #:negotiated-mac-s2c
                #:negotiated-compression-c2s #:negotiated-compression-s2c)
  (:import-from #:ssh/compression
                #:compression-error)
  (:import-from #:ssh/kex
                #:perform-kex-curve25519
                #:perform-kex-dh-group14
                #:kex-result-session-id
                #:kex-result-iv-c2s #:kex-result-iv-s2c
                #:kex-result-key-c2s #:kex-result-key-s2c
                #:kex-result-mac-c2s #:kex-result-mac-s2c)
  (:import-from #:ssh/keys
                #:verify-host-key-signature)
  (:import-from #:ssh/known-hosts
                #:check-host-key)
  (:export
   #:transport
   #:transport-socket
   #:transport-packet-stream
   #:transport-session-id
   #:transport-hostname
   #:transport-send
   #:transport-recv
   #:transport-disconnect
   #:connect-transport
   #:transport-error))

(in-package #:ssh/transport)

;;;; Condition

(define-condition transport-error (error)
  ((message :initarg :message :reader transport-error-message))
  (:report (lambda (c s)
             (format s "SSH transport error: ~A" (transport-error-message c)))))

;;;; Transport structure

(defconstant +default-rekey-packet-limit+ #.(ash 1 28)
  "Default maximum packets sent or received with one set of keys.")

(defconstant +default-rekey-byte-limit+ #.(ash 1 30)
  "Default maximum bytes sent or received with one set of keys.")

(defconstant +default-rekey-seconds-limit+ 3600
  "Default maximum seconds to keep one set of keys.")

(defconstant +default-rekey-pending-packet-limit+ 1024
  "Default maximum non-KEX packets buffered while waiting for peer KEXINIT.")

(defconstant +default-rekey-pending-byte-limit+ #.(ash 1 26)
  "Default maximum non-KEX packet payload bytes buffered while waiting for peer KEXINIT.")

(defun normalize-rekey-limit (value default)
  (cond
    ((or (eq value :unset) (eq value :default)) default)
    ((or (null value)
         (and (integerp value) (plusp value)))
     value)
    (t
     (error 'transport-error
            :message (format nil "invalid rekey limit: ~S" value)))))

(defun normalize-compression-policy (value)
  (if (member value '(:none :zlib :delayed))
      value
      (error 'transport-error
             :message (format nil "invalid compression policy: ~S" value))))

(defstruct transport
  packet-stream
  session-id
  (strict-kex-p nil :type boolean)
  server-sig-algs
  (compression-policy :none)
  (server-ext-info-s-p nil :type boolean)
  (client-delay-compression-sent-p nil :type boolean)
  client-delay-compression-c2s
  client-delay-compression-s2c
  server-delay-compression-c2s
  server-delay-compression-s2c
  delayed-compression-c2s
  delayed-compression-s2c
  negotiated-compression-c2s
  negotiated-compression-s2c
  (authentication-complete-p nil :type boolean)
  (delayed-compression-triggered-p nil :type boolean)
  hostname
  client-version
  server-version
  known-hosts-path
  (strict-host-checking :yes)
  pending-packets
  (pending-packet-count 0 :type (integer 0 *))
  (pending-packet-bytes 0 :type (integer 0 *))
  (rekeying-p nil :type boolean)
  (last-rekey-packets-out 0 :type (integer 0 *))
  (last-rekey-packets-in 0 :type (integer 0 *))
  (last-rekey-bytes-out 0 :type (integer 0 *))
  (last-rekey-bytes-in 0 :type (integer 0 *))
  (last-rekey-time 0 :type (integer 0 *))
  (rekey-packet-limit +default-rekey-packet-limit+)
  (rekey-byte-limit +default-rekey-byte-limit+)
  (rekey-seconds-limit +default-rekey-seconds-limit+)
  (rekey-pending-packet-limit +default-rekey-pending-packet-limit+)
  (rekey-pending-byte-limit +default-rekey-pending-byte-limit+)
  ;; The raw socket (kept for cleanup)
  socket)

(defun transport-kex-compression-lists (transport)
  (let ((algorithms
          (case (transport-compression-policy transport)
            (:none (list +compression-none+))
            (:zlib +preferred-compression+)
            (:delayed
             (if (transport-authentication-complete-p transport)
                 +preferred-compression+
                 (list +compression-none+)))
            (otherwise
             (error 'transport-error
                    :message "invalid compression policy in transport")))))
    (values algorithms algorithms)))

(defun delayed-compression-rekey-blocked-p (transport)
  (and (eq (transport-compression-policy transport) :delayed)
       (not (transport-authentication-complete-p transport))))

(defun openssh-delayed-compression-p (algorithm)
  (and algorithm
       (string= algorithm +compression-zlib-openssh+)))

;;;; Algorithm → Ironclad cipher mapping

(defun cipher-key-length (algorithm)
  "Return the key length in bytes for the named cipher algorithm."
  (cond ((member algorithm
                 (list +cipher-aes128-ctr+
                       +cipher-aes128-gcm-openssh+
                       +aead-aes128-gcm+)
                 :test #'string=)
         16)
        ((member algorithm
                 (list +cipher-aes256-ctr+
                       +cipher-aes256-gcm-openssh+
                       +aead-aes256-gcm+)
                 :test #'string=)
         32)
        (t (error 'transport-error
                  :message (format nil "unsupported cipher: ~S" algorithm)))))

(defun cipher-block-size (algorithm)
  "Return the block size in bytes for the named cipher algorithm."
  (cond ((or (gcm-cipher-p algorithm)
             (string= algorithm +cipher-aes128-ctr+)
             (string= algorithm +cipher-aes256-ctr+))
         16)
        (t (error 'transport-error
                  :message (format nil "unsupported cipher: ~S" algorithm)))))

(defun cipher-iv-length (algorithm)
  "Return the KDF IV length in bytes for the named cipher algorithm."
  (if (gcm-cipher-p algorithm)
      12
      (cipher-block-size algorithm)))

(defun mac-key-length (algorithm)
  "Return the MAC key length in bytes for the named MAC algorithm."
  (cond ((or (null algorithm)
             (string= algorithm +aead-aes128-gcm+)
             (string= algorithm +aead-aes256-gcm+))
         0)
        ((string= algorithm +mac-hmac-sha2-256+) 32)
        ((string= algorithm +mac-hmac-sha2-512+) 64)
        (t (error 'transport-error
                  :message (format nil "unsupported MAC: ~S" algorithm)))))

(defun mac-output-length (algorithm)
  "Return the MAC output length in bytes."
  (cond ((string= algorithm +mac-hmac-sha2-256+) 32)
        ((string= algorithm +mac-hmac-sha2-512+) 64)
        (t (error 'transport-error
                  :message (format nil "unsupported MAC: ~S" algorithm)))))

(defun mac-digest-name (algorithm)
  "Return the Ironclad digest keyword for a MAC algorithm."
  (cond ((string= algorithm +mac-hmac-sha2-256+) :sha256)
        ((string= algorithm +mac-hmac-sha2-512+) :sha512)
        (t (error 'transport-error
                  :message (format nil "unsupported MAC: ~S" algorithm)))))

(defun make-aes-ctr-cipher (key iv)
  "Return an Ironclad AES/CTR cipher object."
  (ironclad:make-cipher :aes :mode :ctr :key key :initialization-vector iv))

;;;; Version string exchange (RFC 4253 §4.2)

(defun send-version (stream)
  "Send our SSH identification string."
  (let ((line (concatenate 'string +client-version-string+ (string #\Return) (string #\Newline))))
    (write-sequence (map '(vector (unsigned-byte 8)) #'char-code line) stream)
    (finish-output stream)))

(defun recv-version (stream)
  "Read the server's SSH identification string.
   Skips pre-banner lines.
   Accepts SSH-2.0 and SSH-1.99 compatibility identification strings.
   Returns the version string without CRLF as an octet vector."
  (let ((limit 254)) ; RFC 4253 caps the identification string at 255 chars incl. CRLF.
    (labels ((ssh-prefix-p (line)
               (and (= (length line) 4)
                    (char= (aref line 0) #\S)
                    (char= (aref line 1) #\S)
                    (char= (aref line 2) #\H)
                    (char= (aref line 3) #\-)))
             (read-line* ()
               (let ((line (make-array 32 :element-type 'character
                                           :adjustable t :fill-pointer 0))
                     (line-kind :unknown)
                     (count 0))
                 (loop for byte = (read-byte stream)
                       for char = (code-char byte)
                       do (cond
                            ((char= char #\Newline)
                             (return (values (coerce line 'string) line-kind)))
                            ((char= char #\Return)
                             (incf count)
                             (when (and (eq line-kind :ssh)
                                        (> count limit))
                               (error 'transport-error
                                      :message "server sent an overlong SSH identification string")))
                            (t
                             (incf count)
                             (case line-kind
                               (:ssh
                                (when (> count limit)
                                  (error 'transport-error
                                         :message "server sent an overlong SSH identification string"))
                                (vector-push-extend char line))
                               (:banner
                                nil)
                               (:unknown
                                (vector-push-extend char line)
                                (when (= (length line) 4)
                                  (setf line-kind (if (ssh-prefix-p line)
                                                      :ssh
                                                      :banner)))))))))))
      (loop
        (multiple-value-bind (line line-kind)
            (read-line*)
          (when (eq line-kind :ssh)
            (let* ((protocol-end (position #\- line :start 4))
                   (protocol (and protocol-end (subseq line 4 protocol-end))))
              (unless (member protocol '("2.0" "1.99") :test #'string=)
                (error 'transport-error
                       :message (format nil "server requires SSH protocol 2.0 or 1.99; got ~A"
                                        (or protocol line)))))
            (return (map '(vector (unsigned-byte 8)) #'char-code line))))))))

;;;; Disconnect helper

(defun send-disconnect (ps reason description)
  "Send SSH_MSG_DISCONNECT and close cleanly."
  (handler-case
      (let ((buf (make-write-buffer)))
        (write-byte*   buf +msg-disconnect+)
        (write-uint32  buf reason)
        (write-string* buf description)
        (write-string* buf "")              ; language tag (empty)
        (send-packet ps (buffer-to-octets buf)))
    (error () nil)))                        ; ignore errors during teardown

(defun recv-transport-packet (transport)
  (handler-case
      (recv-packet (transport-packet-stream transport))
    (compression-error (condition)
      (send-disconnect (transport-packet-stream transport)
                       +disconnect-compression-error+
                       (princ-to-string condition))
      (error condition))))

(defun parse-ext-info-payload (payload)
  "Parse SSH_MSG_EXT_INFO and return an alist of extension names to raw values."
  (handler-case
      (let ((buf (make-read-buffer payload :start 1)))
        (let ((count (read-uint32 buf))
              (extensions '()))
          (loop repeat count
                do (push (cons (octets-to-ascii (read-string* buf))
                               (read-string* buf))
                         extensions))
          (when (plusp (read-remaining-bytes buf))
            (error 'transport-error
                   :message "malformed SSH_MSG_EXT_INFO: trailing bytes"))
          (nreverse extensions)))
    (error (c)
      (error 'transport-error
             :message (format nil "malformed SSH_MSG_EXT_INFO: ~A" c)))))

(defun csv-string-to-name-list (string)
  (loop with start = 0
        for end = (position #\, string :start start)
        for item = (subseq string start end)
        unless (string= item "")
          collect item
        while end
        do (setf start (1+ end))))

(defun make-delay-compression-value (c2s s2c)
  (let ((buf (make-write-buffer)))
    (write-name-list buf c2s)
    (write-name-list buf s2c)
    (buffer-to-octets buf)))

(defun parse-delay-compression-value (value)
  (handler-case
      (let ((buf (make-read-buffer value)))
        (let ((c2s (read-name-list buf))
              (s2c (read-name-list buf)))
          (when (plusp (read-remaining-bytes buf))
            (error 'transport-error
                   :message "malformed delay-compression value: trailing bytes"))
          (values c2s s2c)))
    (transport-error (condition)
      (error condition))
    (error (condition)
      (error 'transport-error
             :message (format nil "malformed delay-compression value: ~A"
                              condition)))))

(defun first-common-compression (client-list server-list)
  (find-if (lambda (algorithm)
             (member algorithm server-list :test #'string=))
           client-list))

(defun recompute-delayed-compression (transport)
  (setf (transport-delayed-compression-c2s transport) nil
        (transport-delayed-compression-s2c transport) nil)
  (when (and (transport-client-delay-compression-sent-p transport)
             (transport-server-delay-compression-c2s transport)
             (transport-server-delay-compression-s2c transport))
    (let ((c2s (first-common-compression
                (transport-client-delay-compression-c2s transport)
                (transport-server-delay-compression-c2s transport)))
          (s2c (first-common-compression
                (transport-client-delay-compression-s2c transport)
                (transport-server-delay-compression-s2c transport))))
      (unless (and c2s s2c)
        (let ((message "no common RFC 8308 delayed compression algorithm"))
          ;; RFC 8308 section 3.2 requires the same disconnect behavior as
          ;; failed KEXINIT algorithm negotiation.
          (send-disconnect (transport-packet-stream transport)
                           +disconnect-key-exchange-failed+
                           message)
          (error 'transport-error :message message)))
      (setf (transport-delayed-compression-c2s transport) c2s
            (transport-delayed-compression-s2c transport) s2c))))

(defun make-client-delay-compression-ext-info (c2s s2c)
  (let ((buf (make-write-buffer)))
    (write-byte* buf +msg-ext-info+)
    (write-uint32 buf 1)
    (write-string* buf +extension-delay-compression+)
    (write-string* buf (make-delay-compression-value c2s s2c))
    (buffer-to-octets buf)))

(defun send-client-delay-compression-ext-info (transport)
  (when (and (eq (transport-compression-policy transport) :delayed)
             (transport-server-ext-info-s-p transport)
             (not (transport-client-delay-compression-sent-p transport)))
    (let ((c2s (copy-list +preferred-delay-compression+))
          (s2c (copy-list +preferred-delay-compression+)))
      ;; RFC 8308 section 2.4 requires this to be the next client packet after the
      ;; first NEWKEYS. The caller invokes this before any other send.
      (send-packet (transport-packet-stream transport)
                   (make-client-delay-compression-ext-info c2s s2c))
      (setf (transport-client-delay-compression-sent-p transport) t
            (transport-client-delay-compression-c2s transport) c2s
            (transport-client-delay-compression-s2c transport) s2c))))

(defun process-ext-info (transport payload)
  "Update TRANSPORT state from an SSH_MSG_EXT_INFO payload."
  (handler-case
      (let ((extensions (parse-ext-info-payload payload)))
        (setf (transport-server-sig-algs transport)
              (let ((entry (assoc "server-sig-algs" extensions :test #'string=)))
                (when entry
                  (csv-string-to-name-list
                   (octets-to-ascii (cdr entry))))))
        (let ((entry (assoc +extension-delay-compression+
                            extensions
                            :test #'string=)))
          (if entry
              (multiple-value-bind (c2s s2c)
                  (parse-delay-compression-value (cdr entry))
                (setf (transport-server-delay-compression-c2s transport) c2s
                      (transport-server-delay-compression-s2c transport) s2c))
              ;; RFC 8308 section 2.4 says a second server EXT_INFO replaces the
              ;; first, so absence removes an earlier delayed offer.
              (setf (transport-server-delay-compression-c2s transport) nil
                    (transport-server-delay-compression-s2c transport) nil))
          (recompute-delayed-compression transport))
        nil)
    (ssh/buffer:buffer-format-error (c)
      (error 'transport-error
             :message (format nil "malformed SSH_MSG_EXT_INFO: ~A" c)))))

(defun validate-server-kexinit (server-kexinit)
  "Reject role-incorrect extension markers in the server KEXINIT."
  (when (member +ext-info-c+
                (kexinit-kex-algorithms server-kexinit)
                :test #'string=)
    (error 'transport-error
           :message "server sent ext-info-c in KEXINIT")))

;;;; Key exchange / rekey helpers

(defun payload-message-type (payload)
  (when (plusp (length payload))
    (aref payload 0)))

(defun negotiate-strict-kex (transport client-kexinit server-kexinit)
  ;; The initial negotiation persists across rekeys, including absent markers.
  (unless (transport-session-id transport)
    (setf (transport-strict-kex-p transport)
          (and (not (null (member "kex-strict-c-v00@openssh.com"
                                  (kexinit-kex-algorithms client-kexinit)
                                  :test #'string=)))
               (not (null (member "kex-strict-s-v00@openssh.com"
                                  (kexinit-kex-algorithms server-kexinit)
                                  :test #'string=)))))
    ;; Use the non-wrapping count: a wrapped sequence number must not pass.
    (when (and (transport-strict-kex-p transport)
               (/= 1 (packet-stream-packets-in (transport-packet-stream transport))))
      (error 'transport-error :message "Strict KEX requires KEXINIT as the first packet")))
  (transport-strict-kex-p transport))

(defun delayed-compression-negotiated-p (transport)
  (and (transport-delayed-compression-c2s transport)
       (transport-delayed-compression-s2c transport)))

(defun note-userauth-success (transport)
  (unless (transport-authentication-complete-p transport)
    ;; USERAUTH_SUCCESS itself was decoded with the old inbound algorithm.
    ;; RFC 8308 activates the negotiated server-to-client algorithm for the
    ;; next message, so replace the context before receiving anything else.
    (when (delayed-compression-negotiated-p transport)
      (install-compression
       (transport-packet-stream transport)
       :in (transport-delayed-compression-s2c transport))
      ;; NEWCOMPRESS is the client trigger and is sent with the old outbound
      ;; algorithm. The fresh outbound context applies to the next message.
      (send-packet (transport-packet-stream transport)
                   (make-array 1
                               :element-type '(unsigned-byte 8)
                               :initial-element +msg-newcompress+))
      (install-compression
       (transport-packet-stream transport)
       :out (transport-delayed-compression-c2s transport))
      (setf (transport-delayed-compression-triggered-p transport) t))
    ;; OpenSSH's negotiated delayed-zlib method has no NEWCOMPRESS trigger.
    ;; Both contexts start after USERAUTH_SUCCESS itself has been decoded, so
    ;; the next packet in each direction begins a fresh zlib stream.
    (unless (delayed-compression-negotiated-p transport)
      (when (openssh-delayed-compression-p
             (transport-negotiated-compression-s2c transport))
        (install-compression
         (transport-packet-stream transport)
         :in (transport-negotiated-compression-s2c transport)))
      (when (openssh-delayed-compression-p
             (transport-negotiated-compression-c2s transport))
        (install-compression
         (transport-packet-stream transport)
         :out (transport-negotiated-compression-c2s transport))))
    (setf (transport-authentication-complete-p transport) t)))

(defun enqueue-pending-packet (transport packet)
  (let ((new-count (1+ (transport-pending-packet-count transport)))
        (new-bytes (+ (transport-pending-packet-bytes transport)
                      (length packet))))
    (when (or (> new-count (transport-rekey-pending-packet-limit transport))
              (> new-bytes (transport-rekey-pending-byte-limit transport)))
      (error 'transport-error
             :message "too many in-flight packets before rekey KEXINIT"))
    (setf (transport-pending-packets transport)
          (nconc (transport-pending-packets transport) (list packet))
          (transport-pending-packet-count transport) new-count
          (transport-pending-packet-bytes transport) new-bytes)))

(defun dequeue-pending-packet (transport)
  (let ((pending (transport-pending-packets transport)))
    (when pending
      (setf (transport-pending-packets transport) (rest pending))
      (decf (transport-pending-packet-count transport))
      (decf (transport-pending-packet-bytes transport) (length (first pending)))
      (first pending))))

(defun rekey-limit-reached-p (current baseline limit)
  (and limit
       (plusp limit)
       (>= (- current baseline) limit)))

(defun transport-rekey-needed-p (transport &key (now (get-universal-time)))
  (let ((ps (transport-packet-stream transport)))
    (and (transport-session-id transport)
         (not (transport-rekeying-p transport))
         (not (delayed-compression-rekey-blocked-p transport))
         (or (rekey-limit-reached-p (packet-stream-packets-out ps)
                                    (transport-last-rekey-packets-out transport)
                                    (transport-rekey-packet-limit transport))
             (rekey-limit-reached-p (packet-stream-packets-in ps)
                                    (transport-last-rekey-packets-in transport)
                                    (transport-rekey-packet-limit transport))
             (rekey-limit-reached-p (packet-stream-bytes-out ps)
                                    (transport-last-rekey-bytes-out transport)
                                    (transport-rekey-byte-limit transport))
             (rekey-limit-reached-p (packet-stream-bytes-in ps)
                                    (transport-last-rekey-bytes-in transport)
                                    (transport-rekey-byte-limit transport))
             (rekey-limit-reached-p now
                                    (transport-last-rekey-time transport)
                                    (transport-rekey-seconds-limit transport))))))

(defun note-key-exchange-complete (transport &key (now (get-universal-time)))
  (let ((ps (transport-packet-stream transport)))
    (setf (transport-last-rekey-packets-out transport) (packet-stream-packets-out ps)
          (transport-last-rekey-packets-in transport)  (packet-stream-packets-in ps)
          (transport-last-rekey-bytes-out transport)   (packet-stream-bytes-out ps)
          (transport-last-rekey-bytes-in transport)    (packet-stream-bytes-in ps)
          (transport-last-rekey-time transport)        now
          (transport-rekeying-p transport)             nil)))

(defun make-kex-host-key-verifier (transport host-key-algorithm)
  (lambda (host-key-blob exchange-hash sig-blob)
    (verify-host-key-signature
     host-key-algorithm host-key-blob exchange-hash sig-blob)
    (apply #'check-host-key
           (transport-hostname transport)
           host-key-algorithm
           host-key-blob
           (append
            (when (transport-known-hosts-path transport)
              (list :known-hosts-path (transport-known-hosts-path transport)))
            (list :strict (transport-strict-host-checking transport))))))

(defun send-newkeys (packet-stream)
  (let ((newkeys-buf (make-write-buffer)))
    (write-byte* newkeys-buf +msg-newkeys+)
    (send-packet packet-stream (buffer-to-octets newkeys-buf))))

(defun prefix-octets (octets length)
  (if (= (length octets) length)
      octets
      (subseq octets 0 length)))

(defun install-kex-result-keys (packet-stream kex-result negotiated direction
                                &key post-authentication-p)
  (ecase direction
    (:out
     (let* ((cipher-name (negotiated-cipher-c2s negotiated))
            (mac-name (negotiated-mac-c2s negotiated))
            (compression-name
              (or (negotiated-compression-c2s negotiated)
                  +compression-none+))
            (active-compression-name
              (if (and (openssh-delayed-compression-p compression-name)
                       (not post-authentication-p))
                  +compression-none+
                  compression-name))
            (iv (prefix-octets (kex-result-iv-c2s kex-result)
                               (cipher-iv-length cipher-name)))
            (key (prefix-octets (kex-result-key-c2s kex-result)
                                (cipher-key-length cipher-name))))
       (if (gcm-cipher-p cipher-name)
           (install-gcm-keys packet-stream :key-out key :iv-out iv)
           (let ((mac-key (prefix-octets (kex-result-mac-c2s kex-result)
                                         (mac-key-length mac-name))))
             (install-keys packet-stream
                           :cipher-out (make-aes-ctr-cipher key iv)
                           :block-size-out (cipher-block-size cipher-name)
                           :mac-out (make-hmac-mac-fn mac-key (mac-digest-name mac-name))
                           :mac-length-out (mac-output-length mac-name))))
       (install-compression packet-stream :out active-compression-name)))
    (:in
     (let* ((cipher-name (negotiated-cipher-s2c negotiated))
            (mac-name (negotiated-mac-s2c negotiated))
            (compression-name
              (or (negotiated-compression-s2c negotiated)
                  +compression-none+))
            (active-compression-name
              (if (and (openssh-delayed-compression-p compression-name)
                       (not post-authentication-p))
                  +compression-none+
                  compression-name))
            (iv (prefix-octets (kex-result-iv-s2c kex-result)
                               (cipher-iv-length cipher-name)))
            (key (prefix-octets (kex-result-key-s2c kex-result)
                                (cipher-key-length cipher-name))))
       (if (gcm-cipher-p cipher-name)
           (install-gcm-keys packet-stream :key-in key :iv-in iv)
           (let ((mac-key (prefix-octets (kex-result-mac-s2c kex-result)
                                         (mac-key-length mac-name))))
             (install-keys packet-stream
                           :cipher-in (make-aes-ctr-cipher key iv)
                           :block-size-in (cipher-block-size cipher-name)
                           :mac-in (make-hmac-mac-fn mac-key (mac-digest-name mac-name))
                           :mac-length-in (mac-output-length mac-name))))
       (install-compression packet-stream :in active-compression-name)))))

(defun %perform-negotiated-key-exchange (transport client-kexinit-payload server-kexinit-payload)
  (unless (= (or (payload-message-type server-kexinit-payload) -1) +msg-kexinit+)
    (error 'transport-error
           :message (format nil "expected KEXINIT (20), got ~D"
                            (or (payload-message-type server-kexinit-payload) -1))))
  (let* ((packet-stream (transport-packet-stream transport))
         (server-kexinit (parse-kexinit server-kexinit-payload))
         (client-kexinit (parse-kexinit client-kexinit-payload))
         (initial-exchange-p (null (transport-session-id transport))))
    (validate-server-kexinit server-kexinit)
    (negotiate-strict-kex transport client-kexinit server-kexinit)
    (when initial-exchange-p
      (setf (transport-server-ext-info-s-p transport)
            (not (null (member +ext-info-s+
                               (kexinit-kex-algorithms server-kexinit)
                               :test #'string=)))))
    (let* ((neg (negotiate-algorithms
                 server-kexinit
                 :compression-algorithms-c2s
                 (kexinit-compression-algorithms-c2s client-kexinit)
                 :compression-algorithms-s2c
                 (kexinit-compression-algorithms-s2c client-kexinit)))
           (kex-algo      (negotiated-kex neg))
           (host-key-algo (negotiated-host-key neg))
           (cipher-c2s    (negotiated-cipher-c2s neg))
           (cipher-s2c    (negotiated-cipher-s2c neg))
           (mac-c2s-name  (negotiated-mac-c2s neg))
           (mac-s2c-name  (negotiated-mac-s2c neg))
           (key-verifier  (make-kex-host-key-verifier transport host-key-algo))
           (kex-args (list packet-stream
                           (transport-client-version transport)
                           (transport-server-version transport)
                           client-kexinit-payload
                           server-kexinit-payload
                           (transport-session-id transport)
                           key-verifier
                           :iv-length (max (cipher-iv-length cipher-c2s)
                                           (cipher-iv-length cipher-s2c))
                           :cipher-key-length (max (cipher-key-length cipher-c2s)
                                                   (cipher-key-length cipher-s2c))
                           :mac-key-length (max (mac-key-length mac-c2s-name)
                                                (mac-key-length mac-s2c-name)))))
      (setf (transport-negotiated-compression-c2s transport)
            (negotiated-compression-c2s neg)
            (transport-negotiated-compression-s2c transport)
            (negotiated-compression-s2c neg))
      (let ((kex-result
              (cond
                ((or (string= kex-algo "curve25519-sha256")
                     (string= kex-algo "curve25519-sha256@libssh.org"))
                 (apply #'perform-kex-curve25519 kex-args))
                ((string= kex-algo "diffie-hellman-group14-sha256")
                 (apply #'perform-kex-dh-group14 kex-args))
                (t
                 (error 'transport-error
                        :message (format nil "negotiated unsupported KEX: ~S"
                                         kex-algo))))))
        (send-newkeys packet-stream)
        (when (transport-strict-kex-p transport)
          (setf (ssh/packet:packet-stream-seq-out packet-stream) 0))
        (install-kex-result-keys packet-stream kex-result neg :out
                                 :post-authentication-p
                                 (transport-authentication-complete-p transport))
        (when initial-exchange-p
          (send-client-delay-compression-ext-info transport))
        ;; The surrounding handler maps any decompression failure to exactly
        ;; one SSH_DISCONNECT_COMPRESSION_ERROR, including failures here.
        (let ((newkeys-pkt (recv-packet packet-stream)))
          (unless (and (= (length newkeys-pkt) 1)
                       (= (payload-message-type newkeys-pkt) +msg-newkeys+))
            (error 'transport-error
                   :message (format nil "expected NEWKEYS (21), got ~D"
                                    (or (payload-message-type newkeys-pkt) -1)))))
        (when (transport-strict-kex-p transport)
          (setf (ssh/packet:packet-stream-seq-in packet-stream) 0))
        (install-kex-result-keys packet-stream kex-result neg :in
                                 :post-authentication-p
                                 (transport-authentication-complete-p transport))
        (setf (transport-session-id transport)
              (kex-result-session-id kex-result))
        (note-key-exchange-complete transport)
        kex-result))))

(defun perform-negotiated-key-exchange (transport client-kexinit-payload server-kexinit-payload)
  (handler-case
      (%perform-negotiated-key-exchange
       transport client-kexinit-payload server-kexinit-payload)
    (compression-error (condition)
      ;; KEX implementations receive directly from PACKET-STREAM. Catch their
      ;; inflater failures here so RFC 4253's compression disconnect reason is
      ;; still sent during rekey.
      (send-disconnect (transport-packet-stream transport)
                       +disconnect-compression-error+
                       (princ-to-string condition))
      (error condition))
    ((or transport-error ssh-protocol-error) (condition)
      (send-disconnect (transport-packet-stream transport)
                       +disconnect-protocol-error+
                       "Key exchange protocol error")
      (error condition))))

(defun receive-server-kexinit-for-rekey (transport)
  (loop
    for packet = (recv-transport-packet transport)
    for type = (payload-message-type packet)
    do (case type
         (#.+msg-kexinit+ (return packet))
         (#.+msg-ignore+ nil)
         (#.+msg-debug+ nil)
         (#.+msg-ext-info+ (process-ext-info transport packet))
         (#.+msg-disconnect+
          (error 'transport-error :message "server sent SSH_MSG_DISCONNECT"))
         (otherwise
          (enqueue-pending-packet transport packet)))))

(defun perform-initial-key-exchange (transport)
  (multiple-value-bind (compression-c2s compression-s2c)
      (transport-kex-compression-lists transport)
    (let* ((packet-stream (transport-packet-stream transport))
           (client-kexinit
             (kexinit-payload
              :include-ext-info-c-p t
              :compression-algorithms-c2s compression-c2s
              :compression-algorithms-s2c compression-s2c)))
      (send-packet packet-stream client-kexinit)
      (perform-negotiated-key-exchange
       transport
       client-kexinit
       (recv-transport-packet transport)))))

(defun transport-rekey (transport &key server-kexinit-payload)
  (when (transport-rekeying-p transport)
    (return-from transport-rekey nil))
  (when (and (null server-kexinit-payload)
             (delayed-compression-rekey-blocked-p transport))
    (return-from transport-rekey nil))
  (multiple-value-bind (compression-c2s compression-s2c)
      (transport-kex-compression-lists transport)
    (let* ((packet-stream (transport-packet-stream transport))
           (client-kexinit
             (kexinit-payload
              :include-ext-info-c-p nil
              :compression-algorithms-c2s compression-c2s
              :compression-algorithms-s2c compression-s2c)))
      (setf (transport-rekeying-p transport) t)
      (unwind-protect
           (progn
             (send-packet packet-stream client-kexinit)
             (perform-negotiated-key-exchange
              transport client-kexinit
              (or server-kexinit-payload
                  (receive-server-kexinit-for-rekey transport))))
        (setf (transport-rekeying-p transport) nil)))))

;;;; Main setup

(defun connect-transport (hostname
                          &key (port 22) (known-hosts-path nil) (strict-host-checking :yes)
                            (compression :none)
                            (rekey-byte-limit +default-rekey-byte-limit+)
                            (rekey-seconds-limit +default-rekey-seconds-limit+))
  "Open a TCP connection and negotiate an SSH transport ready for authentication.
HOSTNAME names the remote SSH server.
PORT is its TCP port number.
KNOWN-HOSTS-PATH selects the host-key database, or NIL for the default.
STRICT-HOST-CHECKING selects the host-key verification policy.
COMPRESSION selects :NONE, :ZLIB, or :DELAYED compression.
REKEY-BYTE-LIMIT and REKEY-SECONDS-LIMIT select automatic rekey thresholds.
Returns the negotiated TRANSPORT, releasing its socket if setup unwinds."
  ;; Reject local option errors before allocating a socket.
  (let ((compression (normalize-compression-policy compression))
        (rekey-byte-limit (normalize-rekey-limit rekey-byte-limit +default-rekey-byte-limit+))
        (rekey-seconds-limit (normalize-rekey-limit rekey-seconds-limit +default-rekey-seconds-limit+))
        (socket nil)
        (transferred-p nil))
    (unwind-protect
         (progn
           (setf socket (usocket:socket-connect hostname port
                                               :element-type '(unsigned-byte 8)))
           (let* ((stream (usocket:socket-stream socket))
                  (ps (make-packet-stream stream))
                  (transport (make-transport :packet-stream ps :hostname hostname
                               :known-hosts-path known-hosts-path
                               :strict-host-checking strict-host-checking
                               :compression-policy compression
                               :rekey-byte-limit rekey-byte-limit
                               :rekey-seconds-limit rekey-seconds-limit :socket socket)))
             (send-version stream)
             (let* ((our-version (map '(vector (unsigned-byte 8)) #'char-code +client-version-string+))
                    (server-version (recv-version stream)))
               (setf (transport-client-version transport) our-version
                     (transport-server-version transport) server-version)
               (perform-initial-key-exchange transport)
               (let ((svc-buf (make-write-buffer)))
                 (write-byte* svc-buf +msg-service-request+)
                 (write-string* svc-buf +service-userauth+)
                 (send-packet ps (buffer-to-octets svc-buf)))
               (transport-recv-skipping-global transport +msg-service-accept+)
               (prog1 transport (setf transferred-p t)))))
      (unless transferred-p
        (when socket (ignore-errors (usocket:socket-close socket)))))))

;;;; Message dispatch helpers

(defun transport-recv-step (transport &optional expected-type)
  ;; Return after one transport message so the dispatcher can service queued work.
  ;; A key exchange itself must still finish before application traffic resumes.
  (when (and (null (transport-pending-packets transport))
             (transport-rekey-needed-p transport))
    (transport-rekey transport)
    (return-from transport-recv-step nil))
  (let ((pkt (or (dequeue-pending-packet transport)
                 (recv-transport-packet transport))))
    (case (aref pkt 0)
      (#.+msg-ignore+ nil)
      (#.+msg-debug+ nil)
      (#.+msg-ext-info+
       (process-ext-info transport pkt)
       nil)
      (#.+msg-kexinit+
       (transport-rekey transport :server-kexinit-payload pkt)
       nil)
      (#.+msg-disconnect+
       (error 'transport-error :message "server sent SSH_MSG_DISCONNECT"))
      (otherwise
       (when (= (aref pkt 0) +msg-userauth-success+)
         (note-userauth-success transport))
       (when (and expected-type (/= (aref pkt 0) expected-type))
         (error 'transport-error
                :message (format nil "expected message type ~D, got ~D"
                                 expected-type (aref pkt 0))))
       pkt))))

(defun transport-recv-skipping-global (transport expected-type)
  "Receive packets, silently handling IGNORE/DEBUG/UNIMPLEMENTED, until a
   packet of EXPECTED-TYPE (or any non-global message) is found.
   Returns the payload."
  (loop for packet = (transport-recv-step transport expected-type)
        when packet return packet))

;;;; Public send / recv

(defun transport-send (transport payload)
  "Send PAYLOAD as an encrypted SSH packet."
  (when (transport-rekey-needed-p transport)
    (transport-rekey transport))
  (send-packet (transport-packet-stream transport) payload))

(defun transport-recv (transport)
  "Receive the next application-layer packet, skipping IGNORE/DEBUG."
  (transport-recv-skipping-global transport nil))

(defun transport-disconnect (transport &optional (reason "normal closure"))
  "Send an SSH disconnect message and release the underlying TCP socket.
TRANSPORT is the transport to stop.
REASON is the description sent to the peer when possible.
Returns true after best-effort disconnection and socket cleanup."
  (unwind-protect
       (ignore-errors (send-disconnect (transport-packet-stream transport) 11 reason))
    (ignore-errors (usocket:socket-close (transport-socket transport))))
  t)
