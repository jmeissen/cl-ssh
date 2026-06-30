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
                #:+msg-service-request+
                #:+msg-service-accept+
                #:+msg-disconnect+
                #:+msg-ignore+
                #:+msg-debug+
                #:+msg-unimplemented+
                #:+service-userauth+
                #:+cipher-aes128-ctr+
                #:+cipher-aes256-ctr+
                #:+mac-hmac-sha2-256+
                #:+mac-hmac-sha2-512+
                #:+client-version-string+
                #:+ext-info-c+
                #:+disconnect-protocol-error+)
  (:import-from #:ssh/buffer
                #:make-write-buffer #:write-byte* #:write-uint32 #:write-string*
                #:buffer-to-octets
                #:make-read-buffer #:read-byte* #:read-uint32 #:read-string*
                #:read-remaining-bytes #:read-name-list)
  (:import-from #:ssh/packet
                #:make-packet-stream #:send-packet #:recv-packet #:install-keys
                #:make-hmac-mac-fn #:ssh-protocol-error
                #:packet-stream-packets-out #:packet-stream-packets-in
                #:packet-stream-bytes-out #:packet-stream-bytes-in)
  (:import-from #:ssh/algorithms
                 #:kexinit-payload #:parse-kexinit #:kexinit-kex-algorithms
                 #:negotiate-algorithms
                 #:negotiated-kex #:negotiated-host-key
                 #:negotiated-cipher-c2s #:negotiated-cipher-s2c
                 #:negotiated-mac-c2s #:negotiated-mac-s2c)
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

(defstruct transport
  packet-stream
  session-id
  server-sig-algs
  hostname
  client-version
  server-version
  known-hosts-path
  (strict-host-checking t)
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

;;;; Algorithm → Ironclad cipher mapping

(defun cipher-key-length (algorithm)
  "Return the key length in bytes for the named cipher algorithm."
  (cond ((string= algorithm +cipher-aes128-ctr+) 16)
        ((string= algorithm +cipher-aes256-ctr+) 32)
        (t (error 'transport-error
                  :message (format nil "unsupported cipher: ~S" algorithm)))))

(defun cipher-block-size (algorithm)
  "Return the block/IV size in bytes for the named cipher algorithm."
  (cond ((string= algorithm +cipher-aes128-ctr+) 16)
        ((string= algorithm +cipher-aes256-ctr+) 16)
        (t (error 'transport-error
                  :message (format nil "unsupported cipher: ~S" algorithm)))))

(defun mac-key-length (algorithm)
  "Return the MAC key length in bytes for the named MAC algorithm."
  (cond ((string= algorithm +mac-hmac-sha2-256+) 32)
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

(defun parse-ext-info-payload (payload)
  "Parse SSH_MSG_EXT_INFO and return an alist of extension names to raw values."
  (handler-case
      (let ((buf (make-read-buffer payload :start 1)))
        (let ((count (read-uint32 buf))
              (extensions '()))
          (loop repeat count
                do
            (push (cons (map 'string #'code-char (read-string* buf))
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

(defun process-ext-info (transport payload)
  "Update TRANSPORT state from an SSH_MSG_EXT_INFO payload."
  (let ((extensions (parse-ext-info-payload payload)))
    (setf (transport-server-sig-algs transport)
          (let ((entry (assoc "server-sig-algs" extensions :test #'string=)))
            (when entry
              (csv-string-to-name-list
               (map 'string #'code-char (cdr entry))))))
    nil))

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

(defun install-kex-result-keys (packet-stream kex-result negotiated direction)
  (ecase direction
    (:out
     (let* ((cipher-name (negotiated-cipher-c2s negotiated))
            (mac-name    (negotiated-mac-c2s negotiated))
            (iv          (prefix-octets (kex-result-iv-c2s kex-result)
                                        (cipher-block-size cipher-name)))
            (key         (prefix-octets (kex-result-key-c2s kex-result)
                                        (cipher-key-length cipher-name)))
            (mac-key     (prefix-octets (kex-result-mac-c2s kex-result)
                                        (mac-key-length mac-name))))
       (install-keys packet-stream
         :cipher-out     (make-aes-ctr-cipher key iv)
         :block-size-out (cipher-block-size cipher-name)
         :mac-out        (make-hmac-mac-fn mac-key (mac-digest-name mac-name))
         :mac-length-out (mac-output-length mac-name))))
    (:in
     (let* ((cipher-name (negotiated-cipher-s2c negotiated))
            (mac-name    (negotiated-mac-s2c negotiated))
            (iv          (prefix-octets (kex-result-iv-s2c kex-result)
                                        (cipher-block-size cipher-name)))
            (key         (prefix-octets (kex-result-key-s2c kex-result)
                                        (cipher-key-length cipher-name)))
            (mac-key     (prefix-octets (kex-result-mac-s2c kex-result)
                                        (mac-key-length mac-name))))
       (install-keys packet-stream
         :cipher-in      (make-aes-ctr-cipher key iv)
         :block-size-in  (cipher-block-size cipher-name)
         :mac-in         (make-hmac-mac-fn mac-key (mac-digest-name mac-name))
         :mac-length-in  (mac-output-length mac-name))))))

(defun perform-negotiated-key-exchange (transport client-kexinit-payload server-kexinit-payload)
  (unless (= (or (payload-message-type server-kexinit-payload) -1) +msg-kexinit+)
    (error 'transport-error
           :message (format nil "expected KEXINIT (20), got ~D"
                            (or (payload-message-type server-kexinit-payload) -1))))
  (let* ((packet-stream (transport-packet-stream transport))
         (server-kexinit (parse-kexinit server-kexinit-payload)))
    (validate-server-kexinit server-kexinit)
    (let* ((neg (negotiate-algorithms server-kexinit))
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
                           :iv-length (max (cipher-block-size cipher-c2s)
                                           (cipher-block-size cipher-s2c))
                           :cipher-key-length (max (cipher-key-length cipher-c2s)
                                                   (cipher-key-length cipher-s2c))
                           :mac-key-length (max (mac-key-length mac-c2s-name)
                                                (mac-key-length mac-s2c-name)))))
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
        (install-kex-result-keys packet-stream kex-result neg :out)
        (let ((newkeys-pkt (recv-packet packet-stream)))
          (unless (= (or (payload-message-type newkeys-pkt) -1) +msg-newkeys+)
            (error 'transport-error
                   :message (format nil "expected NEWKEYS (21), got ~D"
                                    (or (payload-message-type newkeys-pkt) -1)))))
        (install-kex-result-keys packet-stream kex-result neg :in)
        (setf (transport-session-id transport)
              (kex-result-session-id kex-result))
        (note-key-exchange-complete transport)
        kex-result))))

(defun receive-server-kexinit-for-rekey (transport)
  (let ((packet-stream (transport-packet-stream transport)))
    (loop
      for packet = (recv-packet packet-stream)
      for type = (payload-message-type packet)
      do (case type
           (#.+msg-kexinit+ (return packet))
           (#.+msg-ignore+ nil)
           (#.+msg-debug+ nil)
           (#.+msg-ext-info+ (process-ext-info transport packet))
           (#.+msg-disconnect+
            (error 'transport-error :message "server sent SSH_MSG_DISCONNECT"))
           (otherwise
            (enqueue-pending-packet transport packet))))))

(defun perform-initial-key-exchange (transport)
  (let* ((packet-stream (transport-packet-stream transport))
         (client-kexinit (kexinit-payload :include-ext-info-c-p t)))
    (send-packet packet-stream client-kexinit)
    (perform-negotiated-key-exchange
     transport
     client-kexinit
     (recv-packet packet-stream))))

(defun transport-rekey (transport &key server-kexinit-payload)
  (when (transport-rekeying-p transport)
    (return-from transport-rekey nil))
  (let* ((packet-stream (transport-packet-stream transport))
         (client-kexinit (kexinit-payload :include-ext-info-c-p nil)))
    (setf (transport-rekeying-p transport) t)
    (unwind-protect
         (let ((server-payload
                 (if server-kexinit-payload
                     (progn
                       (send-packet packet-stream client-kexinit)
                       server-kexinit-payload)
                     (progn
                       (send-packet packet-stream client-kexinit)
                       (receive-server-kexinit-for-rekey transport)))))
           (perform-negotiated-key-exchange transport client-kexinit server-payload))
      (setf (transport-rekeying-p transport) nil))))

;;;; Main setup

(defun connect-transport (hostname
                          &key (port 22)
                            (known-hosts-path nil)
                            (strict-host-checking t)
                            (rekey-byte-limit +default-rekey-byte-limit+)
                            (rekey-seconds-limit +default-rekey-seconds-limit+))
  "Open a TCP connection to HOSTNAME:PORT, perform the full SSH transport
   handshake (version exchange, KEX, host-key verification, NEWKEYS, service
   request), and return a TRANSPORT struct ready for use by the auth layer.

   KNOWN-HOSTS-PATH  — pathname for the known_hosts file; NIL uses the default.
   STRICT-HOST-CHECKING — if true (default), refuse changed host keys."
  (let* ((socket (usocket:socket-connect hostname port
                                         :element-type '(unsigned-byte 8)))
         (stream (usocket:socket-stream socket))
         (ps (make-packet-stream stream))
         (transport (make-transport :packet-stream ps
                                    :hostname hostname
                                    :known-hosts-path known-hosts-path
                                    :strict-host-checking strict-host-checking
                                    :rekey-byte-limit (normalize-rekey-limit
                                                       rekey-byte-limit
                                                       +default-rekey-byte-limit+)
                                    :rekey-seconds-limit (normalize-rekey-limit
                                                          rekey-seconds-limit
                                                          +default-rekey-seconds-limit+)
                                    :socket socket)))

    (handler-bind ((error (lambda (e)
                            (declare (ignore e))
                            (ignore-errors (usocket:socket-close socket)))))

      ;; 1. Version exchange
      (send-version stream)
      (let* ((our-version (map '(vector (unsigned-byte 8)) #'char-code +client-version-string+))
             (server-version (recv-version stream)))
        (setf (transport-client-version transport) our-version
              (transport-server-version transport) server-version)

        (perform-initial-key-exchange transport)

        ;; Request the userauth service.
        (let ((svc-buf (make-write-buffer)))
          (write-byte* svc-buf +msg-service-request+)
          (write-string* svc-buf +service-userauth+)
          (send-packet ps (buffer-to-octets svc-buf)))

        ;; Expect SSH_MSG_SERVICE_ACCEPT.
        (let ((svc-reply (transport-recv-skipping-global
                          transport +msg-service-accept+)))
          (declare (ignore svc-reply)))

        transport))))

;;;; Message dispatch helpers

(defun transport-recv-skipping-global (transport expected-type)
  "Receive packets, silently handling IGNORE/DEBUG/UNIMPLEMENTED, until a
   packet of EXPECTED-TYPE (or any non-global message) is found.
   Returns the payload."
  (let ((ps (transport-packet-stream transport)))
    (when (and (null (transport-pending-packets transport))
               (transport-rekey-needed-p transport))
      (transport-rekey transport))
    (loop
      for pkt = (or (dequeue-pending-packet transport)
                    (recv-packet ps))
      do (case (aref pkt 0)
           (#.+msg-ignore+ nil)   ; discard
           (#.+msg-debug+ nil)    ; discard (could log)
           (#.+msg-ext-info+ (process-ext-info transport pkt))
           (#.+msg-kexinit+
            (transport-rekey transport :server-kexinit-payload pkt))
           (#.+msg-disconnect+
            (error 'transport-error :message "server sent SSH_MSG_DISCONNECT"))
           (otherwise
            (when (and expected-type (/= (aref pkt 0) expected-type))
              (error 'transport-error
                     :message (format nil "expected message type ~D, got ~D"
                                      expected-type (aref pkt 0))))
            (return-from transport-recv-skipping-global pkt))))))

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
  "Send SSH_MSG_DISCONNECT and close the TCP connection."
  (ignore-errors
    (send-disconnect (transport-packet-stream transport)
                     11 reason))       ; 11 = SSH_DISCONNECT_BY_APPLICATION
  (ignore-errors
    (usocket:socket-close (transport-socket transport))))
