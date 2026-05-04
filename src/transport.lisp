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
                #:+disconnect-protocol-error+)
  (:import-from #:ssh/buffer
                #:make-write-buffer #:write-byte* #:write-uint32 #:write-string*
                #:buffer-to-octets
                #:make-read-buffer #:read-byte* #:read-uint32 #:read-string*)
  (:import-from #:ssh/packet
                #:make-packet-stream #:send-packet #:recv-packet #:install-keys
                #:make-hmac-mac-fn #:ssh-protocol-error)
  (:import-from #:ssh/algorithms
                #:kexinit-payload #:parse-kexinit #:negotiate-algorithms
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

(defstruct transport
  packet-stream
  session-id
  hostname
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
   Skips lines that do not start with SSH-2.0 (pre-banner lines are allowed
   by RFC 4253 §4.2 as long as they do not start with 'SSH-').
   Returns the version string without CRLF as an octet vector."
  (loop
    (let ((line (with-output-to-string (s)
                  (loop for byte = (read-byte stream)
                        for char = (code-char byte)
                        until (char= char #\Newline)
                        unless (char= char #\Return)
                          do (write-char char s)))))
      (when (and (>= (length line) 7)
                 (string= (subseq line 0 4) "SSH-"))
        (unless (string= (subseq line 0 8) "SSH-2.0-")
          (error 'transport-error
                 :message (format nil "server requires SSH protocol ~A; only 2.0 is supported"
                                  (subseq line 4 (position #\- line :start 4)))))
        (return (map '(vector (unsigned-byte 8)) #'char-code line))))))

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

;;;; Main setup

(defun connect-transport (hostname
                           &key (port 22)
                                (known-hosts-path nil)
                                (strict-host-checking t))
  "Open a TCP connection to HOSTNAME:PORT, perform the full SSH transport
   handshake (version exchange, KEX, host-key verification, NEWKEYS, service
   request), and return a TRANSPORT struct ready for use by the auth layer.

   KNOWN-HOSTS-PATH  — pathname for the known_hosts file; NIL uses the default.
   STRICT-HOST-CHECKING — if true (default), refuse changed host keys."
  (let* ((socket  (usocket:socket-connect hostname port
                                          :element-type '(unsigned-byte 8)))
         (stream  (usocket:socket-stream socket))
         (ps      (make-packet-stream stream)))

    (handler-bind ((error (lambda (e)
                            (declare (ignore e))
                            (ignore-errors (usocket:socket-close socket)))))

      ;; 1. Version exchange
      (send-version stream)
      (let* ((our-version    (map '(vector (unsigned-byte 8)) #'char-code +client-version-string+))
             (server-version (recv-version stream)))

        ;; 2. Build and send our KEXINIT.
        (let ((our-kexinit (kexinit-payload)))
          (send-packet ps our-kexinit)

          ;; 3. Receive server KEXINIT
          (let ((server-kexinit-payload (recv-packet ps)))
            (unless (= (aref server-kexinit-payload 0) +msg-kexinit+)
              (error 'transport-error
                     :message (format nil "expected KEXINIT (20), got ~D"
                                      (aref server-kexinit-payload 0))))
            (let* ((server-kexinit (parse-kexinit server-kexinit-payload))
                   ;; 4. Negotiate algorithms
                   (neg (negotiate-algorithms server-kexinit))
                   (kex-algo      (negotiated-kex neg))
                   (host-key-algo (negotiated-host-key neg))
                   (cipher-c2s   (negotiated-cipher-c2s neg))
                   (cipher-s2c   (negotiated-cipher-s2c neg))
                   (mac-c2s-name (negotiated-mac-c2s neg))
                   (mac-s2c-name (negotiated-mac-s2c neg)))

              ;; 5. Key exchange — dispatch on negotiated algorithm.
              (let* ((key-verifier
                      ;; Host-key verifier closure shared by all KEX paths.
                      (lambda (host-key-blob exchange-hash sig-blob)
                        ;; a) Verify cryptographic signature.
                        (verify-host-key-signature
                         host-key-algo host-key-blob exchange-hash sig-blob)
                        ;; b) Check / update known_hosts.
                        (apply #'check-host-key
                               hostname host-key-algo host-key-blob
                               (append
                                (when known-hosts-path
                                  (list :known-hosts-path known-hosts-path))
                                (list :strict strict-host-checking)))))
                     (kex-args (list ps
                                     our-version
                                     server-version
                                     our-kexinit
                                     server-kexinit-payload
                                     nil          ; first exchange: no prior session-id
                                     key-verifier
                                     :iv-length         (cipher-block-size cipher-c2s)
                                     :cipher-key-length (cipher-key-length cipher-c2s)
                                     :mac-key-length    (mac-key-length mac-c2s-name))))
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

                ;; 6. Send SSH_MSG_NEWKEYS
                (let ((newkeys-buf (make-write-buffer)))
                  (write-byte* newkeys-buf +msg-newkeys+)
                  (send-packet ps (buffer-to-octets newkeys-buf)))

                ;; 7. Receive SSH_MSG_NEWKEYS from server
                (let ((newkeys-pkt (recv-packet ps)))
                  (unless (= (aref newkeys-pkt 0) +msg-newkeys+)
                    (error 'transport-error
                           :message (format nil "expected NEWKEYS (21), got ~D"
                                            (aref newkeys-pkt 0)))))

                ;; 8. Install symmetric keys
                (let* ((iv-c2s  (kex-result-iv-c2s  kex-result))
                       (iv-s2c  (kex-result-iv-s2c  kex-result))
                       (key-c2s (kex-result-key-c2s kex-result))
                       (key-s2c (kex-result-key-s2c kex-result))
                       (mac-c2s-key (kex-result-mac-c2s kex-result))
                       (mac-s2c-key (kex-result-mac-s2c kex-result)))
                  (install-keys ps
                    :cipher-out     (make-aes-ctr-cipher key-c2s iv-c2s)
                    :cipher-in      (make-aes-ctr-cipher key-s2c iv-s2c)
                    :block-size-out (cipher-block-size cipher-c2s)
                    :block-size-in  (cipher-block-size cipher-s2c)
                    :mac-out        (make-hmac-mac-fn mac-c2s-key (mac-digest-name mac-c2s-name))
                    :mac-in         (make-hmac-mac-fn mac-s2c-key (mac-digest-name mac-s2c-name))
                    :mac-length-out (mac-output-length mac-c2s-name)
                    :mac-length-in  (mac-output-length mac-s2c-name)))

                ;; 9. Request the userauth service
                (let ((svc-buf (make-write-buffer)))
                  (write-byte*   svc-buf +msg-service-request+)
                  (write-string* svc-buf +service-userauth+)
                  (send-packet ps (buffer-to-octets svc-buf)))

                ;; Expect SSH_MSG_SERVICE_ACCEPT
                (let ((svc-reply (transport-recv-skipping-global
                                   ps +msg-service-accept+)))
                  (declare (ignore svc-reply)))

                (make-transport
                 :packet-stream ps
                 :session-id    (kex-result-session-id kex-result)
                 :hostname      hostname
                 :socket        socket))))))))))

;;;; Message dispatch helpers

(defun transport-recv-skipping-global (ps expected-type)
  "Receive packets, silently handling IGNORE/DEBUG/UNIMPLEMENTED, until a
   packet of EXPECTED-TYPE (or any non-global message) is found.
   Returns the payload."
  (loop
    (let ((pkt (recv-packet ps)))
      (case (aref pkt 0)
        (#.+msg-ignore+        nil)   ; discard
        (#.+msg-debug+         nil)   ; discard (could log)
        (#.+msg-disconnect+
         (error 'transport-error :message "server sent SSH_MSG_DISCONNECT"))
        (otherwise
         (when (and expected-type (/= (aref pkt 0) expected-type))
           (error 'transport-error
                  :message (format nil "expected message type ~D, got ~D"
                                   expected-type (aref pkt 0))))
         (return pkt))))))

;;;; Public send / recv

(defun transport-send (transport payload)
  "Send PAYLOAD as an encrypted SSH packet."
  (send-packet (transport-packet-stream transport) payload))

(defun transport-recv (transport)
  "Receive the next application-layer packet, skipping IGNORE/DEBUG."
  (transport-recv-skipping-global (transport-packet-stream transport) nil))

(defun transport-disconnect (transport &optional (reason "normal closure"))
  "Send SSH_MSG_DISCONNECT and close the TCP connection."
  (ignore-errors
    (send-disconnect (transport-packet-stream transport)
                     11 reason))       ; 11 = SSH_DISCONNECT_BY_APPLICATION
  (ignore-errors
    (usocket:socket-close (transport-socket transport))))
