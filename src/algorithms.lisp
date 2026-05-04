;;;; SSH algorithm negotiation — RFC 4253 §7.1.
;;;;
;;;; Handles encoding and decoding of SSH_MSG_KEXINIT and the
;;;; first-match selection rule for each algorithm category.

(uiop:define-package ssh/algorithms
  (:use #:cl)
  (:import-from #:ssh/constants
                #:+msg-kexinit+
                #:+kex-curve25519-sha256+
                #:+kex-curve25519-sha256-libssh+
                #:+kex-dh-group14-sha256+
                #:+host-key-ed25519+
                #:+host-key-rsa-sha2-256+
                #:+host-key-rsa-sha2-512+
                #:+cipher-aes128-ctr+
                #:+cipher-aes256-ctr+
                #:+mac-hmac-sha2-256+
                #:+mac-hmac-sha2-512+
                #:+compression-none+)
  (:import-from #:ssh/buffer
                #:make-write-buffer #:write-byte* #:write-uint32 #:write-raw-bytes
                #:write-boolean #:write-name-list #:buffer-to-octets
                #:make-read-buffer #:read-byte* #:read-boolean #:read-uint32
                #:read-raw-bytes #:read-name-list)
  (:export
   #:+preferred-kex+
   #:+preferred-host-key+
   #:+preferred-cipher+
   #:+preferred-mac+
   #:+preferred-compression+
   #:kexinit-payload
   #:parse-kexinit
   #:negotiate-algorithms
   #:negotiated-kex
   #:negotiated-host-key
   #:negotiated-cipher-c2s
   #:negotiated-cipher-s2c
   #:negotiated-mac-c2s
   #:negotiated-mac-s2c
   #:negotiated-compression-c2s
   #:negotiated-compression-s2c))

(in-package #:ssh/algorithms)

;;;; Preference lists — ordered from most to least preferred

(defparameter +preferred-kex+
  (list +kex-curve25519-sha256+
        +kex-curve25519-sha256-libssh+
        +kex-dh-group14-sha256+)
  "Preferred KEX algorithms, most preferred first.")

(defparameter +preferred-host-key+
  (list +host-key-ed25519+
        +host-key-rsa-sha2-256+
        +host-key-rsa-sha2-512+)
  "Preferred host-key algorithms, most preferred first.")

(defparameter +preferred-cipher+
  (list +cipher-aes128-ctr+
        +cipher-aes256-ctr+)
  "Preferred symmetric ciphers, most preferred first.")

(defparameter +preferred-mac+
  (list +mac-hmac-sha2-256+
        +mac-hmac-sha2-512+)
  "Preferred MAC algorithms, most preferred first.")

(defparameter +preferred-compression+
  (list +compression-none+)
  "Preferred compression algorithms (none only for now).")

;;;; SSH_MSG_KEXINIT encoding (RFC 4253 §7.1)

(defun kexinit-payload ()
  "Build and return the full SSH_MSG_KEXINIT payload as an octet vector.
   The 16-byte random cookie is generated freshly each call."
  (let ((buf (make-write-buffer)))
    (write-byte* buf +msg-kexinit+)
    ;; 16 random cookie bytes
    (write-raw-bytes buf (ironclad:random-data 16))
    ;; Algorithm name-lists
    (write-name-list buf +preferred-kex+)
    (write-name-list buf +preferred-host-key+)
    (write-name-list buf +preferred-cipher+)   ; encryption client→server
    (write-name-list buf +preferred-cipher+)   ; encryption server→client
    (write-name-list buf +preferred-mac+)      ; MAC client→server
    (write-name-list buf +preferred-mac+)      ; MAC server→client
    (write-name-list buf +preferred-compression+) ; compression client→server
    (write-name-list buf +preferred-compression+) ; compression server→client
    (write-name-list buf '())                  ; languages client→server
    (write-name-list buf '())                  ; languages server→client
    (write-boolean buf nil)                    ; first_kex_packet_follows
    (write-uint32  buf 0)                      ; reserved
    (buffer-to-octets buf)))

;;;; SSH_MSG_KEXINIT parsing

(defstruct kexinit
  "Decoded contents of an SSH_MSG_KEXINIT message."
  cookie                 ; 16 raw bytes
  kex-algorithms
  server-host-key-algorithms
  encryption-algorithms-c2s
  encryption-algorithms-s2c
  mac-algorithms-c2s
  mac-algorithms-s2c
  compression-algorithms-c2s
  compression-algorithms-s2c
  languages-c2s
  languages-s2c
  first-kex-packet-follows)

(defun parse-kexinit (payload)
  "Parse PAYLOAD (the raw bytes of an SSH_MSG_KEXINIT message, including
   the message-type byte at index 0) and return a KEXINIT struct."
  (let ((buf (make-read-buffer payload)))
    ;; Skip message type byte (already verified by caller)
    (read-byte* buf)
    (make-kexinit
     :cookie                        (read-raw-bytes buf 16)
     :kex-algorithms                (read-name-list buf)
     :server-host-key-algorithms    (read-name-list buf)
     :encryption-algorithms-c2s     (read-name-list buf)
     :encryption-algorithms-s2c     (read-name-list buf)
     :mac-algorithms-c2s            (read-name-list buf)
     :mac-algorithms-s2c            (read-name-list buf)
     :compression-algorithms-c2s    (read-name-list buf)
     :compression-algorithms-s2c    (read-name-list buf)
     :languages-c2s                 (read-name-list buf)
     :languages-s2c                 (read-name-list buf)
     :first-kex-packet-follows      (read-boolean buf))))

;;;; Algorithm selection

(defun first-match (preferred peer)
  "Return the first element of PREFERRED that also appears in PEER,
   or NIL if there is no match (RFC 4253 §7.1 selection rule)."
  (dolist (name preferred nil)
    (when (member name peer :test #'string=)
      (return name))))

(defstruct negotiated
  "Results of algorithm negotiation between client and server."
  kex
  host-key
  cipher-c2s cipher-s2c
  mac-c2s    mac-s2c
  compression-c2s compression-s2c)

(defun negotiate-algorithms (server-kexinit)
  "Select algorithms by matching our preference lists against the server's
   KEXINIT.  Returns a NEGOTIATED struct or signals an error on failure."
  (flet ((pick (category our-list server-list)
           (or (first-match our-list server-list)
               (error "No common ~A algorithm with server~%  ours:   ~A~%  theirs: ~A"
                      category our-list server-list))))
    (make-negotiated
     :kex            (pick "KEX"
                           +preferred-kex+
                           (kexinit-kex-algorithms server-kexinit))
     :host-key       (pick "host-key"
                           +preferred-host-key+
                           (kexinit-server-host-key-algorithms server-kexinit))
     :cipher-c2s     (pick "cipher c→s"
                           +preferred-cipher+
                           (kexinit-encryption-algorithms-c2s server-kexinit))
     :cipher-s2c     (pick "cipher s→c"
                           +preferred-cipher+
                           (kexinit-encryption-algorithms-s2c server-kexinit))
     :mac-c2s        (pick "MAC c→s"
                           +preferred-mac+
                           (kexinit-mac-algorithms-c2s server-kexinit))
     :mac-s2c        (pick "MAC s→c"
                           +preferred-mac+
                           (kexinit-mac-algorithms-s2c server-kexinit))
     :compression-c2s (pick "compression c→s"
                            +preferred-compression+
                            (kexinit-compression-algorithms-c2s server-kexinit))
     :compression-s2c (pick "compression s→c"
                            +preferred-compression+
                            (kexinit-compression-algorithms-s2c server-kexinit)))))
