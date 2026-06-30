;;;; SSH binary packet protocol — RFC 4253 §6.
;;;;
;;;; A packet-stream wraps a socket stream and handles:
;;;;   - Padding calculation and random padding generation
;;;;   - Sequence number tracking (used in MAC computation)
;;;;   - Encryption / decryption via pluggable cipher objects
;;;;   - MAC computation and constant-time verification
;;;;
;;;; Cipher and MAC slots are NIL initially ("none" mode used during
;;;; version exchange and KEX).  Transport switches them after NEWKEYS.

(uiop:define-package ssh/packet
  (:use #:cl)
  (:import-from #:ssh/buffer
                #:make-write-buffer #:write-byte* #:write-uint32 #:write-raw-bytes
                #:buffer-to-octets
                #:make-read-buffer #:read-byte* #:read-uint32 #:read-raw-bytes
                #:read-remaining-bytes)
  (:export
   #:make-packet-stream
   #:packet-stream-socket-stream
   #:packet-stream-seq-out
   #:packet-stream-seq-in
   #:packet-stream-packets-out
   #:packet-stream-packets-in
   #:packet-stream-bytes-out
   #:packet-stream-bytes-in
   #:send-packet
   #:recv-packet
   #:install-keys
   #:ssh-protocol-error))

(in-package #:ssh/packet)

;;;; Condition

(define-condition ssh-protocol-error (error)
  ((message :initarg :message :reader ssh-protocol-error-message))
  (:report (lambda (c s)
             (format s "SSH protocol error: ~A"
                     (ssh-protocol-error-message c)))))

;;;; Packet stream

(defstruct (packet-stream (:constructor %make-packet-stream))
  socket-stream
  ;; Sequence numbers — uint32 wrapping (RFC 4253 §6.4)
  (seq-out 0 :type (unsigned-byte 32))
  (seq-in  0 :type (unsigned-byte 32))
  ;; Monotonic counters used by transport rekey policy.
  (packets-out 0 :type (integer 0 *))
  (packets-in  0 :type (integer 0 *))
  (bytes-out   0 :type (integer 0 *))
  (bytes-in    0 :type (integer 0 *))
  ;; Active cipher objects (or NIL for "none")
  cipher-out
  cipher-in
  ;; Block size governs padding; 8 when no cipher, 16 for AES
  (block-size-out 8 :type (integer 1 256))
  (block-size-in  8 :type (integer 1 256))
  ;; MAC functions: (funcall fn seq-uint32 plaintext-octets) -> mac-octets
  ;; NIL when MAC is "none"
  mac-out
  mac-in
  (mac-length-out 0 :type fixnum)
  (mac-length-in  0 :type fixnum))

(defun make-packet-stream (socket-stream)
  "Return a new packet-stream over SOCKET-STREAM in cleartext mode."
  (%make-packet-stream :socket-stream socket-stream))

;;;; Key installation (called by transport after SSH_MSG_NEWKEYS)

(defun install-keys (ps
                     &key cipher-out cipher-in
                          block-size-out block-size-in
                          mac-out mac-in
                          mac-length-out mac-length-in)
  "Swap in the negotiated cipher and MAC objects.
   CIPHER-OUT / CIPHER-IN are Ironclad cipher objects (or NIL).
   MAC-OUT / MAC-IN are functions (lambda (seq plaintext) -> octets)."
  (when cipher-out     (setf (packet-stream-cipher-out     ps) cipher-out))
  (when cipher-in      (setf (packet-stream-cipher-in      ps) cipher-in))
  (when block-size-out (setf (packet-stream-block-size-out ps) block-size-out))
  (when block-size-in  (setf (packet-stream-block-size-in  ps) block-size-in))
  (when mac-out        (setf (packet-stream-mac-out        ps) mac-out))
  (when mac-in         (setf (packet-stream-mac-in         ps) mac-in))
  (when mac-length-out (setf (packet-stream-mac-length-out ps) mac-length-out))
  (when mac-length-in  (setf (packet-stream-mac-length-in  ps) mac-length-in)))

;;;; Padding

(defun compute-padding (payload-length block-size)
  "Return the number of random padding bytes required.

   RFC 4253 §6: the total of (4 + 1 + payload + padding) must be a
   multiple of max(block-size, 8), and padding must be at least 4 bytes."
  (let* ((bs   (max block-size 8))
         (base (+ 5 payload-length))          ; 4 (length field) + 1 (padding_length)
         (pad  (- bs (mod base bs))))
    (if (< pad 4) (+ pad bs) pad)))

;;;; Writing a packet to the stream

(defun %write-octets (stream octets)
  (write-sequence octets stream)
  (finish-output stream))

(defun send-packet (ps payload)
  "Encrypt and send PAYLOAD as one SSH binary packet.

   PAYLOAD is a simple octet vector whose first byte is the SSH message
   type.  Returns the sequence number used for this packet."
  (declare (type packet-stream ps)
           (type (vector (unsigned-byte 8)) payload))
  (let* ((plen       (length payload))
         (padding    (compute-padding plen (packet-stream-block-size-out ps)))
         (pad-bytes  (ironclad:random-data padding))
         ;; packet_length = padding_length(1) + payload + padding
         (pkt-length (+ 1 plen padding))
         ;; Full plaintext: [packet_length:4][padding_length:1][payload][padding]
         (total      (+ 4 pkt-length))
         (plaintext  (make-array total :element-type '(unsigned-byte 8)))
         (seq        (packet-stream-seq-out ps)))
    ;; Lay out plaintext
    (setf (aref plaintext 0) (ldb (byte 8 24) pkt-length)
          (aref plaintext 1) (ldb (byte 8 16) pkt-length)
          (aref plaintext 2) (ldb (byte 8  8) pkt-length)
          (aref plaintext 3) (ldb (byte 8  0) pkt-length)
          (aref plaintext 4) padding)
    (replace plaintext payload   :start1 5)
    (replace plaintext pad-bytes :start1 (+ 5 plen))
    ;; Compute MAC over seq || plaintext (before encryption)
    (let ((mac (when (packet-stream-mac-out ps)
                 (funcall (packet-stream-mac-out ps) seq plaintext))))
      ;; Encrypt in place
      (when (packet-stream-cipher-out ps)
        (ironclad:encrypt-in-place (packet-stream-cipher-out ps) plaintext))
      ;; Send ciphertext then MAC
      (%write-octets (packet-stream-socket-stream ps) plaintext)
      (when mac
        (%write-octets (packet-stream-socket-stream ps) mac))
      (incf (packet-stream-bytes-out ps)
            (+ total (if mac (length mac) 0))))
    ;; Advance sequence number (wraps at 2^32)
    (incf (packet-stream-packets-out ps))
    (setf (packet-stream-seq-out ps) (ldb (byte 32 0) (1+ seq)))
    seq))

;;;; Reading a packet from the stream

(defun %read-octets (stream n)
  "Read exactly N bytes from STREAM into a fresh octet vector."
  (let ((buf (make-array n :element-type '(unsigned-byte 8))))
    (let ((got (read-sequence buf stream)))
      (unless (= got n)
        (error 'ssh-protocol-error
               :message (format nil "short read: expected ~D bytes, got ~D" n got))))
    buf))

(defun recv-packet (ps)
  "Read, decrypt, verify, and return the payload of one SSH binary packet.

   Returns a simple octet vector whose first byte is the SSH message type."
  (declare (type packet-stream ps))
  (let* ((stream     (packet-stream-socket-stream ps))
         (cipher-in  (packet-stream-cipher-in ps))
         (bs         (max (packet-stream-block-size-in ps) 8))
         (seq        (packet-stream-seq-in ps))
         (mac-len    (packet-stream-mac-length-in ps))
         ;; Step 1: read and decrypt the first block to learn packet_length
         (first-block (%read-octets stream bs)))
    (when cipher-in
      (ironclad:decrypt-in-place cipher-in first-block))
    (let* ((pkt-length (logior (ash (aref first-block 0) 24)
                               (ash (aref first-block 1) 16)
                               (ash (aref first-block 2)  8)
                                    (aref first-block 3)))
           ;; Sanity check — RFC 4253 §6.1 recommends rejecting > 35000 bytes
           (dummy (when (> pkt-length 35000)
                    (error 'ssh-protocol-error
                           :message (format nil "packet_length ~D exceeds limit" pkt-length))))
           (total      (+ 4 pkt-length))
           (remaining  (- total bs))
           ;; Full plaintext buffer
           (plaintext  (make-array total :element-type '(unsigned-byte 8))))
      (declare (ignore dummy))
      ;; Copy already-decrypted first block
      (replace plaintext first-block)
      ;; Step 2: read and decrypt the rest
      (when (plusp remaining)
        (let ((rest (%read-octets stream remaining)))
          (when cipher-in
            (ironclad:decrypt-in-place cipher-in rest))
          (replace plaintext rest :start1 bs)))
      ;; Step 3: read and verify MAC
      (when (plusp mac-len)
        (let ((received-mac (%read-octets stream mac-len))
              (expected-mac (funcall (packet-stream-mac-in ps) seq plaintext)))
          (unless (ironclad:constant-time-equal received-mac expected-mac)
            (error 'ssh-protocol-error :message "MAC verification failed"))))
      ;; Step 4: extract payload
      (let* ((padding-length (aref plaintext 4))
             (payload-length (- pkt-length 1 padding-length))
             (payload        (make-array payload-length :element-type '(unsigned-byte 8))))
        (replace payload plaintext :start2 5 :end2 (+ 5 payload-length))
        ;; Advance sequence number
        (incf (packet-stream-packets-in ps))
        (incf (packet-stream-bytes-in ps) (+ total mac-len))
        (setf (packet-stream-seq-in ps) (ldb (byte 32 0) (1+ seq)))
        payload))))

;;;; MAC construction helper (used by transport to build MAC functions)

(defun make-hmac-mac-fn (key digest-name)
  "Return a MAC function (lambda (seq plaintext) -> octets) using HMAC.
   SEQ is a uint32 sequence number; PLAINTEXT is the full packet plaintext."
  (lambda (seq plaintext)
    (let ((mac (ironclad:make-mac :hmac key digest-name)))
      ;; MAC input: uint32(seq) || plaintext
      (let ((seq-buf (make-array 4 :element-type '(unsigned-byte 8))))
        (setf (aref seq-buf 0) (ldb (byte 8 24) seq)
              (aref seq-buf 1) (ldb (byte 8 16) seq)
              (aref seq-buf 2) (ldb (byte 8  8) seq)
              (aref seq-buf 3) (ldb (byte 8  0) seq))
        (ironclad:update-mac mac seq-buf))
      (ironclad:update-mac mac plaintext)
      (ironclad:produce-mac mac))))
