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
  (:import-from #:ssh/gcm
                #:gcm-seal #:gcm-open #:gcm-authentication-error)
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
   #:install-gcm-keys
   #:ssh-protocol-error))

(in-package #:ssh/packet)

;;;; Condition

(define-condition ssh-protocol-error (error)
  ((message :initarg :message :reader ssh-protocol-error-message))
  (:report (lambda (c s)
             (format s "SSH protocol error: ~A"
                     (ssh-protocol-error-message c)))))

;;;; Packet stream

(defstruct classic-protection
  cipher
  (block-size 8 :type (integer 1 256))
  mac
  (mac-length 0 :type fixnum))

(defstruct gcm-protection
  key
  iv
  (exhausted-p nil :type boolean))

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
  ;; Complete protection state is installed atomically per direction.
  (protection-out (make-classic-protection))
  (protection-in  (make-classic-protection)))

(defun make-packet-stream (socket-stream)
  "Return a new packet-stream over SOCKET-STREAM in cleartext mode."
  (%make-packet-stream :socket-stream socket-stream))

;;;; Key installation (called by transport after SSH_MSG_NEWKEYS)

(defun install-keys (ps &key cipher-out cipher-in
                          block-size-out block-size-in
                          mac-out mac-in
                          mac-length-out mac-length-in)
  "Install classic cipher and MAC state for selected packet directions.
PS is the packet stream whose directional protection is replaced.
CIPHER-OUT and CIPHER-IN are outbound and inbound Ironclad cipher objects.
BLOCK-SIZE-OUT and BLOCK-SIZE-IN control classic packet padding.
MAC-OUT and MAC-IN compute a MAC from a sequence number and plaintext packet.
MAC-LENGTH-OUT and MAC-LENGTH-IN are the corresponding wire lengths.
Returns PS."
  (when (or cipher-out block-size-out mac-out mac-length-out)
    (setf (packet-stream-protection-out ps)
          (make-classic-protection
           :cipher cipher-out
           :block-size (or block-size-out 8)
           :mac mac-out
           :mac-length (or mac-length-out 0))))
  (when (or cipher-in block-size-in mac-in mac-length-in)
    (setf (packet-stream-protection-in ps)
          (make-classic-protection
           :cipher cipher-in
           :block-size (or block-size-in 8)
           :mac mac-in
           :mac-length (or mac-length-in 0))))
  ps)

(defun install-gcm-keys (ps &key key-out iv-out key-in iv-in)
  "Install AES-GCM key and IV state for selected packet directions.
PS is the packet stream whose directional protection is replaced.
KEY-OUT and IV-OUT provide the outbound AES key and 12-octet initial IV.
KEY-IN and IV-IN provide the inbound AES key and 12-octet initial IV.
Returns PS."
  (labels ((make-protection (key iv direction)
             (unless (and key iv)
               (error 'ssh-protocol-error
                      :message (format nil "incomplete AES-GCM ~A key state"
                                       direction)))
             (unless (member (length key) '(16 32))
               (error 'ssh-protocol-error
                      :message "AES-GCM key length must be 16 or 32 octets"))
             (unless (= (length iv) 12)
               (error 'ssh-protocol-error
                      :message "AES-GCM IV length must be 12 octets"))
             (make-gcm-protection :key (copy-seq key) :iv (copy-seq iv))))
    (when (or key-out iv-out)
      (setf (packet-stream-protection-out ps)
            (make-protection key-out iv-out "outbound")))
    (when (or key-in iv-in)
      (setf (packet-stream-protection-in ps)
            (make-protection key-in iv-in "inbound"))))
  ps)

(defun reserve-gcm-iv (protection)
  (when (gcm-protection-exhausted-p protection)
    (error 'ssh-protocol-error
           :message "AES-GCM invocation counter exhausted"))
  (prog1 (copy-seq (gcm-protection-iv protection))
    (loop for index downfrom 11 to 4
          for byte = (aref (gcm-protection-iv protection) index)
          do (if (< byte 255)
                 (progn
                   (incf (aref (gcm-protection-iv protection) index))
                   (return))
                 (setf (aref (gcm-protection-iv protection) index) 0))
          finally (setf (gcm-protection-exhausted-p protection) t))))

;;;; Padding

(defun compute-padding (payload-length block-size)
  "Return the number of random padding bytes required.

   RFC 4253 §6: the total of (4 + 1 + payload + padding) must be a
   multiple of max(block-size, 8), and padding must be at least 4 bytes."
  (let* ((bs (max block-size 8))
         (base (+ 5 payload-length))    ; 4 (length field) + 1 (padding_length)
         (pad (- bs (mod base bs))))
    (if (< pad 4) (+ pad bs) pad)))

(defun compute-gcm-padding (payload-length)
  (let* ((base (1+ payload-length))
         (pad (- 16 (mod base 16))))
    (if (< pad 4) (+ pad 16) pad)))

(defun uint32-octets (value)
  (let ((octets (make-array 4 :element-type '(unsigned-byte 8))))
    (setf (aref octets 0) (ldb (byte 8 24) value)
          (aref octets 1) (ldb (byte 8 16) value)
          (aref octets 2) (ldb (byte 8 8) value)
          (aref octets 3) (ldb (byte 8 0) value))
    octets))

(defun octets-uint32 (octets)
  (logior (ash (aref octets 0) 24)
          (ash (aref octets 1) 16)
          (ash (aref octets 2) 8)
          (aref octets 3)))

(defun validate-packet-length (packet-length)
  (when (> packet-length 35000)
    (error 'ssh-protocol-error
           :message (format nil "packet_length ~D exceeds limit" packet-length)))
  (when (< packet-length 5)
    (error 'ssh-protocol-error
           :message (format nil "packet_length ~D is too small" packet-length))))

(defun extract-payload (body packet-length)
  (unless (= (length body) packet-length)
    (error 'ssh-protocol-error :message "packet body length mismatch"))
  (let* ((padding-length (aref body 0))
         (payload-length (- packet-length 1 padding-length)))
    (unless (<= 4 padding-length 255)
      (error 'ssh-protocol-error :message "invalid packet padding length"))
    (when (minusp payload-length)
      (error 'ssh-protocol-error :message "packet padding exceeds packet length"))
    (let ((payload (make-array payload-length
                               :element-type '(unsigned-byte 8))))
      (replace payload body :start2 1 :end2 (1+ payload-length))
      payload)))

;;;; Writing a packet to the stream

(defun %write-octets (stream octets)
  (write-sequence octets stream)
  (finish-output stream))

(defun send-classic-packet (ps protection payload seq)
  (let* ((plen (length payload))
         (padding (compute-padding plen (classic-protection-block-size protection)))
         (pad-bytes (ironclad:random-data padding))
         ;; packet_length = padding_length(1) + payload + padding
         (pkt-length (+ 1 plen padding))
         ;; Full plaintext: [packet_length:4][padding_length:1][payload][padding]
         (total (+ 4 pkt-length))
         (plaintext (make-array total :element-type '(unsigned-byte 8))))
    ;; Lay out plaintext
    (setf (aref plaintext 0) (ldb (byte 8 24) pkt-length)
          (aref plaintext 1) (ldb (byte 8 16) pkt-length)
          (aref plaintext 2) (ldb (byte 8 8) pkt-length)
          (aref plaintext 3) (ldb (byte 8 0) pkt-length)
          (aref plaintext 4) padding)
    (replace plaintext payload :start1 5)
    (replace plaintext pad-bytes :start1 (+ 5 plen))
    ;; Compute MAC over seq || plaintext (before encryption)
    (let ((mac (when (classic-protection-mac protection)
                 (funcall (classic-protection-mac protection) seq plaintext))))
      ;; Encrypt in place
      (when (classic-protection-cipher protection)
        (ironclad:encrypt-in-place (classic-protection-cipher protection) plaintext))
      ;; Send ciphertext then MAC
      (%write-octets (packet-stream-socket-stream ps) plaintext)
      (when mac
        (%write-octets (packet-stream-socket-stream ps) mac))
      (+ total (if mac (length mac) 0)))))

(defun send-gcm-packet (ps protection payload)
  (let* ((payload-length (length payload))
         (padding-length (compute-gcm-padding payload-length))
         (packet-length (+ 1 payload-length padding-length))
         (associated-data (uint32-octets packet-length))
         (body (make-array packet-length :element-type '(unsigned-byte 8)))
         (iv (reserve-gcm-iv protection)))
    (setf (aref body 0) padding-length)
    (replace body payload :start1 1)
    (replace body (ironclad:random-data padding-length)
             :start1 (1+ payload-length))
    (multiple-value-bind (ciphertext tag)
        (gcm-seal (gcm-protection-key protection) iv associated-data body)
      (%write-octets
       (packet-stream-socket-stream ps)
       (concatenate '(vector (unsigned-byte 8))
                    associated-data ciphertext tag))
      (+ 4 packet-length (length tag)))))

(defun send-packet (ps payload)
  "Encrypt and send PAYLOAD as one SSH binary packet.
PS is the packet stream with active outbound protection state.
PAYLOAD is an octet vector whose first byte is the SSH message type.
Returns the sequence number used for this packet."
  (declare (type packet-stream ps)
           (type (vector (unsigned-byte 8)) payload))
  (let* ((seq (packet-stream-seq-out ps))
         (protection (packet-stream-protection-out ps))
         (wire-length
           (etypecase protection
             (classic-protection
              (send-classic-packet ps protection payload seq))
             (gcm-protection
              (send-gcm-packet ps protection payload)))))
    (incf (packet-stream-packets-out ps))
    (incf (packet-stream-bytes-out ps) wire-length)
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

(defun recv-classic-packet (ps protection seq)
  (let* ((stream (packet-stream-socket-stream ps))
         (cipher-in (classic-protection-cipher protection))
         (bs (max (classic-protection-block-size protection) 8))
         (mac-len (classic-protection-mac-length protection))
         ;; Step 1: read and decrypt the first block to learn packet_length
         (first-block (%read-octets stream bs)))
    (when cipher-in
      (ironclad:decrypt-in-place cipher-in first-block))
    (let* ((pkt-length (octets-uint32 first-block))
           (total (+ 4 pkt-length))
           (remaining (- total bs))
           ;; Full plaintext buffer
           (plaintext (make-array total :element-type '(unsigned-byte 8))))
      (validate-packet-length pkt-length)
      (unless (and (>= total bs) (zerop (mod total bs)))
        (error 'ssh-protocol-error :message "misaligned classic packet"))
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
              (expected-mac (funcall (classic-protection-mac protection)
                                     seq plaintext)))
          (unless (ironclad:constant-time-equal received-mac expected-mac)
            (error 'ssh-protocol-error :message "MAC verification failed"))))
      (values (extract-payload (subseq plaintext 4) pkt-length)
              (+ total mac-len)))))

(defun recv-gcm-packet (ps protection)
  (let* ((stream (packet-stream-socket-stream ps))
         (associated-data (%read-octets stream 4))
         (packet-length (octets-uint32 associated-data)))
    (validate-packet-length packet-length)
    (unless (zerop (mod packet-length 16))
      (error 'ssh-protocol-error :message "misaligned AES-GCM packet"))
    (let ((ciphertext (%read-octets stream packet-length))
          (tag (%read-octets stream 16))
          (iv (reserve-gcm-iv protection)))
      (handler-case
          (values
           (extract-payload
            (gcm-open (gcm-protection-key protection)
                      iv associated-data ciphertext tag)
            packet-length)
           (+ 4 packet-length 16))
        (gcm-authentication-error ()
          (error 'ssh-protocol-error
                 :message "AES-GCM authentication failed"))))))

(defun recv-packet (ps)
  "Read, authenticate, decrypt, and return one SSH packet payload.
PS is the packet stream with active inbound protection state.
Returns an octet vector whose first byte is the SSH message type."
  (declare (type packet-stream ps))
  (let ((seq (packet-stream-seq-in ps))
        (protection (packet-stream-protection-in ps)))
    (multiple-value-bind (payload wire-length)
        (etypecase protection
          (classic-protection
           (recv-classic-packet ps protection seq))
          (gcm-protection
           (recv-gcm-packet ps protection)))
      (incf (packet-stream-packets-in ps))
      (incf (packet-stream-bytes-in ps) wire-length)
      (setf (packet-stream-seq-in ps) (ldb (byte 32 0) (1+ seq)))
      payload)))

;;;; MAC construction helper (used by transport to build MAC functions)

(defun make-hmac-mac-fn (key digest-name)
  "Return a MAC function (lambda (seq plaintext) -> octets) using HMAC.
   SEQ is a uint32 sequence number; PLAINTEXT is the full packet plaintext."
  (let ((mac (ironclad:make-mac :hmac key digest-name))
        (seq-buf (make-array 4 :element-type '(unsigned-byte 8))))
    (lambda (seq plaintext)
      (reinitialize-instance mac :key key)
      ;; MAC input: uint32(seq) || plaintext
      (setf (aref seq-buf 0) (ldb (byte 8 24) seq)
            (aref seq-buf 1) (ldb (byte 8 16) seq)
            (aref seq-buf 2) (ldb (byte 8 8) seq)
            (aref seq-buf 3) (ldb (byte 8 0) seq))
      (ironclad:update-mac mac seq-buf)
      (ironclad:update-mac mac plaintext)
      (ironclad:produce-mac mac))))
