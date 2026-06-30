;;;; Unit tests for ssh/packet — binary packet protocol.

(defpackage :ssh/tests/packet
  (:use :cl :parachute :trivial-gray-streams)
  (:import-from :ssh/tests #:octets)
  (:import-from :ssh/packet
    #:make-packet-stream
    #:send-packet
    #:recv-packet
    #:install-keys
    #:make-hmac-mac-fn
    #:ssh-protocol-error))

(in-package :ssh/tests/packet)

;;;; In-process loopback stream

(defclass pipe-stream (fundamental-binary-input-stream
                       fundamental-binary-output-stream)
  ((buffer   :initform (make-array 4096 :element-type '(unsigned-byte 8)
                                        :adjustable t :fill-pointer 0))
   (read-pos :initform 0)))

(defmethod stream-read-byte ((s pipe-stream))
  (with-slots (buffer read-pos) s
    (loop while (= read-pos (length buffer))
          do (error "pipe-stream underflow in test"))
    (prog1 (aref buffer read-pos)
      (incf read-pos))))

(defmethod stream-write-byte ((s pipe-stream) byte)
  (vector-push-extend byte (slot-value s 'buffer))
  byte)

(defmethod stream-write-sequence ((s pipe-stream) seq start end &key &allow-other-keys)
  (loop for i from start below end
        do (stream-write-byte s (elt seq i)))
  seq)

(defmethod stream-read-sequence ((s pipe-stream) seq start end &key &allow-other-keys)
  (loop for i from start below end
        do (setf (elt seq i) (stream-read-byte s)))
  end)

(defmethod stream-finish-output ((s pipe-stream)) nil)

(defun make-pipe ()
  (make-instance 'pipe-stream))

;;; ---- cleartext (no cipher, no MAC) -------------------------------------

(define-test cleartext-roundtrip
  :parent (:ssh/tests ssh/tests)
  (let* ((pipe    (make-pipe))
         (ps      (make-packet-stream pipe))
         (payload (octets 10 1 2 3 4 5)))
    (send-packet ps payload)
    (is equalp payload (recv-packet ps))))

(define-test cleartext-empty-payload
  :parent (:ssh/tests ssh/tests)
  (let* ((pipe    (make-pipe))
         (ps      (make-packet-stream pipe))
         (payload (octets 20)))
    (send-packet ps payload)
    (is equalp payload (recv-packet ps))))

(define-test cleartext-sequence-numbers
  :parent (:ssh/tests ssh/tests)
  (let* ((pipe (make-pipe))
         (ps   (make-packet-stream pipe)))
    (is = 0 (ssh/packet:packet-stream-seq-out ps))
    (is = 0 (ssh/packet:packet-stream-seq-in  ps))
    (send-packet ps (octets 1))
    (is = 1 (ssh/packet:packet-stream-seq-out ps))
    (send-packet ps (octets 2))
    (is = 2 (ssh/packet:packet-stream-seq-out ps))
    (recv-packet ps)
    (is = 1 (ssh/packet:packet-stream-seq-in  ps))
    (recv-packet ps)
    (is = 2 (ssh/packet:packet-stream-seq-in  ps))))

(define-test packet-stream-tracks-rekey-counters
  :parent (:ssh/tests ssh/tests)
  (let* ((pipe (make-pipe))
         (ps   (make-packet-stream pipe)))
    (is = 0 (ssh/packet:packet-stream-packets-out ps))
    (is = 0 (ssh/packet:packet-stream-packets-in ps))
    (is = 0 (ssh/packet:packet-stream-bytes-out ps))
    (is = 0 (ssh/packet:packet-stream-bytes-in ps))
    (send-packet ps (octets 2 3 4))
    (is = 1 (ssh/packet:packet-stream-packets-out ps))
    (true (plusp (ssh/packet:packet-stream-bytes-out ps)))
    (recv-packet ps)
    (is = 1 (ssh/packet:packet-stream-packets-in ps))
    (true (plusp (ssh/packet:packet-stream-bytes-in ps)))))

(define-test cleartext-multiple-packets
  :parent (:ssh/tests ssh/tests)
  (let* ((pipe (make-pipe))
         (ps   (make-packet-stream pipe)))
    (dotimes (i 10)
      (send-packet ps (octets i)))
    (dotimes (i 10)
      (is equalp (octets i) (recv-packet ps)))))

;;; ---- sequence number wrapping ------------------------------------------

(define-test sequence-number-wraps-at-32-bits
  :parent (:ssh/tests ssh/tests)
  (let* ((pipe (make-pipe))
         (ps   (make-packet-stream pipe)))
    (setf (ssh/packet:packet-stream-seq-out ps) #xFFFFFFFF)
    (send-packet ps (octets 99))
    (is = 0 (ssh/packet:packet-stream-seq-out ps))))

;;; ---- with AES-128-CTR + HMAC-SHA256 ------------------------------------

(define-test encrypted-roundtrip
  :parent (:ssh/tests ssh/tests)
  (let* ((pipe    (make-pipe))
         (ps      (make-packet-stream pipe))
         (key     (ironclad:random-data 16))
         (iv      (ironclad:random-data 16))
         (mac-key (ironclad:random-data 32))
         ;; Loopback: same key/IV for enc and dec, CTR is symmetric
         (cipher-out (ironclad:make-cipher :aes :mode :ctr
                                           :key key
                                           :initialization-vector iv))
         (cipher-in  (ironclad:make-cipher :aes :mode :ctr
                                           :key key
                                           :initialization-vector (copy-seq iv))))
    (install-keys ps
      :cipher-out     cipher-out
      :cipher-in      cipher-in
      :block-size-out 16
      :block-size-in  16
      :mac-out        (make-hmac-mac-fn mac-key :sha256)
      :mac-in         (make-hmac-mac-fn mac-key :sha256)
      :mac-length-out 32
      :mac-length-in  32)
    (let ((payload (octets 94 65 66 67 68 69)))
      (send-packet ps payload)
      (is equalp payload (recv-packet ps)))))

;;; ---- MAC failure --------------------------------------------------------

(define-test mac-failure-signals-error
  :parent (:ssh/tests ssh/tests)
  (let* ((pipe     (make-pipe))
         (ps-send  (make-packet-stream pipe))
         (ps-recv  (make-packet-stream pipe))
         (key      (ironclad:random-data 16))
         (iv       (ironclad:random-data 16))
         (mac-send (ironclad:random-data 32))
         (mac-recv (ironclad:random-data 32))   ; different — verification must fail
         (c-out    (ironclad:make-cipher :aes :mode :ctr :key key :initialization-vector iv))
         (c-in     (ironclad:make-cipher :aes :mode :ctr :key key
                                         :initialization-vector (copy-seq iv))))
    (install-keys ps-send
      :cipher-out c-out :block-size-out 16
      :mac-out    (make-hmac-mac-fn mac-send :sha256)
      :mac-length-out 32)
    (install-keys ps-recv
      :cipher-in c-in :block-size-in 16
      :mac-in    (make-hmac-mac-fn mac-recv :sha256)
      :mac-length-in 32)
    (send-packet ps-send (octets 1 2 3))
    (of-type 'ssh-protocol-error
      (handler-case (progn (recv-packet ps-recv) nil)
        (ssh-protocol-error (c) c)))))
