;;;; Unit tests for ssh/buffer — RFC 4251 binary codec.
;;;;
;;;; All tests use static byte vectors and verify round-trip correctness.
;;;; No network, no crypto.

(defpackage :ssh/tests/buffer
  (:use :cl :parachute)
  (:import-from :ssh/tests #:octets)
  (:import-from :ssh/buffer
    #:make-write-buffer #:buffer-to-octets
    #:write-byte* #:write-boolean #:write-uint32 #:write-uint64
    #:write-string* #:write-mpint #:write-name-list #:write-raw-bytes
    #:make-read-buffer
    #:read-byte* #:read-boolean #:read-uint32 #:read-uint64
    #:read-string* #:read-mpint #:read-name-list #:read-raw-bytes
    #:read-remaining-bytes
    #:buffer-underflow))

(in-package :ssh/tests/buffer)

;;; ---- byte ---------------------------------------------------------------

(define-test byte-roundtrip
  :parent (:ssh/tests ssh/tests)
  (let ((buf (make-write-buffer)))
    (write-byte* buf 0)
    (write-byte* buf 127)
    (write-byte* buf 255)
    (is equalp (octets 0 127 255) (buffer-to-octets buf)))
  (let ((rbuf (make-read-buffer (octets 42 0 255))))
    (is = 42  (read-byte* rbuf))
    (is = 0   (read-byte* rbuf))
    (is = 255 (read-byte* rbuf))
    (is = 0   (read-remaining-bytes rbuf))))

;;; ---- boolean ------------------------------------------------------------

(define-test boolean-encoding
  :parent (:ssh/tests ssh/tests)
  (let ((buf (make-write-buffer)))
    (write-boolean buf nil)
    (write-boolean buf t)
    (is equalp (octets 0 1) (buffer-to-octets buf)))
  (let ((rbuf (make-read-buffer (octets 0 1 42))))
    (is eq nil (read-boolean rbuf))
    (is eq t   (read-boolean rbuf))
    ;; Any non-zero value is true
    (is eq t   (read-boolean rbuf))))

;;; ---- uint32 -------------------------------------------------------------

(define-test uint32-encoding
  :parent (:ssh/tests ssh/tests)
  (let ((buf (make-write-buffer)))
    (write-uint32 buf 0)
    (is equalp (octets 0 0 0 0) (buffer-to-octets buf)))
  (let ((buf (make-write-buffer)))
    (write-uint32 buf 1)
    (is equalp (octets 0 0 0 1) (buffer-to-octets buf)))
  (let ((buf (make-write-buffer)))
    (write-uint32 buf #xDEADBEEF)
    (is equalp (octets #xDE #xAD #xBE #xEF) (buffer-to-octets buf)))
  (let ((buf (make-write-buffer)))
    (write-uint32 buf #xFFFFFFFF)
    (is equalp (octets #xFF #xFF #xFF #xFF) (buffer-to-octets buf))))

(define-test uint32-roundtrip
  :parent (:ssh/tests ssh/tests)
  (dolist (n '(0 1 127 128 255 256 #xFFFF #x10000 #xFFFFFFFF))
    (let* ((buf  (make-write-buffer))
           (rbuf (progn (write-uint32 buf n)
                        (make-read-buffer (buffer-to-octets buf)))))
      (is = n (read-uint32 rbuf)))))

;;; ---- uint64 -------------------------------------------------------------

(define-test uint64-roundtrip
  :parent (:ssh/tests ssh/tests)
  (dolist (n '(0 1 #xFFFFFFFF #x100000000 #xFFFFFFFFFFFFFFFF))
    (let* ((buf  (make-write-buffer))
           (rbuf (progn (write-uint64 buf n)
                        (make-read-buffer (buffer-to-octets buf)))))
      (is = n (read-uint64 rbuf)))))

;;; ---- string* ------------------------------------------------------------

(define-test string-encoding
  :parent (:ssh/tests ssh/tests)
  (let ((buf (make-write-buffer)))
    (write-string* buf (octets))
    (is equalp (octets 0 0 0 0) (buffer-to-octets buf)))
  (let ((buf (make-write-buffer)))
    (write-string* buf (octets #x74 #x65 #x73 #x74))
    (is equalp (octets 0 0 0 4 #x74 #x65 #x73 #x74) (buffer-to-octets buf)))
  (let ((buf (make-write-buffer)))
    (write-string* buf "AB")
    (is equalp (octets 0 0 0 2 #x41 #x42) (buffer-to-octets buf))))

(define-test string-roundtrip
  :parent (:ssh/tests ssh/tests)
  (let* ((data (octets 1 2 3 4 5))
         (buf  (make-write-buffer))
         (rbuf (progn (write-string* buf data)
                      (make-read-buffer (buffer-to-octets buf)))))
    (is equalp data (read-string* rbuf))))

;;; ---- mpint — RFC 4251 §5 test vectors -----------------------------------

(define-test mpint-zero
  :parent (:ssh/tests ssh/tests)
  (let ((buf (make-write-buffer)))
    (write-mpint buf 0)
    (is equalp (octets 0 0 0 0) (buffer-to-octets buf)))
  (let ((rbuf (make-read-buffer (octets 0 0 0 0))))
    (is = 0 (read-mpint rbuf))))

(define-test mpint-positive-no-leading-zero
  :parent (:ssh/tests ssh/tests)
  ;; #x9a378f9b2e332a7 — high bit of first byte is 0, no leading zero needed
  (let* ((n        #x9a378f9b2e332a7)
         (buf      (make-write-buffer))
         (expected (octets 0 0 0 8 #x09 #xa3 #x78 #xf9 #xb2 #xe3 #x32 #xa7)))
    (write-mpint buf n)
    (is equalp expected (buffer-to-octets buf)))
  (let ((rbuf (make-read-buffer (octets 0 0 0 8 #x09 #xa3 #x78 #xf9 #xb2 #xe3 #x32 #xa7))))
    (is = #x9a378f9b2e332a7 (read-mpint rbuf))))

(define-test mpint-positive-needs-leading-zero
  :parent (:ssh/tests ssh/tests)
  ;; 0x80 = 128 — high bit set, needs leading 0x00
  (let* ((buf      (make-write-buffer))
         (expected (octets 0 0 0 2 0 #x80)))
    (write-mpint buf #x80)
    (is equalp expected (buffer-to-octets buf)))
  (let ((rbuf (make-read-buffer (octets 0 0 0 2 0 #x80))))
    (is = #x80 (read-mpint rbuf))))

(define-test mpint-negative
  :parent (:ssh/tests ssh/tests)
  ;; -1234: byte-count=2, twos-complement=0xFB2E, high bit set → no 0xFF prefix
  (let* ((buf (make-write-buffer)))
    (write-mpint buf -1234)
    (is equalp (octets 0 0 0 2 #xfb #x2e) (buffer-to-octets buf)))
  (let* ((buf  (make-write-buffer))
         (rbuf (progn (write-mpint buf -1234)
                      (make-read-buffer (buffer-to-octets buf)))))
    (is = -1234 (read-mpint rbuf))))

(define-test mpint-roundtrip-various
  :parent (:ssh/tests ssh/tests)
  (dolist (n (list 0 1 127 128 255 256 65535 65536
                   #xDEADBEEFCAFEBABE
                   -1 -128 -129 -256 -32768))
    (let* ((buf  (make-write-buffer))
           (rbuf (progn (write-mpint buf n)
                        (make-read-buffer (buffer-to-octets buf)))))
      (is = n (read-mpint rbuf)
          (format nil "mpint round-trip failed for ~D" n)))))

;;; ---- name-list ----------------------------------------------------------

(define-test name-list-empty
  :parent (:ssh/tests ssh/tests)
  (let ((buf (make-write-buffer)))
    (write-name-list buf '())
    (is equalp (octets 0 0 0 0) (buffer-to-octets buf)))
  (let ((rbuf (make-read-buffer (octets 0 0 0 0))))
    (is equal '() (read-name-list rbuf))))

(define-test name-list-single
  :parent (:ssh/tests ssh/tests)
  (let* ((buf (make-write-buffer))
         (rbuf (progn (write-name-list buf '("ssh-ed25519"))
                      (make-read-buffer (buffer-to-octets buf)))))
    (is equal '("ssh-ed25519") (read-name-list rbuf))))

(define-test name-list-multiple
  :parent (:ssh/tests ssh/tests)
  (let* ((names '("curve25519-sha256" "diffie-hellman-group14-sha256"))
         (buf   (make-write-buffer))
         (rbuf  (progn (write-name-list buf names)
                       (make-read-buffer (buffer-to-octets buf)))))
    (is equal names (read-name-list rbuf))))

;;; ---- underflow condition ------------------------------------------------

(define-test buffer-underflow-signal
  :parent (:ssh/tests ssh/tests)
  (let ((rbuf (make-read-buffer (octets 0 1))))
    (read-byte* rbuf)
    (read-byte* rbuf)
    (of-type 'buffer-underflow
      (handler-case (progn (read-byte* rbuf) nil)
        (buffer-underflow (c) c)))))

(define-test uint32-underflow
  :parent (:ssh/tests ssh/tests)
  (let ((rbuf (make-read-buffer (octets 0 0 1)))) ; only 3 bytes, need 4
    (of-type 'buffer-underflow
      (handler-case (progn (read-uint32 rbuf) nil)
        (buffer-underflow (c) c)))))
