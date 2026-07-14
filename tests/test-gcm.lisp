;;;; Unit tests for the generic AES-GCM wrapper.

(defpackage :ssh/tests/gcm
  (:use :cl :parachute)
  (:import-from :ssh/gcm
    #:gcm-seal
    #:gcm-open
    #:gcm-authentication-error))

(in-package :ssh/tests/gcm)

(defun hex-octets (string)
  (let ((result (make-array (/ (length string) 2)
                            :element-type '(unsigned-byte 8))))
    (dotimes (i (length result) result)
      (setf (aref result i)
            (parse-integer string :start (* i 2) :end (+ (* i 2) 2)
                                  :radix 16)))))

(define-test aes128-gcm-empty-nist-vector
  :parent (:ssh/tests ssh/tests)
  (let ((key (hex-octets "00000000000000000000000000000000"))
        (iv  (hex-octets "000000000000000000000000"))
        (empty (hex-octets "")))
    (multiple-value-bind (ciphertext tag)
        (gcm-seal key iv empty empty)
      (is equalp empty ciphertext)
      (is equalp (hex-octets "58e2fccefa7e3061367f1d57a4e7455a") tag)
      (is equalp empty (gcm-open key iv empty ciphertext tag)))))

(define-test aes256-gcm-one-block-nist-vector
  :parent (:ssh/tests ssh/tests)
  (let ((key (hex-octets
              "0000000000000000000000000000000000000000000000000000000000000000"))
        (iv (hex-octets "000000000000000000000000"))
        (plaintext (hex-octets "00000000000000000000000000000000")))
    (multiple-value-bind (ciphertext tag)
        (gcm-seal key iv (hex-octets "") plaintext)
      (is equalp (hex-octets "cea7403d4d606b6e074ec5d3baf39d18") ciphertext)
      (is equalp (hex-octets "d0d1c8a799996bf0265b98b5d48ab919") tag)
      (is equalp plaintext
          (gcm-open key iv (hex-octets "") ciphertext tag)))))

(define-test aes128-gcm-associated-data-nist-vector
  :parent (:ssh/tests ssh/tests)
  (let ((key (hex-octets "feffe9928665731c6d6a8f9467308308"))
        (iv (hex-octets "cafebabefacedbaddecaf888"))
        (aad (hex-octets "feedfacedeadbeeffeedfacedeadbeefabaddad2"))
        (plaintext
          (hex-octets
           (concatenate 'string
                        "d9313225f88406e5a55909c5aff5269a"
                        "86a7a9531534f7da2e4c303d8a318a72"
                        "1c3c0c95956809532fcf0e2449a6b525"
                        "b16aedf5aa0de657ba637b39"))))
    (multiple-value-bind (ciphertext tag)
        (gcm-seal key iv aad plaintext)
      (is equalp
          (hex-octets
           (concatenate 'string
                        "42831ec2217774244b7221b784d0d49c"
                        "e3aa212f2c02a4e035c17e2329aca12e"
                        "21d514b25466931c7d8f6a5aac84aa05"
                        "1ba30b396a0aac973d58e091"))
          ciphertext)
      (is equalp (hex-octets "5bc94fbc3221a5db94fae95ae7121a47") tag)
      (is equalp plaintext (gcm-open key iv aad ciphertext tag)))))

(define-test gcm-open-rejects-modified-associated-data-ciphertext-and-tag
  :parent (:ssh/tests ssh/tests)
  (let ((key (hex-octets "00000000000000000000000000000000"))
        (iv (hex-octets "000000000000000000000000"))
        (aad (hex-octets "00000010"))
        (plaintext (hex-octets "000102030405060708090a0b0c0d0e0f")))
    (multiple-value-bind (ciphertext tag)
        (gcm-seal key iv aad plaintext)
      (let ((bad-aad (copy-seq aad))
            (bad-ciphertext (copy-seq ciphertext))
            (bad-tag (copy-seq tag)))
        (setf (aref bad-aad 3) (logxor (aref bad-aad 3) 1)
              (aref bad-ciphertext 0) (logxor (aref bad-ciphertext 0) 1)
              (aref bad-tag 0) (logxor (aref bad-tag 0) 1))
        (fail (gcm-open key iv bad-aad ciphertext tag)
              'gcm-authentication-error)
        (fail (gcm-open key iv aad bad-ciphertext tag)
              'gcm-authentication-error)
        (fail (gcm-open key iv aad ciphertext bad-tag)
              'gcm-authentication-error)))))
