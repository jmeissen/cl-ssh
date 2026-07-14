;;;; Generic AES-GCM authenticated encryption built on Ironclad.

(uiop:define-package ssh/gcm
  (:use #:cl)
  (:export
   #:gcm-seal
   #:gcm-open
   #:gcm-authentication-error))

(in-package #:ssh/gcm)

(define-condition gcm-authentication-error (error) ()
  (:report (lambda (condition stream)
             (declare (ignore condition))
             (write-string "AES-GCM authentication failed" stream))))

(defun copy-octets (octets)
  (let ((copy (make-array (length octets)
                          :element-type '(unsigned-byte 8))))
    (replace copy octets)
    copy))

(defun check-gcm-parameters (key iv tag)
  (unless (member (length key) '(16 32))
    (error "AES-GCM key length must be 16 or 32 octets"))
  (unless (= (length iv) 12)
    (error "AES-GCM IV length must be 12 octets"))
  (when (and tag (/= (length tag) 16))
    (error "AES-GCM authentication tag length must be 16 octets")))

(defun make-gcm-mode (key iv)
  (ironclad:make-authenticated-encryption-mode
   :gcm
   :cipher-name :aes
   :key (copy-octets key)
   :initialization-vector (copy-octets iv)))

(defun gcm-seal (key iv associated-data plaintext)
  "Encrypt and authenticate PLAINTEXT with AES-GCM.
KEY is a 16- or 32-octet AES key.
IV is the 12-octet nonce for this invocation.
ASSOCIATED-DATA is authenticated without being encrypted.
PLAINTEXT is the octet vector to encrypt.
Returns the ciphertext and the 16-octet authentication tag as two values."
  (check-gcm-parameters key iv nil)
  (let ((mode (make-gcm-mode key iv))
        (ciphertext (copy-octets plaintext)))
    (ironclad:process-associated-data mode associated-data)
    (ironclad:encrypt-in-place mode ciphertext)
    (values ciphertext (ironclad:produce-tag mode))))

(defun gcm-open (key iv associated-data ciphertext tag)
  "Authenticate and decrypt CIPHERTEXT with AES-GCM.
KEY is a 16- or 32-octet AES key.
IV is the 12-octet nonce for this invocation.
ASSOCIATED-DATA is authenticated without being encrypted.
CIPHERTEXT is the octet vector to decrypt.
TAG is the complete 16-octet authentication tag.
Returns the plaintext only after successful authentication."
  (check-gcm-parameters key iv tag)
  (let ((mode (make-gcm-mode key iv))
        (plaintext (copy-octets ciphertext)))
    (ironclad:process-associated-data mode associated-data)
    (ironclad:decrypt-in-place mode plaintext)
    (unless (ironclad:constant-time-equal tag (ironclad:produce-tag mode))
      (fill plaintext 0)
      (error 'gcm-authentication-error))
    plaintext))
