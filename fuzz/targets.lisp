;;;; File-oriented parser fuzz targets.

(in-package #:ssh/fuzz)

(defparameter +target-names+
  '("packet" "kexinit" "ext-info" "public-key" "signature"
    "private-key" "known-hosts" "config" "zlib" "sftp"))

(defun target-names ()
  "Return the supported fuzz target names.
Returns a fresh list of target name strings."
  (copy-list +target-names+))

(defun read-octets (path)
  "Read PATH as an octet vector.
Returns the file contents as an unsigned-byte 8 vector."
  (with-open-file (stream path :direction :input :element-type '(unsigned-byte 8))
    (let ((contents (make-array (file-length stream) :element-type '(unsigned-byte 8))))
      (read-sequence contents stream)
      contents)))

(defun run-packet-target (path)
  (with-open-file (stream path :direction :input :element-type '(unsigned-byte 8))
    (ssh/packet:recv-packet (ssh/packet:make-packet-stream stream))))

(defun run-known-hosts-target (path)
  (ssh/known-hosts::load-known-hosts path))

(defun run-config-target (path)
  (ssh/config::parse-config-file path))

(defun run-zlib-target (path)
  (let ((input (read-octets path)))
    (when (zerop (length input))
      (return-from run-zlib-target :empty))
    (let* ((chunk-size (1+ (mod (aref input 0) 64)))
           (payload (subseq input 1)))
      (ssh/compression:decompress-payload
       (ssh/compression:make-decompressor "zlib")
       payload)
      (let ((decompressor
              (ssh/compression:make-decompressor "zlib")))
        (loop
          for start from 0 below (length payload) by chunk-size
          for end = (min (length payload) (+ start chunk-size))
          do (ssh/compression:decompress-payload
              decompressor (subseq payload start end)))))))

(defun run-sftp-target (path)
  (with-open-file (stream path :element-type '(unsigned-byte 8))
    (multiple-value-bind (type payload) (ssh/sftp/codec:read-frame stream)
      (case type
        (2 (ssh/sftp/codec:decode-version payload))
        (otherwise (ssh/sftp/codec:decode-response type payload))))))

(defun run-target (target path)
  "Run fuzz TARGET against the bytes at PATH.
TARGET names one parser target and PATH names an existing input file.
Returns :ACCEPTED for successful parsing or :REJECTED for a defined input error."
  (handler-case
      (progn
        (ecase (intern (string-upcase target) :keyword)
          (:packet (run-packet-target path))
          (:kexinit (ssh/algorithms::parse-kexinit (read-octets path)))
          (:ext-info (ssh/transport::parse-ext-info-payload (read-octets path)))
          (:public-key (ssh/keys::parse-public-key-blob (read-octets path)))
          (:signature (ssh/keys::parse-signature-blob (read-octets path)))
          (:private-key (ssh/keys:load-private-key path))
          (:known-hosts (run-known-hosts-target path))
          (:config (run-config-target path))
          (:zlib (run-zlib-target path))
          (:sftp (run-sftp-target path)))
        :accepted)
    (ssh/buffer:buffer-underflow () :rejected)
    (ssh/buffer:buffer-format-error () :rejected)
    (ssh/packet:ssh-protocol-error () :rejected)
    (ssh/transport:transport-error () :rejected)
    (ssh/auth:auth-error () :rejected)
    (ssh/keys:key-error () :rejected)
    (ssh/compression:compression-error () :rejected)
    (ssh/sftp/codec:sftp-protocol-error () :rejected)
    (end-of-file () :rejected)))

(defun replay-corpus (root)
  "Replay every checked-in fuzz input below ROOT.
ROOT contains one directory per target name.
Returns :REPLAYED after all inputs complete without an unexpected failure."
  (let ((root-directory (uiop:ensure-directory-pathname root)))
    (dolist (target +target-names+)
      (let ((directory (merge-pathnames (format nil "~A/" target) root-directory)))
        (when (probe-file directory)
          (dolist (input (directory (merge-pathnames "*" directory)))
            (when (pathname-name input)
              (run-target target input))))))
    :replayed))

(defun main ()
  "Run one file-oriented fuzz target from command-line arguments.
The arguments are TARGET and PATH.
Returns no values and exits with a nonzero status for unexpected failures."
  (let ((arguments (remove "--" (uiop:command-line-arguments) :test #'string=)))
    (unless (= (length arguments) 2)
      (format *error-output* "usage: ssh-fuzz TARGET PATH~%")
      (uiop:quit 64))
    (handler-bind
        ((error (lambda (condition)
                  (format *error-output* "unexpected fuzz failure: ~A~%condition type: ~S~%target: ~A~%input: ~A~%"
                          condition (type-of condition)
                          (first arguments) (second arguments))
                  #+sbcl
                  (sb-debug:print-backtrace :stream *error-output* :count 30)
                  (finish-output *error-output*)
                  (uiop:quit 1))))
      (run-target (first arguments) (second arguments))
      (uiop:quit 0))))
