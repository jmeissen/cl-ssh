;;;; Generate SBCL parser-source coverage after corpus replay.

(require :sb-cover)
(declaim (optimize sb-cover:store-coverage-data))

(let* ((root (uiop:ensure-directory-pathname
              (or (uiop:getenv "SSH_FUZZ_ROOT") (uiop:getcwd))))
       (report (uiop:ensure-directory-pathname
                (or (uiop:getenv "SSH_FUZZ_COVERAGE")
                    (merge-pathnames "coverage/" (uiop:temporary-directory))))))
  ;; Force the parser source itself to compile after coverage instrumentation is
  ;; enabled; loading ssh/fuzz alone would otherwise instrument only the harness.
  (asdf:load-system :ssh)
  (dolist (system '(:ssh/compression/zlib/deflate
                    :ssh/compression/zlib/inflate
                    :ssh/compression
                    :ssh/constants :ssh/buffer :ssh/algorithms :ssh/gcm
                    :ssh/packet :ssh/kex :ssh/keys :ssh/known-hosts
                    :ssh/config :ssh/transport :ssh/auth :ssh/connection
                    :ssh/session :ssh/channel-buffer :ssh/sftp/codec :ssh/sftp
                    :ssh/sftp/stream :ssh/ssh :ssh/fuzz))
    (asdf:clear-system system))
  (asdf:load-asd (merge-pathnames "ssh.asd" root))
  (dolist (system '(:ssh/compression/zlib/deflate
                    :ssh/compression/zlib/inflate
                    :ssh/compression
                    :ssh/constants :ssh/buffer :ssh/algorithms :ssh/gcm
                    :ssh/packet :ssh/kex :ssh/keys :ssh/known-hosts
                    :ssh/config :ssh/transport :ssh/auth :ssh/connection
                    :ssh/session :ssh/channel-buffer :ssh/sftp/codec :ssh/sftp
                    :ssh/sftp/stream :ssh/ssh))
    (asdf:load-system system :force t))
  (asdf:load-system :ssh/fuzz :force t)
  (uiop:symbol-call
   :ssh/fuzz :replay-corpus
   (uiop:ensure-directory-pathname
    (or (uiop:getenv "SSH_FUZZ_CORPUS")
        (merge-pathnames "fuzz/corpus/" root))))
  (ensure-directories-exist report)
  (sb-cover:report report))
