(defsystem "ssh/compression/zlib/deflate"
  :description "Internal streaming zlib deflater derived from Salza2"
  :license "BSD-2-Clause"
  :pathname "src/compression/zlib/deflate"
  :serial t
  :components ((:file "package")
               (:file "parameters")
               (:file "types")
               (:file "bit-writer")
               (:file "huffman")
               (:file "lz77")
               (:file "deflater")))

(defsystem "ssh/compression/zlib/inflate"
  :description "Internal streaming zlib inflater"
  :license "MIT"
  :pathname "src/compression/zlib/inflate"
  :depends-on ("nibbles")
  :serial t
  :components ((:file "package")
               (:file "platform")
               (:file "state")
               (:file "parameters")
               (:file "huffman")
               (:file "input")
               (:file "inflate")
               (:file "adler32")
               (:file "stream")))

(defsystem "ssh"
  :class :package-inferred-system
  :version "1.0.0"
  :author "Jeffrey Meissen <jeffrey@meissen.email>"
  :description "SSH v2 client implementation"
  :license "MIT"
  :pathname "src"
  :depends-on ("usocket"
               "bordeaux-threads"
               "ironclad"
               "trivial-gray-streams"
               "babel"
               "ssh/ssh")
  :in-order-to ((test-op (test-op "ssh/tests"))))

(defsystem "ssh/tests"
  :depends-on ("ssh"
               "ssh/fuzz"
               "parachute")
  :serial t
  :components ((:file "tests/package")
               (:file "tests/test-buffer")
               (:file "tests/test-zlib-deflate")
               (:file "tests/test-zlib-inflate")
               (:file "tests/test-compression")
               (:file "tests/test-fuzz")
               (:file "tests/test-gcm")
               (:file "tests/test-packet")
               (:file "tests/test-kex")
               (:file "tests/test-kex-dh")
               (:file "tests/test-known-hosts")
               (:file "tests/test-config")
               (:file "tests/test-ssh")
               (:file "tests/test-destination")
               (:file "tests/test-transport")
               (:file "tests/test-auth")
               (:file "tests/test-channel-buffer")
               (:file "tests/test-connection")
               (:file "tests/test-session")
               (:file "tests/test-sftp-codec")
               (:file "tests/test-sftp")
               (:file "tests/test-sftp-stream")
               (:file "tests/test-facade")
               (:file "tests/test-sftp-channel")
               (:file "tests/test-keys")
               (:file "tests/test-concurrency")
               (:file "tests/test-resource-cleanup"))
  :perform (test-op (op c)
                    (let ((report (uiop:symbol-call :parachute :test :ssh/tests)))
                      (when (eq :failed (uiop:symbol-call :parachute :status report))
                        (error "SSH tests failed"))
                      report)))

(defsystem "ssh/integration-tests"
  :depends-on ("ssh"
               "parachute")
  :serial t
  :components ((:file "tests/test-integration")
               (:file "tests/test-sftp-integration"))
  :perform (test-op (op c)
                    (let ((report (uiop:symbol-call :parachute :test :ssh/integration-tests)))
                      (when (eq :failed (uiop:symbol-call :parachute :status report))
                        (error "SSH integration tests failed"))
                      report)))

(defsystem "ssh/fuzz"
  :description "Developer fuzz targets for cl-ssh parser entry points"
  :pathname "."
  :depends-on ("ssh")
  :serial t
  :components ((:file "fuzz/package")
               (:file "fuzz/targets")))
