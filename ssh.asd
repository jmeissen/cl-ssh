(defsystem "ssh"
  :class :package-inferred-system
  :version "0.1.0"
  :author "Jeffrey Meissen <jeffrey@meissen.email>"
  :description "SSH v2 client implementation"
  :license "MIT"
  :pathname "src"
  :depends-on ("usocket"
               "ironclad"
               "trivial-gray-streams"
               "journal"
               "ssh/ssh")
  :in-order-to ((test-op (test-op "ssh/tests"))))

(defsystem "ssh/tests"
  :depends-on ("ssh"
               "parachute"
               "journal")
  :serial t
  :components ((:file "tests/package")
               (:file "tests/test-buffer")
               (:file "tests/test-packet")
               (:file "tests/test-kex")
               (:file "tests/test-kex-dh")
               (:file "tests/test-config")
               (:file "tests/test-kex-replay")
               (:file "tests/test-keys"))
  :perform (test-op (op c)
                    (uiop:symbol-call :parachute :test :ssh/tests)))
