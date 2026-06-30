(defsystem "ssh"
  :class :package-inferred-system
  :version "0.2.0"
  :author "Jeffrey Meissen <jeffrey@meissen.email>"
  :description "SSH v2 client implementation"
  :license "MIT"
  :pathname "src"
  :depends-on ("usocket"
               "ironclad"
               "trivial-gray-streams"
               "babel"
               "ssh/ssh")
  :in-order-to ((test-op (test-op "ssh/tests"))))

(defsystem "ssh/tests"
  :depends-on ("ssh"
               "parachute")
  :serial t
  :components ((:file "tests/package")
               (:file "tests/test-buffer")
               (:file "tests/test-packet")
               (:file "tests/test-kex")
               (:file "tests/test-kex-dh")
               (:file "tests/test-known-hosts")
               (:file "tests/test-config")
               (:file "tests/test-ssh")
               (:file "tests/test-transport")
               (:file "tests/test-auth")
               (:file "tests/test-connection")
               (:file "tests/test-session")
               (:file "tests/test-keys"))
  :perform (test-op (op c)
                    (uiop:symbol-call :parachute :test :ssh/tests)))

(defsystem "ssh/integration-tests"
  :depends-on ("ssh"
               "parachute")
  :serial t
  :components ((:file "tests/test-integration"))
  :perform (test-op (op c)
                    (uiop:symbol-call :parachute :test :ssh/integration-tests)))
