;;;; Reproducible KEX exchange tests using journal record-and-replay.
;;;;
;;;; WORKFLOW
;;;; --------
;;;; 1. Run once against a live server to capture the exchange bytes:
;;;;
;;;;      (ssh/tests/kex-replay::record-kex-exchange)   ; uses "dp" by default
;;;;
;;;;    Writes tests/fixtures/kex-exchange/kex-capture.jrn containing the
;;;;    version strings, KEXINIT payloads, ephemeral keypair, and ECDH reply.
;;;;
;;;; 2. After recording, run the offline test suite:
;;;;
;;;;      (asdf:test-system :ssh)
;;;;
;;;;    kex-hash-and-verify reads those bytes from the journal, independently
;;;;    recomputes H, and calls verify-host-key-signature.
;;;;    It fails while the bug is present; passes once the bug is fixed.
;;;;
;;;; 3. To re-record:
;;;;
;;;;      (ssh/tests/kex-replay::record-kex-exchange "myhost")
;;;;
;;;; NOTE: Parachute's `skip` does not stop test body execution.
;;;; All conditional logic here uses `when` guards so the body simply
;;;; does not run (and produces zero assertions) when the fixture is absent.

(defpackage :ssh/tests/kex-replay
  (:use :cl :parachute :journal))

(in-package :ssh/tests/kex-replay)

;;;; ---- Fixture paths ------------------------------------------------------

(defun fixture-dir ()
  (asdf:system-relative-pathname :ssh "tests/fixtures/kex-exchange/"))

(defun capture-path ()
  (merge-pathnames "kex-capture.jrn" (fixture-dir)))

;;;; ---- Recording ---------------------------------------------------------

(defun record-kex-exchange (host)
  "Connect to HOST, record all journaled exchange events into the fixture
   file.  Must be called once with a live connection before offline tests run."
  (ensure-directories-exist (fixture-dir))
  (let ((path (capture-path)))
    (when (probe-file path) (delete-file path))
    (let ((journal (jrn:make-file-journal path)))
      (jrn:with-journaling (:record journal)
        (handler-case
            (let ((transport (ssh/transport:connect-transport host)))
              (ssh/transport:transport-disconnect transport))
          (error (e)
            (format *error-output* "~&[record] ~A~%" e)
            (finish-output *error-output*))))
      (jrn:list-events journal))))

;;;; ---- Event reading helpers ---------------------------------------------

(defun load-capture ()
  "Load events from the fixture file.  Returns NIL if the file is absent."
  (let ((path (capture-path)))
    (when (probe-file path)
      (jrn:list-events (jrn:make-file-journal path)))))

(defun out-value (events name)
  "Return the first return value from the :OUT event named NAME (string)."
  (dolist (e events nil)
    (when (and (eq (first e) :out)
               (equal (second e) name))
      (return (first (getf (cddr e) :values))))))

;;;; ---- Parachute tests ---------------------------------------------------

(define-test kex-replay
  :parent (:ssh/tests ssh/tests))

;;; ---- Fixture presence ---------------------------------------------------

(define-test kex-fixture-exists
  :parent kex-replay
  "The journal capture file must exist.
   If this fails, run: (ssh/tests/kex-replay::record-kex-exchange)"
  (true (probe-file (capture-path))
        "capture file missing — run (record-kex-exchange) once"))

;;; ---- Hash + signature verification -------------------------------------

(define-test kex-hash-and-verify
  :parent kex-replay
  "Reproduce the exact exchange hash from captured bytes and verify the
   host-key signature.  This test:
     - Is skipped silently when no fixture exists.
     - Fails while the exchange hash or verify logic is wrong.
     - Passes once the bug is fixed, without needing a live server."
  (let ((events (load-capture)))
    (when events   ; guard: fixture must exist and be readable
      (let* ((v-s   (out-value events "transport/server-version"))
             (i-c   (out-value events "transport/client-kexinit"))
             (i-s   (out-value events "transport/server-kexinit"))
             (kp    (out-value events "kex/ephemeral"))
             (reply (out-value events "kex/ecdh-reply")))
        (when (and v-s i-c i-s kp reply)   ; guard: all events present
          (let* ((v-c     (map '(simple-array (unsigned-byte 8) (*))
                               #'char-code ssh/constants:+client-version-string+))
                 (q-c     (coerce (first  kp) '(simple-array (unsigned-byte 8) (*))))
                 (priv-x  (coerce (second kp) '(simple-array (unsigned-byte 8) (*)))))

            (is = 32 (length q-c) "Q_C must be 32 bytes")

            ;; Parse ECDH reply: type byte at 0, then K_S / Q_S / sig strings
            (let* ((rbuf     (ssh/buffer:make-read-buffer reply :start 1))
                   (k-s-blob (ssh/buffer:read-string* rbuf))
                   (q-s      (ssh/buffer:read-string* rbuf))
                   (sig-blob (ssh/buffer:read-string* rbuf)))

              (is = 32 (length q-s) "Q_S must be 32 bytes")

              ;; Recompute K and H exactly as perform-kex-curve25519 does
              (let* ((priv-key   (ironclad:make-private-key :curve25519
                                                            :x priv-x :y q-c))
                     (server-pub (ironclad:make-public-key  :curve25519 :y q-s))
                     (shared-le  (ironclad:diffie-hellman priv-key server-pub))
                     (k          (ssh/kex:curve25519-bytes->mpint-integer shared-le))
                     (h          (ssh/kex:build-exchange-hash
                                  v-c v-s i-c i-s k-s-blob q-c q-s k)))

                (is = 32 (length h) "exchange hash H must be 32 bytes")

                ;; THE KEY ASSERTION: signature must verify against our H.
                ;; Fails while the bug is present; passes once it is fixed.
                (true
                 (handler-case
                     (progn
                       (ssh/keys:verify-host-key-signature "" k-s-blob h sig-blob)
                       t)
                   (ssh/keys:key-error () nil))
                 "verify-host-key-signature failed for replayed H ~{~2,'0x~^ ~}"
                 (coerce h 'list))))))))))

;;; ---- Determinism check -------------------------------------------------

(define-test kex-hash-is-deterministic
  :parent kex-replay
  "build-exchange-hash must produce the same H for the same inputs."
  (let ((events (load-capture)))
    (when events
      (let* ((v-s   (out-value events "transport/server-version"))
             (i-c   (out-value events "transport/client-kexinit"))
             (i-s   (out-value events "transport/server-kexinit"))
             (kp    (out-value events "kex/ephemeral"))
             (reply (out-value events "kex/ecdh-reply")))
        (when (and v-s i-c i-s kp reply)
          (let* ((v-c    (map '(simple-array (unsigned-byte 8) (*))
                              #'char-code ssh/constants:+client-version-string+))
                 (q-c    (coerce (first  kp) '(simple-array (unsigned-byte 8) (*))))
                 (priv-x (coerce (second kp) '(simple-array (unsigned-byte 8) (*)))))
            (let* ((rbuf  (ssh/buffer:make-read-buffer reply :start 1))
                   (k-s   (ssh/buffer:read-string* rbuf))
                   (q-s   (ssh/buffer:read-string* rbuf))
                   (_     (ssh/buffer:read-string* rbuf))
                   (priv  (ironclad:make-private-key :curve25519 :x priv-x :y q-c))
                   (spub  (ironclad:make-public-key  :curve25519 :y q-s))
                   (k     (ssh/kex:curve25519-bytes->mpint-integer
                            (ironclad:diffie-hellman priv spub)))
                   (h1    (ssh/kex:build-exchange-hash v-c v-s i-c i-s k-s q-c q-s k))
                   (h2    (ssh/kex:build-exchange-hash v-c v-s i-c i-s k-s q-c q-s k)))
              (declare (ignore _))
              (is equalp h1 h2
                  "build-exchange-hash is not deterministic"))))))))
