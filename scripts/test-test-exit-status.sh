#!/usr/bin/env bash
# Verify the actual ASDF hooks turn failed assertions into a failed process.
set -euo pipefail
task_root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
task_log=$(mktemp)
trap 'rm -f "$task_log"' EXIT
cd "$task_root"

for task_system in ssh/tests ssh/integration-tests; do
    task_status=0
    SSH_EXIT_TEST_SYSTEM="$task_system" sbcl --disable-debugger \
        --load .qlot/setup.lisp \
        --eval '(asdf:load-asd (truename "ssh.asd"))' \
        --eval '(asdf:load-system (uiop:getenv "SSH_EXIT_TEST_SYSTEM"))' \
        --eval '(parachute:define-test cl-user::deliberate-exit-status-failure
                  (parachute:false t "Deliberate exit-status regression"))' \
        --eval '(let ((original (symbol-function (quote parachute:test))))
                  (setf (symbol-function (quote parachute:test))
                        (lambda (&rest args)
                          (declare (ignore args))
                          (funcall original (quote cl-user::deliberate-exit-status-failure)))))' \
        --eval '(asdf:test-system (uiop:getenv "SSH_EXIT_TEST_SYSTEM"))' \
        --quit >"$task_log" 2>&1 || task_status=$?
    if [ "$task_status" -eq 0 ]; then
        printf '%s accepted a failed test report\n' "$task_system" >&2
        exit 1
    fi
    # Distinguish the intended test-hook error from setup or compilation errors.
    if ! grep -Eq 'SSH (integration )?tests failed' "$task_log"; then
        cat "$task_log" >&2
        exit 1
    fi
    printf '%s correctly exits nonzero after a failed assertion\n' "$task_system"
done
