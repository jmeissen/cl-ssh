#!/usr/bin/env bash
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
TEST_OUTPUT=$(mktemp -d)
trap 'rm -rf "$TEST_OUTPUT"' EXIT

[ "$(bash "$ROOT/scripts/run-fuzz.sh" classify 0)" = success ]
[ "$(bash "$ROOT/scripts/run-fuzz.sh" classify 10)" = coverage-growth ]
[ "$(bash "$ROOT/scripts/run-fuzz.sh" classify 124)" = fault ]
[ "$(bash "$ROOT/scripts/run-fuzz.sh" classify 137)" = fault ]

SSH_FUZZ_OUTPUT_ROOT="$TEST_OUTPUT" bash "$ROOT/scripts/run-fuzz.sh" verify
mkdir -p "$TEST_OUTPUT/zlib/faults"
touch "$TEST_OUTPUT/zlib/faults/input-controlled-timeout"
if SSH_FUZZ_OUTPUT_ROOT="$TEST_OUTPUT" \
   bash "$ROOT/scripts/run-fuzz.sh" verify zlib >/dev/null 2>&1; then
  echo "verify accepted a retained fault" >&2
  exit 1
fi

FAKE_BIN="$TEST_OUTPUT/bin"
FAKE_CORPUS="$TEST_OUTPUT/corpus"
FAKE_SBCL_ARGS="$TEST_OUTPUT/sbcl-args"
mkdir -p "$FAKE_BIN" "$FAKE_CORPUS/packet"
touch "$FAKE_CORPUS/packet/input"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'printf '\''%s\n'\'' __invocation__ "$@" >> "$FAKE_SBCL_ARGS"' \
  > "$FAKE_BIN/sbcl"
chmod +x "$FAKE_BIN/sbcl"

assert_dynamic_space_size() {
  local expected=$1
  awk -v expected="$expected" '
    previous == "--dynamic-space-size" && $0 == expected { found = 1 }
    { previous = $0 }
    END { exit !found }
  ' "$FAKE_SBCL_ARGS"
}

assert_bootstraps_project_before() {
  local next_argument=$1
  awk -v next_argument="$next_argument" '
    index($0, "(asdf:load-asd ") == 1 { load_asd_line = NR }
    $0 == "(ql:quickload :ssh)" { quickload_line = NR }
    $0 == next_argument { next_line = NR }
    END {
      exit !(load_asd_line && quickload_line && next_line && load_asd_line < quickload_line && quickload_line < next_line)
    }
  ' "$FAKE_SBCL_ARGS"
}

assert_prepares_before_main() {
  awk '
    $0 == "__invocation__" { invocation += 1 }
    invocation == 1 && $0 == "--quit" { prepared = 1 }
    invocation == 2 && $0 == "(ssh/fuzz:main)" { ran_target = 1 }
    END { exit !(invocation == 2 && prepared && ran_target) }
  ' "$FAKE_SBCL_ARGS"
}

: > "$FAKE_SBCL_ARGS"
PATH="$FAKE_BIN:$PATH" \
FAKE_SBCL_ARGS="$FAKE_SBCL_ARGS" \
SSH_FUZZ_CORPUS="$FAKE_CORPUS" \
  bash "$ROOT/scripts/run-fuzz.sh" replay packet
assert_dynamic_space_size 1024
assert_bootstraps_project_before '(asdf:load-system :ssh/fuzz)'
assert_prepares_before_main

: > "$FAKE_SBCL_ARGS"
PATH="$FAKE_BIN:$PATH" \
FAKE_SBCL_ARGS="$FAKE_SBCL_ARGS" \
SSH_FUZZ_CORPUS="$FAKE_CORPUS" \
SSH_FUZZ_DYNAMIC_SPACE_MB=192 \
  bash "$ROOT/scripts/run-fuzz.sh" replay packet
assert_dynamic_space_size 192
assert_bootstraps_project_before '(asdf:load-system :ssh/fuzz)'
assert_prepares_before_main

: > "$FAKE_SBCL_ARGS"
PATH="$FAKE_BIN:$PATH" \
FAKE_SBCL_ARGS="$FAKE_SBCL_ARGS" \
SSH_FUZZ_OUTPUT_ROOT="$TEST_OUTPUT" \
  bash "$ROOT/scripts/run-fuzz.sh" coverage
assert_bootstraps_project_before "$ROOT/scripts/fuzz-coverage.lisp"
