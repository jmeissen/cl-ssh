#!/usr/bin/env bash
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
export SSH_PROJECT_ROOT=$ROOT
MODE=${1:-replay}
TARGET=${2:-}
CORPUS_ROOT=${SSH_FUZZ_CORPUS:-"$ROOT/fuzz/corpus"}
OUTPUT_ROOT=${SSH_FUZZ_OUTPUT_ROOT:-"$ROOT/.fuzz-output"}
TIMEOUT_SECONDS=${SSH_FUZZ_TIMEOUT_SECONDS:-10}
MEMORY_LIMIT_KB=${SSH_FUZZ_MEMORY_LIMIT_KB:-2097152}
DYNAMIC_SPACE_MB=${SSH_FUZZ_DYNAMIC_SPACE_MB:-1024}
MAX_INPUT_BYTES=${SSH_FUZZ_MAX_INPUT_BYTES:-1048576}
ITERATIONS=${SSH_FUZZ_ITERATIONS:-0}
DURATION_SECONDS=${SSH_FUZZ_DURATION_SECONDS:-0}
COVERAGE_FEEDBACK=${SSH_FUZZ_COVERAGE_FEEDBACK:-0}
REQUIRE_PLATEAU=${SSH_FUZZ_REQUIRE_PLATEAU:-0}

coverage_score() {
  local corpus=$1
  local report
  report=$(mktemp -d)
  SSH_FUZZ_ROOT="$ROOT" SSH_FUZZ_CORPUS="$corpus" SSH_FUZZ_COVERAGE="$report" \
    bash "$ROOT/scripts/run-fuzz.sh" coverage >/dev/null
  awk -F'<td>' '/<td>expression<\/td>/{split($3, field, "<"); sum += field[1]} END {print sum + 0}' \
    "$report"/*.html
  rm -rf "$report"
}

prepare_runtime() {
  sbcl --dynamic-space-size "$DYNAMIC_SPACE_MB" \
    --disable-debugger --load "$ROOT/.qlot/setup.lisp" \
    --eval '(asdf:load-asd (merge-pathnames "ssh.asd" (uiop:ensure-directory-pathname (uiop:getenv "SSH_PROJECT_ROOT"))))' \
    --eval '(ql:quickload :ssh)' \
    --eval '(asdf:load-system :ssh/fuzz)' \
    --quit
}

run_target() {
  local target=$1
  local input=$2
  local timeout_command=
  if command -v timeout >/dev/null 2>&1; then
    timeout_command=timeout
  elif command -v gtimeout >/dev/null 2>&1; then
    timeout_command=gtimeout
  fi
  (
    ulimit -v "$MEMORY_LIMIT_KB" 2>/dev/null || true
    if [ -n "$timeout_command" ]; then
      "$timeout_command" "$TIMEOUT_SECONDS" \
        sbcl --dynamic-space-size "$DYNAMIC_SPACE_MB" \
        --disable-debugger --load "$ROOT/.qlot/setup.lisp" \
        --eval '(asdf:load-asd (merge-pathnames "ssh.asd" (uiop:ensure-directory-pathname (uiop:getenv "SSH_PROJECT_ROOT"))))' \
        --eval '(ql:quickload :ssh)' \
        --eval '(asdf:load-system :ssh/fuzz)' \
        --eval '(ssh/fuzz:main)' -- "$target" "$input"
    else
      perl -e 'alarm shift; exec @ARGV' "$TIMEOUT_SECONDS" \
        sbcl --dynamic-space-size "$DYNAMIC_SPACE_MB" \
        --disable-debugger --load "$ROOT/.qlot/setup.lisp" \
        --eval '(asdf:load-asd (merge-pathnames "ssh.asd" (uiop:ensure-directory-pathname (uiop:getenv "SSH_PROJECT_ROOT"))))' \
        --eval '(ql:quickload :ssh)' \
        --eval '(asdf:load-system :ssh/fuzz)' \
        --eval '(ssh/fuzz:main)' -- "$target" "$input"
    fi
  )
}

replay_target() {
  local target=$1
  local directory="$CORPUS_ROOT/$target"
  [ -d "$directory" ] || return 0
  while IFS= read -r -d '' input; do
    run_target "$target" "$input"
  done < <(find "$directory" -type f -print0)
}

faults_exist() {
  local search_root=$1
  [ -d "$search_root" ] || return 1
  [ -n "$(find "$search_root" -type f -path '*/faults/input-*' -print -quit)" ]
}

if [ "$MODE" = replay ]; then
  prepare_runtime
  if [ -n "$TARGET" ]; then
    replay_target "$TARGET"
  else
    for directory in "$CORPUS_ROOT"/*; do
      [ -d "$directory" ] && replay_target "$(basename "$directory")"
    done
  fi
  exit 0
fi

if [ "$MODE" = coverage ]; then
  SSH_FUZZ_ROOT="$ROOT" \
    SSH_FUZZ_COVERAGE="${SSH_FUZZ_COVERAGE:-$OUTPUT_ROOT/coverage}" \
    sbcl --disable-debugger --load "$ROOT/.qlot/setup.lisp" \
    --eval '(asdf:load-asd (merge-pathnames "ssh.asd" (uiop:ensure-directory-pathname (uiop:getenv "SSH_PROJECT_ROOT"))))' \
    --eval '(ql:quickload :ssh)' \
    --load "$ROOT/scripts/fuzz-coverage.lisp" --quit
  exit 0
fi

if [ "$MODE" = reproduce ]; then
  if [ "$#" -ne 3 ] || [ -z "$TARGET" ] || [ ! -f "$3" ]; then
    echo "usage: $0 reproduce TARGET INPUT_FILE" >&2
    exit 64
  fi
  prepare_runtime
  run_target "$TARGET" "$3"
  exit 0
fi

if [ "$MODE" = classify ]; then
  case "$TARGET" in
    0)
      echo success
      ;;
    10)
      echo coverage-growth
      ;;
    ''|*[!0-9]*)
      echo "classify requires a numeric status" >&2
      exit 64
      ;;
    *)
      echo fault
      ;;
  esac
  exit 0
fi

if [ "$MODE" = verify ]; then
  if [ -n "$TARGET" ]; then
    VERIFY_ROOT="$OUTPUT_ROOT/$TARGET/faults"
  else
    VERIFY_ROOT="$OUTPUT_ROOT"
  fi
  if faults_exist "$VERIFY_ROOT"; then
    echo "untriaged fuzz faults remain below $VERIFY_ROOT" >&2
    exit 1
  fi
  exit 0
fi

if [ "$MODE" != mutate ] || [ -z "$TARGET" ]; then
  echo "usage: $0 replay [TARGET] | $0 reproduce TARGET INPUT_FILE | $0 coverage | $0 classify STATUS | $0 verify [TARGET] | $0 mutate TARGET" >&2
  exit 64
fi

command -v radamsa >/dev/null || {
  echo "radamsa is required for mutation mode" >&2
  exit 69
}

SEED_DIRECTORY="$CORPUS_ROOT/$TARGET"
[ -d "$SEED_DIRECTORY" ] || {
  echo "missing corpus directory: $SEED_DIRECTORY" >&2
  exit 66
}

prepare_runtime

TARGET_OUTPUT="$OUTPUT_ROOT/$TARGET"
CANDIDATE_DIRECTORY="$TARGET_OUTPUT/candidates"
COVERAGE_DIRECTORY="$TARGET_OUTPUT/coverage"
FAULT_DIRECTORY="$TARGET_OUTPUT/faults"
FAULT_MANIFEST="$FAULT_DIRECTORY/manifest.tsv"
SUMMARY_FILE="$TARGET_OUTPUT/summary.tsv"
mkdir -p "$CANDIDATE_DIRECTORY" "$COVERAGE_DIRECTORY" "$FAULT_DIRECTORY"

build_active_corpus() {
  local destination=$1
  cp -R "$CORPUS_ROOT" "$destination"
  while IFS= read -r -d '' retained; do
    cp "$retained" "$destination/$TARGET/$(basename "$retained")"
  done < <(find "$COVERAGE_DIRECTORY" -type f -name 'input-*' -print0)
}

retain_fault() {
  local candidate=$1
  local status=$2
  local seed=$3
  local retained
  retained="$FAULT_DIRECTORY/input-$(basename "$candidate")"
  mv "$candidate" "$retained"
  printf '%s\t%s\t%s\t%s\n' "$(date -u +%FT%TZ)" "$status" "$retained" "$seed" \
    >> "$FAULT_MANIFEST"
  echo "fuzz fault retained at $retained (status $status)" >&2
}

START_SECONDS=$SECONDS
COMPLETED_ITERATIONS=0
CURRENT_COVERAGE=0
TIME_EXPIRED=0

record_summary() {
  local outcome=$1
  local status=$2
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$(date -u +%FT%TZ)" "$TARGET" "$outcome" "$status" \
    "$((SECONDS - START_SECONDS))" "$COMPLETED_ITERATIONS" "$CURRENT_COVERAGE" \
    >> "$SUMMARY_FILE"
}

if [ "$COVERAGE_FEEDBACK" = 1 ]; then
  ACTIVE_ROOT=$(mktemp -d)
  build_active_corpus "$ACTIVE_ROOT/corpus"
  CURRENT_COVERAGE=$(coverage_score "$ACTIVE_ROOT/corpus")
  rm -rf "$ACTIVE_ROOT"
fi

while :; do
  while IFS= read -r -d '' seed; do
    if [ "$DURATION_SECONDS" -gt 0 ] &&
       [ $((SECONDS - START_SECONDS)) -ge "$DURATION_SECONDS" ]; then
      TIME_EXPIRED=1
      break
    fi
    candidate=$(mktemp "$CANDIDATE_DIRECTORY/input-XXXXXX")
    radamsa "$seed" > "$candidate"
    candidate_size=$(wc -c < "$candidate")
    if [ "$candidate_size" -gt "$MAX_INPUT_BYTES" ]; then
      rm -f "$candidate"
      continue
    fi

    status=0
    run_target "$TARGET" "$candidate" || status=$?
    if [ "$status" -ne 0 ]; then
      retain_fault "$candidate" "$status" "$seed"
      record_summary fault "$status"
      exit "$status"
    fi

    if [ "$COVERAGE_FEEDBACK" = 1 ]; then
      trial_root=$(mktemp -d)
      build_active_corpus "$trial_root/corpus"
      cp "$candidate" "$trial_root/corpus/$TARGET/$(basename "$candidate")"
      candidate_coverage=$(coverage_score "$trial_root/corpus")
      rm -rf "$trial_root"
      if [ "$candidate_coverage" -gt "$CURRENT_COVERAGE" ]; then
        interesting="$COVERAGE_DIRECTORY/input-$(basename "$candidate")"
        mv "$candidate" "$interesting"
        CURRENT_COVERAGE=$candidate_coverage
        echo "coverage-increasing input retained at $interesting" >&2
        if [ "$REQUIRE_PLATEAU" = 1 ]; then
          record_summary coverage-growth 10
          exit 10
        fi
        continue
      fi
    fi
    rm -f "$candidate"
  done < <(
    find "$SEED_DIRECTORY" "$COVERAGE_DIRECTORY" -type f -name '*' -print0
  )

  [ "$TIME_EXPIRED" -eq 1 ] && break
  COMPLETED_ITERATIONS=$((COMPLETED_ITERATIONS + 1))
  if [ "$ITERATIONS" -gt 0 ] && [ "$COMPLETED_ITERATIONS" -ge "$ITERATIONS" ]; then
    break
  fi
  if [ "$DURATION_SECONDS" -gt 0 ] &&
     [ $((SECONDS - START_SECONDS)) -ge "$DURATION_SECONDS" ]; then
    break
  fi
  if [ "$ITERATIONS" -eq 0 ] && [ "$DURATION_SECONDS" -eq 0 ]; then
    break
  fi
done

record_summary success 0
