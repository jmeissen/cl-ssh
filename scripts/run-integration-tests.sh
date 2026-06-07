#!/usr/bin/env bash
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
HOST=${SSH_TEST_HOST:-127.0.0.1}
PORT=${SSH_TEST_PORT:-2222}
RSA_SHA2_512_PORT=${SSH_TEST_RSA_SHA2_512_PORT:-$PORT}
RSA_SHA2_256_PORT=${SSH_TEST_RSA_SHA2_256_PORT:-2223}
SSH_RSA_PORT=${SSH_TEST_SSH_RSA_PORT:-2224}
KBDINT_PORT=${SSH_TEST_KBDINT_PORT:-2225}
SSH_TEST_PARTIAL_SUCCESS_PORT=${SSH_TEST_PARTIAL_SUCCESS_PORT:-2226}
USER=${SSH_TEST_USER:-ssh-test}
PASSWORD=${SSH_TEST_PASSWORD:-cl-ssh-password}
KNOWN_HOSTS=$(mktemp)

cleanup() {
  rm -f "$KNOWN_HOSTS"
  docker compose -f "$ROOT/docker-compose.yml" down -v --remove-orphans >/dev/null 2>&1 || true
}

trap cleanup EXIT INT TERM

if [ "${SSH_TEST_REBUILD:-0}" = 1 ] || ! docker image inspect cl-ssh-sshd >/dev/null 2>&1; then
  docker compose -f "$ROOT/docker-compose.yml" up -d --build
else
  docker compose -f "$ROOT/docker-compose.yml" up -d
fi

for _ in $(seq 1 30); do
  : >"$KNOWN_HOSTS"
  if ssh-keyscan -p "$RSA_SHA2_512_PORT" "$HOST" >>"$KNOWN_HOSTS" 2>/dev/null     && ssh-keyscan -p "$RSA_SHA2_256_PORT" "$HOST" >>"$KNOWN_HOSTS" 2>/dev/null     && ssh-keyscan -p "$SSH_RSA_PORT" "$HOST" >>"$KNOWN_HOSTS" 2>/dev/null     && ssh-keyscan -p "$KBDINT_PORT" "$HOST" >>"$KNOWN_HOSTS" 2>/dev/null     && ssh-keyscan -p "$SSH_TEST_PARTIAL_SUCCESS_PORT" "$HOST" >>"$KNOWN_HOSTS" 2>/dev/null     && [ -s "$KNOWN_HOSTS" ]; then
    break
  fi
  sleep 1
done

if [ ! -s "$KNOWN_HOSTS" ]; then
  printf 'failed to scan SSH host keys from %s:%s %s:%s %s:%s %s:%s %s:%s
'     "$HOST" "$RSA_SHA2_512_PORT" "$HOST" "$RSA_SHA2_256_PORT" "$HOST" "$SSH_RSA_PORT" "$HOST" "$KBDINT_PORT" "$HOST" "$SSH_TEST_PARTIAL_SUCCESS_PORT" >&2
  exit 1
fi

SSH_TEST_HOST="$HOST" SSH_TEST_PORT="$PORT" SSH_TEST_RSA_SHA2_512_PORT="$RSA_SHA2_512_PORT" SSH_TEST_RSA_SHA2_256_PORT="$RSA_SHA2_256_PORT" SSH_TEST_SSH_RSA_PORT="$SSH_RSA_PORT" SSH_TEST_KBDINT_PORT="$KBDINT_PORT" SSH_TEST_PARTIAL_SUCCESS_PORT="$SSH_TEST_PARTIAL_SUCCESS_PORT" SSH_TEST_USER="$USER" SSH_TEST_PASSWORD="$PASSWORD" SSH_TEST_KNOWN_HOSTS="$KNOWN_HOSTS" sbcl --disable-debugger --load "$ROOT/.qlot/setup.lisp" --eval '(asdf:test-system :ssh/integration-tests)' --quit
