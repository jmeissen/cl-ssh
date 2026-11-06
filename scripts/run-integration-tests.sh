#!/usr/bin/env bash
set -euo pipefail

if ! command -v ssh-keyscan >/dev/null 2>&1; then
    printf '%s\n' 'ssh-keyscan is required; install the OpenSSH client package.' >&2
    exit 127
fi

ROOT=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

docker_endpoint_host() {
    local endpoint=${DOCKER_HOST#tcp://}

    endpoint=${endpoint%%/*}
    if [[ $endpoint == \[*\]* ]]; then
        endpoint=${endpoint#\[}
        printf '%s\n' "${endpoint%%\]*}"
    else
        printf '%s\n' "${endpoint%%:*}"
    fi
}

container_default_gateway() {
    local gateway_hex

    gateway_hex=$(awk '$2 == "00000000" { print $3; exit }' /proc/net/route)
    if [[ ! $gateway_hex =~ ^[[:xdigit:]]{8}$ ]]; then
        return 1
    fi

    printf '%d.%d.%d.%d\n' \
           "0x${gateway_hex:6:2}" \
           "0x${gateway_hex:4:2}" \
           "0x${gateway_hex:2:2}" \
           "0x${gateway_hex:0:2}"
}

running_in_container() {
    [ -f /.dockerenv ] \
        || [ -f /run/.containerenv ] \
        || { [ -r /proc/1/cgroup ] \
                 && grep -Eqa '(docker|containerd|kubepods|libpod)' /proc/1/cgroup; }
}

resolve_ipv4() {
    getent ahostsv4 "$1" 2>/dev/null | awk 'NR == 1 { print $1 }'
}

scan_host_keys() {
    local keys
    local port=$1

    if ! keys=$(ssh-keyscan -p "$port" "$HOST" 2>/dev/null) || [ -z "$keys" ]; then
        return 1
    fi
    printf '%s\n' "$keys" >>"$SCANNED_HOSTS"
}

HOST=${SSH_TEST_HOST:-}
if [ -z "$HOST" ]; then
    if [[ ${DOCKER_HOST:-} == tcp://* ]]; then
        HOST=$(docker_endpoint_host)
    elif running_in_container; then
        if ! HOST=$(container_default_gateway); then
            printf '%s\n' 'could not determine the Docker host gateway from this container' >&2
            exit 1
        fi
    else
        HOST=127.0.0.1
    fi
fi

BIND_ADDRESS=${SSH_TEST_BIND_ADDRESS:-}
if [ -z "$BIND_ADDRESS" ]; then
    case $HOST in
        127.0.0.1 | localhost | ::1)
            BIND_ADDRESS=127.0.0.1
            ;;
        *)
            if ! BIND_ADDRESS=$(resolve_ipv4 "$HOST"); then
                BIND_ADDRESS=
            fi
            if [ -z "$BIND_ADDRESS" ]; then
                printf 'could not resolve an IPv4 bind address for SSH test host %s\n' "$HOST" >&2
                exit 1
            fi
            ;;
    esac
fi
export SSH_TEST_BIND_ADDRESS=$BIND_ADDRESS

PORT=${SSH_TEST_PORT:-2222}
RSA_SHA2_512_PORT=${SSH_TEST_RSA_SHA2_512_PORT:-$PORT}
RSA_SHA2_256_PORT=${SSH_TEST_RSA_SHA2_256_PORT:-2223}
SSH_RSA_PORT=${SSH_TEST_SSH_RSA_PORT:-2224}
KBDINT_PORT=${SSH_TEST_KBDINT_PORT:-2225}
SSH_TEST_PARTIAL_SUCCESS_PORT=${SSH_TEST_PARTIAL_SUCCESS_PORT:-2226}
AES256_GCM_PORT=${SSH_TEST_AES256_GCM_PORT:-2227}
AES128_GCM_PORT=${SSH_TEST_AES128_GCM_PORT:-2228}
USER=${SSH_TEST_USER:-ssh-tést}
PASSWORD=${SSH_TEST_PASSWORD:-cl-ssh-pässwörd-値}
KNOWN_HOSTS=$(mktemp)
SCANNED_HOSTS=$(mktemp)

cleanup() {
    rm -f "$KNOWN_HOSTS" "$SCANNED_HOSTS"
    docker compose -f "$ROOT/docker-compose.yml" down -v --remove-orphans >/dev/null 2>&1 || true
}

trap cleanup EXIT INT TERM

if [ "${SSH_TEST_REBUILD:-0}" = 1 ] || ! docker image inspect cl-ssh-sshd >/dev/null 2>&1; then
    docker compose -f "$ROOT/docker-compose.yml" up -d --build
else
    docker compose -f "$ROOT/docker-compose.yml" up -d
fi

printf 'waiting for SSH test services at %s (Docker bind address %s)\n' "$HOST" "$BIND_ADDRESS"
SERVICES_READY=0
for _ in $(seq 1 30); do
    : >"$SCANNED_HOSTS"
    if scan_host_keys "$RSA_SHA2_512_PORT" \
            && scan_host_keys "$RSA_SHA2_256_PORT" \
            && scan_host_keys "$SSH_RSA_PORT" \
            && scan_host_keys "$KBDINT_PORT" \
            && scan_host_keys "$SSH_TEST_PARTIAL_SUCCESS_PORT" \
            && scan_host_keys "$AES256_GCM_PORT" \
            && scan_host_keys "$AES128_GCM_PORT"; then
        SERVICES_READY=1
        break
    fi
    sleep 1
done

if [ "$SERVICES_READY" != 1 ]; then
    printf 'failed to scan SSH host keys from %s:%s %s:%s %s:%s %s:%s %s:%s %s:%s %s:%s
'     "$HOST" "$RSA_SHA2_512_PORT" "$HOST" "$RSA_SHA2_256_PORT" "$HOST" "$SSH_RSA_PORT" "$HOST" "$KBDINT_PORT" "$HOST" "$SSH_TEST_PARTIAL_SUCCESS_PORT" "$HOST" "$AES256_GCM_PORT" "$HOST" "$AES128_GCM_PORT" >&2
    docker compose -f "$ROOT/docker-compose.yml" ps >&2
    docker compose -f "$ROOT/docker-compose.yml" logs --tail=50 >&2
    exit 1
fi

# cl-ssh currently keys known_hosts entries by hostname and does not yet parse
# OpenSSH's [host]:port form emitted by ssh-keyscan for non-default ports.
awk -v host="$HOST" '{$1 = host; print}' "$SCANNED_HOSTS" >"$KNOWN_HOSTS"

SSH_TEST_HOST="$HOST" \
SSH_TEST_PORT="$PORT" \
SSH_TEST_RSA_SHA2_512_PORT="$RSA_SHA2_512_PORT" \
SSH_TEST_RSA_SHA2_256_PORT="$RSA_SHA2_256_PORT" \
SSH_TEST_SSH_RSA_PORT="$SSH_RSA_PORT" \
SSH_TEST_KBDINT_PORT="$KBDINT_PORT" \
SSH_TEST_PARTIAL_SUCCESS_PORT="$SSH_TEST_PARTIAL_SUCCESS_PORT" \
SSH_TEST_AES256_GCM_PORT="$AES256_GCM_PORT" \
SSH_TEST_AES128_GCM_PORT="$AES128_GCM_PORT" \
SSH_TEST_USER="$USER" \
SSH_TEST_PASSWORD="$PASSWORD" \
SSH_TEST_KNOWN_HOSTS="$KNOWN_HOSTS" \
SSH_PROJECT_ROOT="$ROOT" \
sbcl --disable-debugger \
     --load "$ROOT/.qlot/setup.lisp" \
     --eval '(asdf:load-asd (merge-pathnames "ssh.asd" (uiop:ensure-directory-pathname (uiop:getenv "SSH_PROJECT_ROOT"))))' \
     --eval '(ql:quickload :ssh)' \
     --eval '(asdf:test-system :ssh/integration-tests)' \
     --quit
