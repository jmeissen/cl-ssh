#!/usr/bin/env bash
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
TAG=${1:?usage: release-evidence.sh SIGNED_TAG}
OUTPUT=${RELEASE_OUTPUT_DIRECTORY:-"$ROOT/dist"}
ALLOWED_SIGNERS="$ROOT/.github/release-signers"
RELEASE_PRINCIPAL=jeffrey@meissen.email

if [[ ! "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]]; then
  echo "invalid release tag: $TAG" >&2
  exit 64
fi

git -C "$ROOT" show-ref --verify --quiet "refs/tags/$TAG" || {
  echo "release tag does not exist: $TAG" >&2
  exit 66
}

if [ "$(git -C "$ROOT" cat-file -t "refs/tags/$TAG")" != tag ]; then
  echo "release tag must be annotated: $TAG" >&2
  exit 65
fi

tagger_email=$(git -C "$ROOT" for-each-ref --format='%(taggeremail)' "refs/tags/$TAG")
tagger_email=${tagger_email#<}
tagger_email=${tagger_email%>}
if [ "$tagger_email" != "$RELEASE_PRINCIPAL" ]; then
  echo "release tagger must be $RELEASE_PRINCIPAL, got $tagger_email" >&2
  exit 65
fi

if [ ! -f "$ALLOWED_SIGNERS" ] ||
   ! grep -Eq '^[[:space:]]*[^#[:space:]]' "$ALLOWED_SIGNERS"; then
  echo "no release signing key is configured in $ALLOWED_SIGNERS" >&2
  exit 78
fi

mkdir -p "$OUTPUT"
git -C "$ROOT" \
  -c gpg.format=ssh \
  -c gpg.ssh.allowedSignersFile="$ALLOWED_SIGNERS" \
  verify-tag "$TAG" 2>&1 | tee "$OUTPUT/tag-verification.txt"

ARCHIVE="$OUTPUT/cl-ssh-$TAG.tar.gz"
git -C "$ROOT" archive --format=tar.gz --output="$ARCHIVE" "$TAG"
git -C "$ROOT" show --quiet \
  --format='tag=%D%ncommit=%H%nsubject=%s%n' "$TAG" > "$OUTPUT/tag.txt"

checksum_files=("$(basename "$ARCHIVE")")
if [ -f "$OUTPUT/release-run-evidence.tar.gz" ]; then
  checksum_files+=("release-run-evidence.tar.gz")
fi

(
  cd "$OUTPUT"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${checksum_files[@]}" > SHA256SUMS
  else
    shasum -a 256 "${checksum_files[@]}" > SHA256SUMS
  fi
)
