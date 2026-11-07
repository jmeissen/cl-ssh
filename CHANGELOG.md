# Changelog

All notable changes are recorded here, following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - 2026-11-07

### Added
- Concurrent command, shell, subsystem, and SFTP channels over one authenticated
  connection, with a shared dispatcher and independent channel flow control.
- SFTP v3 file/directory operations, binary remote-file streams, and pipelined
  uploads/downloads with progress callbacks; OpenSSH `limits`, `posix-rename`,
  and `fsync` extensions, plus selectable symlink argument order.
- Optional streaming `zlib` compression, RFC 8308 `delay-compression`, and
  OpenSSH delayed-zlib interoperability.
- GitHub and Forgejo CI for SBCL/ECL, integration tests, parser fuzzing, and
  secret scanning; signed-tag release evidence and user/developer guides.
- AES-128-GCM and AES-256-GCM packet protection using both the RFC 5647
  `AEAD_AES_*_GCM` names and the common `aes*-gcm@openssh.com` names.
- Honor `RekeyLimit` configuration and expose `ssh:connect`
  `:rekey-byte-limit` / `:rekey-seconds-limit` overrides.
- Support transport key re-exchange after the initial key exchange (RFC 4253 §9),
  including packet, byte, and time based rekey triggers (RFC 4344 §3).
- Support RFC 4256 `keyboard-interactive` authentication method. Fully supported,
  except there's no inbuilt masking of user input (RFC 4256 §3.3 ¶6).
- Support for RFC 8308 `ext-info` discovery and `server-sig-algs`-based RSA public
  key authentication selection (RFC 8308 §3.1)
- Integration tests through Docker and an additional integration testing system.

### Changed

- **Breaking:** shell/subsystem streams reclaim consumed input and replenish
  receive windows on consumption. Buffer accessors return copies of unread bytes;
  their `setf` places are removed. Drain both stdout and stderr in streaming mode.
  Pass `:capture-output t` to retain full history (with unbounded memory use);
  `run-command` retains its complete-output behavior.
- `open-shell` and `open-subsystem` return a third value, an input-only stderr
  stream. Closing it retains a bounded diagnostic tail. SFTP likewise keeps
  stderr separate from protocol data, with a 64 KiB tail and truncation reporting.

### Security

- Strict host-key checking by default, unconditional rejection of matching
  `@revoked` keys, and RSA-SHA2 verification against ordinary `ssh-rsa` pins.
  Host lists/wildcards are supported and shared pins survive single-host updates.
  RSA-SHA1 client signatures require explicit opt-in.
- OpenSSH strict key exchange, with handshake-message validation and directional
  sequence resets after NEWKEYS, including rekeys.
- Hardened malformed key/config/host-file parsing and keyboard-interactive CLI
  prompts: terminal controls are escaped and hidden prompts require an explicit
  no-echo reader.

### Fixed
- Release sockets, control sockets, channels, and subsystem streams when transport,
  authentication, dispatcher, or session setup fails or unwinds; preserve the
  original error and keep unrelated channels usable.
- Dispatcher responsiveness during idle traffic, rekeying, and concurrent reads
  and writes; unread channel streams no longer block unrelated channels.
- Failed assertions now make both ASDF test systems exit unsuccessfully, with
  ECL-compatible test fixtures and regression checks for the failure exit status.
- Plain `known_hosts` hostnames now match case-insensitively when checking the local
  host name-to-key db because DNS is case-insensitive (RFC 1035 §2.3.3 ¶1)
- `known_hosts` additions and stale-key replacement now use a lock.
- Prefer the stronger `aes256-ctr` over `aes128-ctr` for kex and rekey.
- Reuse packet HMAC state between packets (for performance).
- SSH data encoding, octets, US-ASCII, and UTF-8 where needed (RFC 4252 §5, §8; RFC
  4254 §5)

## [0.2.0] - 2026-05-17

### Added
- Backward compatibility with SSH version exchange (RFC 4253 §5.1 ¶1)

### Changed
- **Breaking**: shell read helpers (`shell-read-{line,until}`) to be possibly
  non-blocking and non-signaling

### Fixed
- `connect` did not update known_hosts when `:strict-host-checking` was `nil`
- Memory-exhaustion bug in `recv-version`  (RFC 4253 §4.2 ¶2)
- Incorrect padding verification bug (RFC 8332 §5.3 ¶2), though encodings with omitted
  leading zeroes are still not accepted (RFC 8332 §3 ¶9)
