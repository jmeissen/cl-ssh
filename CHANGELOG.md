# Changelog

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
