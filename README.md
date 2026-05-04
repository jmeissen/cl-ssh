# cl-ssh

A pure Common Lisp SSH 2.0 client.

## Status

Core transport, authentication, and session execution work. Use at your own risk.

Only `rsa` and `ed25519` host keys are currently supported.

Developed in SBCL and also tested on ECL.

## Dependencies

- [Ironclad](https://github.com/sharplispers/ironclad) - cryptography
- [usocket](https://github.com/usocket/usocket) - TCP-sockets
- [trivial-gray-streams](https://github.com/trivial-gray-streams/trivial-gray-streams) - stream wrappers
- [journal](https://github.com/melisgl/journal) - test logging/reporting
- [qlot](https://github.com/fukamachi/qlot) (more or less)

## Test dependencies

- [Parachute](https://codeberg.org/shinmera/parachute) - test framework
- [journal](https://github.com/melisgl/journal) - test logging/reporting

## Installation

```bash
qlot add github jmeissen/cl-ssh
```

```lisp
(ql:quickload :ssh)
```

## Usage

### `with-connection`

`with-connection` is the preferred way to use cl-ssh. It opens the connection, binds
the client handle to a variable, runs the body, and always closes the connection on
exit - including when an unhandled condition is signaled.

```lisp
;; Via ~/.ssh/config alias
(ssh:with-connection (client "myserver")
  (multiple-value-bind (stdout stderr code)
      (ssh:run-command client "uname -a")
    (format t "exit ~D~%~A" code stdout)))
```

All keyword arguments accepted by `connect` can be passed after the host:

```lisp
;; Public-key authentication (unencrypted key)
(ssh:with-connection (client "example.com"
                             :username "bob"
                             :identity "~/.ssh/id_ed25519")
  (ssh:run-command client "whoami"))

;; Public-key authentication (passphrase-protected key)
(ssh:with-connection (client "example.com"
                             :username "bob"
                             :identity "~/.ssh/id_ed25519"
                             :passphrase "my passphrase")
  (ssh:run-command client "whoami"))

;; Password authentication
(ssh:with-connection (client "example.com"
                             :username "bob"
                             :password "secret")
  (ssh:run-command client "whoami"))
```

Explicit keyword arguments always override `~/.ssh/config`.

### Manual lifecycle

When you need explicit control over the connection lifetime, use `connect` and
`disconnect` directly, but wrap the body in `unwind-protect` to avoid leaks:

```lisp
(let ((client (ssh:connect "myserver")))
  (unwind-protect
      (ssh:run-command client "uname -a")
    (ssh:disconnect client)))
```

### Sending and receiving commands
#### run-command
Single command execution.
```lisp
(ssh:with-connection (client "my_host")
  (multiple-value-bind (stdout stderr exit-code)
      (ssh:run-command client "ls -la /tmp")
    (format t "~A" stdout)))
```

#### open-shell
Interactive shell.
```lisp
(ssh:with-connection (client "my_host")
  (ssh:with-open-shell (shell client :pty nil)
    (ssh:shell-write-line shell "cd /tmp")
    (ssh:shell-write-line shell "pwd; printf '\\n__DONE__\\n'")
    (format t "~A" (ssh:shell-read-until shell "__DONE__"))))
```

`open-shell` itself still returns `(values stream channel)` for callers that
need direct channel access.  The helper functions operate on the returned binary
stream and hide the string/octet conversion for common interactive-shell use.

Use `:pty nil` for scripted shell interaction like the example above.  A PTY is
for terminal-oriented programs; with `:pty t`, servers commonly add prompts,
echo typed commands, translate line endings, and emit terminal control sequences.
Those bytes are returned as normal shell output, so marker-based reads may still
work but the captured text is not machine-clean.

#### open-subsystem

```lisp
;; Open an SFTP subsystem stream (raw framing; no SFTP protocol implemented yet)
(multiple-value-bind (stream channel)
    (ssh:open-subsystem client "sftp")
  ...)
```

## Supported algorithms

| Category    | Algorithm                       | Tested |
|-------------|---------------------------------|--------|
| KEX         | `curve25519-sha256`             | Yes    |
| KEX         | `curve25519-sha256@libssh.org`  | No     |
| KEX         | `diffie-hellman-group14-sha256` | Yes    |
| Host keys   | `ssh-ed25519`                   | Yes    |
| Host keys   | `rsa-sha2-256`                  | Manual |
| Host keys   | `rsa-sha2-512`                  | -      |
| Ciphers     | `aes128-ctr`                    | Yes    |
| Ciphers     | `aes256-ctr`                    | No     |
| MACs        | `hmac-sha2-256`                 | Yes    |
| MACs        | `hmac-sha2-512`                 | No     |
| Compression | `none`                          | —      |


## Supported authentication methods

| Method      | Notes                                                                         |
|-------------|-------------------------------------------------------------------------------|
| `publickey` | Ed25519 and RSA; OpenSSH new-format keys, unencrypted or passphrase-protected |
| `password`  | Plaintext inside the encrypted transport                                      |
| `none`      | Probe only                                                                    |

## `~/.ssh/config` support

The following keywords are read and applied:

`HostName`, `Port`, `User`, `IdentityFile`, `StrictHostKeyChecking`,
`UserKnownHostsFile`

All other keywords are silently ignored. `IdentitiesOnly` is not supported:
even when set in the config, password authentication may still be attempted if
`:password` is passed to `connect`.

## Known limitations

- No re-key (subsequent key exchanges after the initial one)
- No port forwarding
- No SFTP protocol (subsystem channel can be opened; framing not implemented)
- No `ssh-agent` support
- No server mode
- `IdentitiesOnly` config keyword not supported
- Single-threaded; `open-shell` does not handle concurrent stdin/stdout

# Contributing
## Installing
``` shell
git clone https://github.com/jmeissen/cl-ssh
cd cl-ssh
qlot install
```
## Running tests
``` shell
sbcl --disable-debugger --load .qlot/setup.lisp --eval '(asdf:test-system :ssh)' --quit
```
