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
- [babel](https://github.com/cl-babel/babel) - UTF-8 string to octet support
- [qlot](https://github.com/fukamachi/qlot) (more or less)

## Test dependencies

- [Parachute](https://codeberg.org/shinmera/parachute) - test framework

## Installation

This package is not available in quicklisp. However, it is available in
[Ultralisp](https://ultralisp.org), which makes loading the package as easy as:

```lisp
(ql:quickload :ssh)
```
For project-local versioning with Qlot, you could use:
``` shell
qlot add ultralisp jmeissen-cl-ssh
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

## RFC implementation status

This table distinguishes code support from full RFC compliance. "Partial" means
the code implements useful pieces of the RFC, but does not implement enough of
the RFC to claim full compliance.

| RFC                 | Compliant?                                        | Notes                                                                                                           |
|---------------------|---------------------------------------------------|-----------------------------------------------------------------------------------------------------------------|
| RFC 4250            | Partial                                           | Constants and algorithm names are defined for the supported subset only.                                        |
| RFC 4251            | Partial                                           | SSH binary data types are implemented, but this is not full architecture compliance.                            |
| RFC 4252            | Partial                                           | Supports `none`, `password`, and `publickey`; no full authentication protocol coverage.                         |
| RFC 4253            | Partial                                           | Transport, KEXINIT, NEWKEYS, packet framing, and key derivation exist; no rekey and limited algorithms.         |
| RFC 4254            | Partial                                           | Basic session channel, exec, shell, subsystem, and flow-control handling exist.                                 |
| RFC 4255            | None, probably too niche as well                  | DNS SSHFP lookup and validation are not implemented.                                                            |
| RFC 4256            | None, but probably should add                     | Keyboard-interactive authentication is not implemented.                                                         |
| RFC 4344            | Partial                                           | `aes128-ctr` and `aes256-ctr` are supported; rekey recommendations are not implemented.                         |
| RFC 4419 / RFC 8270 | None, but mostly deprecated                       | Diffie-Hellman group exchange is not implemented.                                                               |
| RFC 5647            | None. Should do the OpenSSH one when implementing | AES-GCM is not implemented.                                                                                     |
| RFC 5656            | None, but should be implemented                   | NIST ECDH, ECDSA, and ECMQV are not implemented; Curve25519 only reuses ECDH packet framing.                    |
| RFC 6668            | Yes                                               | `hmac-sha2-256` and `hmac-sha2-512` are advertised and wired into packet MAC handling.                          |
| RFC 8268            | Partial                                           | `diffie-hellman-group14-sha256` is implemented; group15-18 are absent.                                          |
| RFC 8308            | None, but should be done and is low cost          | `ext-info-c/s`, `SSH_MSG_EXT_INFO`, and `server-sig-algs` are not implemented.                                  |
| RFC 8332            | Partial                                           | RSA-SHA2 host-key verification exists; RSA publickey client auth is not fully RFC-conformant.                   |
| RFC 8709            | Partial                                           | `ssh-ed25519` is supported; `ssh-ed448` and SSHFP Ed448 handling are absent.                                    |
| RFC 8731            | Partial                                           | `curve25519-sha256` and `curve25519-sha256@libssh.org` are implemented; `curve448-sha512` is absent.            |
| RFC 8758            | Yes                                               | RC4/arcfour algorithms are not implemented or advertised.                                                       |
| RFC 9142            | Partial                                           | Some recommended KEX methods are present, but extension negotiation and several recommended methods are absent. |
| RFC 9941            | None. Should be done in the future                | `sntrup761x25519-sha512` and the OpenSSH alias are not implemented.                                             |

Quite some SSH RFCs are omitted. Some are deprecated, some too niche to even mention,
or they do not seem relevant at the time of writing. Please open an issue upon
disagreement.

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
