# cl-ssh

A pure Common Lisp SSH 2.0 client.

- [Status](#status)
- [Installation](#installation)
- [Usage](#usage)
- [Connection options](#connection-options)
- [Compatibility and limitations](#compatibility-and-limitations)
- [Development](#development)
- [License and acknowledgements](#license-and-acknowledgements)

## Status

Core transport, authentication, session execution, and SFTP v3 work. The 1.0
release uses modern SSH defaults and automated deterministic, integration,
secret, and fuzz-corpus checks. See [SECURITY.md](SECURITY.md) for reporting and
support. I want to emphasize that this library, because of its age, cannot be
considered mature. This means that in using this library, you are helping it
mature and I hope you will report errors.

Only `rsa` and `ed25519` host keys are currently supported.

Developed in SBCL and also tested on ECL.

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

## Dependencies

- [Ironclad](https://github.com/sharplispers/ironclad) - cryptography
- [usocket](https://github.com/usocket/usocket) - TCP-sockets
- [trivial-gray-streams](https://github.com/trivial-gray-streams/trivial-gray-streams) - stream wrappers
- [babel](https://github.com/cl-babel/babel) - UTF-8 string to octet support
- [Bordeaux Threads](https://github.com/sionescu/bordeaux-threads) - portable threads, locks, and conditions
- [Nibbles](https://github.com/sharplispers/nibbles) - endian-aware octet-vector access

## Usage

### Running commands

`ssh:cmd` connects, executes one command, and disconnects:

```lisp
(ssh:cmd "bob@example.com" "whoami" :identity "~/.ssh/id_ed25519")
```

It returns three values: stdout, stderr, and the remote exit status, including
nonzero statuses. The command string is passed unchanged to the server.
`:environment` accepts an association list such as `'(("LANG" . "C"))`;
other keyword arguments are passed to [ssh:connect](#connection-options).

### Reusing a connection

For several operations on one server, use `ssh:with-connection` with
`ssh:run-command`, shells, or SFTP. Each operation uses a channel on the same
authenticated connection.

```lisp
(ssh:with-connection (client "myserver")
  (multiple-value-bind (stdout stderr code)
      (ssh:run-command client "uname -a")
    (format t "exit ~D~%~A~%~A" code stdout stderr)))
```

`run-command` accepts the same `:environment` option and returns the same
three values as `cmd`. `with-connection` passes its options to `connect` and
disconnects when the body exits. For manual connection lifetimes, use
`connect` and `disconnect` with `unwind-protect`:

```lisp
(let ((client (ssh:connect "myserver")))
  (unwind-protect
      (ssh:run-command client "uname -a")
    (ssh:disconnect client)))
```

Failed connection and session setup releases owned sockets, channels, and
streams while preserving the original error.

### Interactive shells

Combine `ssh:with-connection` with `ssh:with-open-shell`. This allows for using,
for example, `ssh:shell-write-line`, `ssh:shell-read-line` and
`ssh:shell-read-until`.

```lisp
(ssh:with-connection (client "my_host")
  (ssh:with-open-shell (shell client :pty nil)
    (ssh:shell-write-line shell "cd /tmp")
    (ssh:shell-write-line shell "pwd; printf '\\n__DONE__\\n'")
    (format t "~A" (ssh:shell-read-until shell "__DONE__"))))
```

Or, try a dumb interactive shell from your REPL. When done playing, type `exit<RET>`.
```lisp
(ssh:with-connection (c "remote.host" :username "alice")
  (ssh:with-open-shell (s c :pty nil)
    (loop
      for line = (read-line)
      for exiting = (string= line "exit")
      do (ssh:shell-write-line s line)
         (unless exiting
           (ssh:shell-write-line s "printf '%s' '__CL_SSH_DONE__'"))
         (write-string
          (ssh:shell-read-until s (unless exiting "__CL_SSH_DONE__")
                                :error-p nil))
         (finish-output)
      until exiting)))
```

#### Advanced shell: streams, stderr, and PTY

`ssh:open-shell` and `ssh:open-subsystem` return
`(values stream channel stderr-stream)`: a bidirectional binary stream and
an input-only stderr stream. `open-subsystem` takes a client and subsystem name;
use `open-sftp` for the higher-level SFTP API.

Shell helpers convert text to/from UTF-8. `shell-read-line` reads to EOL;
`shell-read-until` reads to a marker. If the marker is `nil`, then
`shell-read-until` reads to EOF and may block indefinitely while the shell stays
open. Disable this blocking behavior by passing `:block-p nil` to drain only
currently available bytes. Pass `:error-p nil` to suppress read conditions and
inspect the second return value.

Shells default to `:pty nil` for scripted interaction. Set `:pty t` for terminal
programs where you want to read all line endings, terminal controls, etc. These
appear in the returned output. Initial terminal type and size use `:pty-term`,
`:pty-cols`, and `:pty-rows`; shells also accept `:environment`.

> [!WARNING]
> Read both stdout and stderr when both can produce output. They share a
> receive window of 2 MiB per channel. Leaving either stream unread can
> fill that window and block further output on both streams.
> If you do not need stderr, close its stream; the channel stays open
> and retains only a bounded diagnostic tail.

See `ssh/connection:open-channel` to override the default value per channel.
However, note that this is not yet considered part of the public API and may be
subject to change. Alternatively, reading consumes buffered bytes and frees
receive-window space, while the channel-buffer accessors return copies of unread
bytes.

To retain complete output history, pass `:capture-output t` to `open-shell`,
`with-open-shell`, or `open-subsystem`. This history can grow without limit in
memory. `run-command` captures complete stdout and stderr internally.

Normal stream close sends EOF/CLOSE and waits for the peer's CLOSE.
`(close stream :abort t)` sends CLOSE without waiting and wakes blocked readers
with failure.

### File transfers (SFTP)

#### Single-file copies

`ssh:scp` uses SFTP to upload or download one file and manages its own connection
and SFTP session. It returns the destination path and transferred byte count
after successful cleanup.

```lisp
(ssh:scp "bob@myserver:/remote/report.bin" #P"report.bin")
(ssh:scp #P"report.bin" "alice@myotherserver:/remote/report.bin")

;; Copy into an existing directory, keeping the filename.
(ssh:scp #P"report.bin" "myserver:/remote/reports/")

;; A nondefault port and an absolute remote path.
(ssh:scp #P"report.bin" "scp://bob@[::1]:2222//remote/report.bin")
```

Exactly one endpoint must be remote: `[user@]host:path` or
`scp://[user@]host[:port]/path`. In a URI, `/file` means relative `file`
and `//file` means absolute `/file`; an empty remote path means `.`.
URI usernames and paths are decoded; shorthand paths are literal.
A colon before any slash marks a string as remote. Use `"./name:part"`
or `#P"name:part"` for a local filename containing a colon.

Existing files are replaced by default; `:if-exists :error` rejects replacement.
`:progress-function` uses the callback described below. Other options go to
`connect`, with explicit `:username` and `:port` overriding endpoint values.
Remote paths go directly to SFTP, without shell interpolation, wildcard or
tilde expansion.

#### Sessions and transfers

Use `ssh:with-sftp` to perform several operations on an existing connection:

```lisp
(ssh:with-connection (client "myserver")
  (ssh:with-sftp (sftp client)
    (ssh:sftp-download sftp "/remote/report.bin" #P"report.bin")
    (ssh:sftp-upload sftp #P"report.bin" "/remote/new-report.bin")
    (ssh:with-open-sftp-file (input sftp "/remote/report.bin")
      (read-byte input))))
```

| Operation       | Return values                            | Existing destination                                      |
|-----------------|------------------------------------------|-----------------------------------------------------------|
| `sftp-download` | Local pathname, transferred bytes        | `:error` (default), `:supersede`                          |
| `sftp-upload`   | Supplied remote path, acknowledged bytes | `:error` (default), `:supersede`, `:overwrite`, `:append` |

Upload also accepts `:if-does-not-exist :create` (default) or `:error`, and
`:attributes` for creation attributes (see `ssh:make-sftp-attributes`). Parent directories must exist. Transfers
do not preserve metadata automatically or guarantee atomic replacement. Sources
are opened before destinations are modified; failure may leave a partial
destination, which is not automatically removed or rolled back.

Upload's `:fsync t` (file synchronization) requires the advertised fsync
OpenSSH-extension before modifying the destination and synchronizes acknowledged
writes before close.

Both helpers accept `:progress-function`, called as `(function completed-bytes
total-or-nil)`, starting at zero. Upload counts acknowledged writes and download
counts local writes. Totals are advisory. Callbacks run on the calling thread
outside state locks, therefore reentering or closing any enclosing callback's
SFTP session, including through nested callbacks, signals an error. Callback
failure stops new requests, drains pending replies where possible, and cleans up
the handle.

#### Remote-file streams

`ssh:open-sftp-file` and `ssh:with-open-sftp-file` follow
[Common Lisp `open`](http://www.lispworks.com/documentation/HyperSpec/Body/f_open.htm)
and `with-open-file`, with an SFTP session before the remote path.
The differences are:

- Remote paths are UTF-8 strings or raw octet vectors, without local pathname
  merging, wildcard processing, or file versions. Stream/pathname designators
  are not accepted.
- Streams are binary Gray streams, not native `file-stream` objects.
  `:element-type` defaults to `(unsigned-byte 8)`; only equivalent types and
  `:default` are supported. `:external-format` is ignored.
  Native file-stream operations such as `pathname`, `truename`, and
  `file-length` are not provided.
- `:if-exists` defaults to `:error`; `:new-version`, `:rename`, and
  `:rename-and-delete` are unsupported. The additional `:default` value
  selects the default for either existence option.
- `:supersede` truncates the existing file immediately, in place. It does
  not defer replacement until close; failure can leave a partial destination.
- Append is output-only and forces every write to the server's current end of
  file. Append streams are non-seekable (`file-position` returns `nil`).
  Seeking other streams to `:end` requires the server to report file size.
- `:attributes` supplies SFTP creation attributes.
- Errors use SFTP conditions rather than `file-error`. Existence checks that
  require STAT and OPEN are not atomic against changes by other clients.
  Ambiguous server failures remain errors rather than being treated as absence
  or silently converted to `nil`.
- Flushing checks remote write acknowledgements; normal close also checks the
  server's CLOSE reply. Use `sftp-fsync` for filesystem durability.
  Abort discards unsent output without undoing completed writes.

Closing an SFTP session normally flushes and closes its owned file streams.

> [!NOTE]
> It is nice to have one-to-one compatibility with `open`, so increasing
> compatibility for the function is a focus of improved for the future. However,
> as it will constitute major version changes since it breaks the public API,
> I'll probably bundle the improvements all together and release at once.

#### Advanced SFTP: Operations, paths, and extensions

The API provides file/handle open and close, `sftp-read-at` and `sftp-write-at`,
directory open/read/list, stat/lstat/fstat, setstat/fsetstat,
mkdir/rmdir/remove, rename, realpath, readlink, and symlink. See `src/ssh.lisp`
for all exported `sftp` symbols. Read-at returns a bounded block and an EOF
flag; a short block is not EOF.  Directory reads return batches of `sftp-entry`
records and an EOF flag.

Sizes and offsets are unsigned 64-bit values. Attribute times are Unix seconds.
Missing attributes are `nil`, distinct from zero. UID/GID and access/modification
times must be supplied in pairs. `longname` is opaque listing text.
Paths accept UTF-8 strings or raw octet vectors, including an empty path for the
default directory. Returned names, canonical paths, and link targets preserve
raw octets, so use `sftp-name-string` to decode UTF-8 explicitly.

The protocol is SFTP v3, with version-1 OpenSSH `limits@openssh.com`,
`posix-rename@openssh.com`, and `fsync@openssh.com` extensions.
Ordinary rename rejects an existing destination; `sftp-posix-rename` requests
replacement without delete/rename fallbacks. Unknown extensions are ignored.

The v3 draft and OpenSSH use different symlink argument orders. On `open-sftp`,
the keyword argument `:symlink-order` accepts `:draft`, `:openssh`, or `:auto`
(default). `:auto` recognizes OpenSSH server identification strings and otherwise
uses draft ordering. Override it when a server's identification hides its
convention; no mutating probe or automatic retry is performed.

`sftp-status-error` retains the operation, path, request ID, status, server
message, and language. Malformed SFTP data fails that session and underlying SSH
failures are retained as causes. `sftp-diagnostics` returns the last 64 KiB of
subsystem stderr and a truncation flag. Handles become invalid on CLOSE even
if its reply reports failure.

### Concurrent channels on a single connection

This library supports concurrency: you may open and use different channels on
different threads over the same connection. Each connection owns one
event-driven dispatcher such that all commands, shells, and subsystems opened
from the client on the same connection will be multiplexed over it.

Public operations within one SFTP session are serialized, so if you want
independently progressing transfers, open separate SFTP sessions. Each SFTP
session defaults to 32 KiB blocks, 16 pending/undelivered requests, and a 1 MiB
incoming frame limit. Though negotiated server limits still apply, they can be
tuned on `open-sftp` with `:block-size`, `:max-pending`, and
`:max-packet-length`.

Replace `alice@sftp.example.com` with your server. Each example creates a
temporary local file and deletes it afterward; reruns replace the remote files.
The progress callback briefly pauses to make the difference visible in the REPL.

**Serial:** two threads share one SFTP session. All progress lines for A appear
before B, or vice versa.

```lisp
(uiop:with-temporary-file (:stream out :pathname path :direction :output
                           :element-type '(unsigned-byte 8))
  (dotimes (i (* 1024 1024))
    (write-byte (random 256) out))
  (close out)
  (let* ((output *standard-output*)
         (output-lock (bt2:make-lock :name "progress output"))
         (progress
           (lambda (done total)
             (when (or (zerop (mod done 262144)) (eql done total))
               (bt2:with-lock-held (output-lock)
                 (format output "~&~A: ~D KiB~%"
                         (bt2:thread-name (bt2:current-thread)) (floor done 1024))
                 (finish-output output))
               (sleep 0.2)))))          ; Slow the demo so progress is visible.
    (ssh:with-connection (client "alice@sftp.example.com")
      (ssh:with-sftp (sftp client)
        (let ((first
                (bt2:make-thread
                 (lambda ()
                   (ssh:sftp-upload sftp path "serial-first.bin"
                                    :if-exists :supersede
                                    :progress-function progress))
                 :name "A"))
              (second
                (bt2:make-thread
                 (lambda ()
                   (ssh:sftp-upload sftp path "serial-second.bin"
                                    :if-exists :supersede
                                    :progress-function progress))
                 :name "B")))
          (unwind-protect (bt2:join-thread first)
            (bt2:join-thread second)))))))
```

**Concurrent:** each thread opens its own SFTP session on the same connection.
Progress lines for A and B can interleave; their order depends on scheduling.

```lisp
(uiop:with-temporary-file (:stream out :pathname path :direction :output
                           :element-type '(unsigned-byte 8))
  (dotimes (i (* 1024 1024))
    (write-byte (random 256) out))
  (close out)
  (let* ((output *standard-output*)
         (output-lock (bt2:make-lock :name "progress output"))
         (progress
           (lambda (done total)
             (when (or (zerop (mod done 262144)) (eql done total))
               (bt2:with-lock-held (output-lock)
                 (format output "~&~A: ~D KiB~%"
                         (bt2:thread-name (bt2:current-thread)) (floor done 1024))
                 (finish-output output))
               (sleep 0.2)))))          ; Slow the demo so progress is visible.
    (ssh:with-connection (client "alice@sftp.example.com")
      (let ((first
              (bt2:make-thread
               (lambda ()
                 (ssh:with-sftp (sftp-a client
                                        :block-size 16384 :max-pending 8
                                        :max-packet-length 262144)
                   (ssh:sftp-upload sftp-a path "concurrent-first.bin"
                                    :if-exists :supersede
                                    :progress-function progress)))
               :name "A"))
            (second
              (bt2:make-thread
               (lambda ()
                 (ssh:with-sftp (sftp-b client
                                        :block-size 32768 :max-pending 16
                                        :max-packet-length 1048576)
                   (ssh:sftp-upload sftp-b path "concurrent-second.bin"
                                    :if-exists :supersede
                                    :progress-function progress)))
               :name "B")))
        (unwind-protect (bt2:join-thread first)
          (bt2:join-thread second))))))
```

The following example illustrates concurrent `ssh:run-command` execution.

```lisp
(defun run-commands-concurrently (client commands)
  (let* ((results (make-array (length commands)))
         (output *standard-output*)
         (output-lock (bt2:make-lock :name "command output"))
         (threads
           (loop for command in commands
                 for index from 0
                 collect
                 ;; Give each thread its own bindings for the loop values.
                 (let ((command command)
                       (index index))
                   (bt2:make-thread
                    (lambda ()
                      (let ((result
                              (handler-case
                                  (multiple-value-list
                                   (ssh:run-command client command))
                                (error (condition)
                                  condition))))
                        (setf (aref results index) result)
                        (bt2:with-lock-held (output-lock)
                          (if (typep result 'condition)
                              (format output "~&~A => error: ~A~%"
                                      command result)
                              (destructuring-bind (stdout stderr exit-code)
                                  result
                                (format output
                                        "~&~A => exit ~D, stdout=~S, stderr=~S~%"
                                        command exit-code stdout stderr)))
                          (finish-output output)))))))))
    (mapc #'bt2:join-thread threads)
    (loop for result across results
          collect (if (typep result 'condition)
                      (error result)
                      result))))

(ssh:with-connection (client "my_host")
  (run-commands-concurrently
   client
   '("sleep 2; printf slow"
     "printf fast"
     "printf third")))
```

#### Two interactive shells

Both workers below share `client`, but each opens its own shell with
`ssh:with-open-shell`. Each thread sends three commands and prints their
one-line replies to the caller's stdout. Shell A waits two seconds per reply;
shell B waits one, so B can send and receive while A is waiting.

```lisp
(ssh:with-connection (client "my_host")
  (let ((output *standard-output*)
        (output-lock (bt2:make-lock :name "shell output")))
    (labels ((show-line (name direction text)
               (bt2:with-lock-held (output-lock)
                 (format output "~&[~A ~A] ~A~%" name direction text)
                 (finish-output output)))
             (exchange (shell name delay)
               (loop for number from 1 to 3
                     for command = (format nil
                                           "sleep ~D; printf '%s\\n' 'reply ~D'"
                                           delay number)
                     do (show-line name "send" command)
                        (ssh:shell-write-line shell command)
                        (multiple-value-bind (line status)
                            (ssh:shell-read-line shell :error-p nil)
                          (unless (eq status :found)
                            (error "Shell ~A stopped: ~A (~S)"
                                   name status line))
                          (show-line name "recv" line)))))
      (let* ((shell-a
               (bt2:make-thread
                (lambda ()
                  (handler-case
                      (ssh:with-open-shell (shell client :pty nil)
                        (exchange shell "A" 2))
                    (error (condition) condition)))
                :name "shell A"))
             (shell-b
               (bt2:make-thread
                (lambda ()
                  (handler-case
                      (ssh:with-open-shell (shell client :pty nil)
                        (exchange shell "B" 1))
                    (error (condition) condition)))
                :name "shell B"))
             ;; Keep the shared connection open until both shells have finished.
             (results (mapcar #'bt2:join-thread (list shell-a shell-b))))
        (dolist (result results)
          (when (typep result 'condition)
            (error result)))))))
```

The `send` and `recv` labels show each shell's progress; their order can vary.
The commands assume a POSIX shell with `sleep` and `printf`, and produce one
stdout line per command. The output lock keeps local log lines intact and is
never held during SSH reads or writes. Both threads are joined before the
shared connection closes; any worker error is re-signaled afterward.

A shell or subsystem stream also permits one blocking reader and one writer
at the same time; operations in the same direction are serialized.

## Connection options

### Destination syntax and precedence

`ssh:connect` and `ssh:with-connection` accept hostnames, IP addresses, SSH config
aliases, `user@host`, and `ssh://[user@]host[:port]`. URI IPv6 addresses require
brackets, for example `"ssh://alice@[::1]:2222"`; bare `"::1"` is also accepted.
Use the URI form for a port in the destination: `host:port` and
`user@host:port` are unsupported.

Configuration is resolved in this order:

1. Explicit keyword arguments.
2. Username and port from the destination string.
3. SSH config values, looked up using the destination's hostname or alias.
4. Defaults: the local username and port 22.

For example, given:

```ssh-config
Host example.com
     HostName 111.222.0.1
     User root
     IdentityFile ~/.ssh/id_rsa
     Port 9000
```

```lisp
(ssh:cmd "alice@example.com" "whoami"
       :username "bob"
       :identity "~/.ssh/id_ed25519")
```

The username is `bob` because the keyword overrides `alice`, which overrides the
configured `root`. The explicit identity overrides `IdentityFile`.

URI usernames support UTF-8 percent escapes; `+` decodes to a space
(use `%2B` for a literal plus). Optional `;connection-parameters` after the
username are ignored, including fingerprints; they do not affect host-key
checking. Supply passwords separately with `:password`.
An empty trailing slash is accepted. Nonempty paths, queries, fragments, empty
hosts/users, and invalid ports are rejected before config lookup or networking.
Ports must be decimal numbers in 1–65535.

### SSH config support

The default config path is `~/.ssh/config`. Change
`ssh:*default-config-path*` globally or pass `:config-path` per connection.

Supported directives are `HostName`, `Port`, `User`, `IdentityFile`,
`StrictHostKeyChecking`, `UserKnownHostsFile`, and `RekeyLimit`.
Other directives are silently ignored. In particular, `IdentitiesOnly` has
no effect: supplying `:password` can still enable password authentication.
The first configured `IdentityFile` is used unless `:identity` overrides it.

### Authentication

Public-key authentication supports RSA and Ed25519 OpenSSH new-format private
keys, unencrypted or passphrase-protected:

```lisp
(ssh:with-connection (client "bob@example.com"
                             :identity "~/.ssh/id_ed25519"
                             :passphrase "my passphrase")
  (ssh:run-command client "whoami"))
```

For password authentication, pass `:password`. Passwords travel inside the
encrypted transport. Keyboard-interactive authentication uses
`:keyboard-interactive-callback`, a function of
`(name instruction language-tag prompts)` returning ordered response strings.
`:keyboard-interactive-submethods` accepts `nil`, a comma-separated string,
or a list of strings.

For a terminal UI, use `ssh:make-keyboard-interactive-cli-callback`.
It prints the server's instructions and prompts, escapes terminal controls,
preserves Unicode and newlines, and adds no prompt suffix.
Hidden prompts require an application-supplied `:no-echo-reader`: a function
that accepts an input stream, disables echo while reading, restores the terminal
on exit, and returns the response string. Without it, the helper signals
`ssh:auth-error` before reading a request containing hidden prompts.

For multi-step authentication, `ssh:auth-partial-success` lets a handler continue
with a server-offered method. In this example, the application supplies
`read-password-without-echo` as described above:

```lisp
(handler-bind ((ssh:auth-partial-success
                (lambda (condition)
                  (declare (ignore condition))
                  (invoke-restart 'ssh/auth::continue-authentication
                                  "keyboard-interactive"
                                  (ssh:make-keyboard-interactive-cli-callback
                                   :no-echo-reader #'read-password-without-echo)))))
  (ssh:with-connection (client "bob@example.com" :password "secret")
    (ssh:run-command client "whoami")))
```

### Host-key verification

Host-key checking is strict by default. Set `:known-hosts-path` in `ssh:connect`
to override `UserKnownHostsFile` or the default known-hosts file.

| `:strict-host-checking`       | Unknown key | Changed key            |
|-------------------------------|-------------|------------------------|
| `:yes` / `t` (default policy) | Reject      | Reject                 |
| `:accept-new`                 | Record      | Reject                 |
| `:no` / `nil`                 | Record      | Replace with a warning |

Omitting the option uses SSH config; `StrictHostKeyChecking ask` is treated
as `yes`, since the library has no interactive host-key approval prompt.
Strict rejection signals `ssh:unknown-host-key-error` or
`ssh:host-key-changed-error` without modifying the file.
Matching `@revoked` entries always signal `ssh:host-key-revoked-error`,
under every policy. RSA-SHA2 works with existing OpenSSH `ssh-rsa` pins.

### Compression

Compression is disabled by default. It costs CPU and memory and can reveal
information about secrets through observable compressed sizes. Consider it for
bandwidth-limited transfers of compressible data; already compressed files
usually gain little.

| `:compression` | Behavior                                               |
|----------------|--------------------------------------------------------|
| `:none`        | Default; no compression                                |
| `:zlib`        | Stateful zlib, with OpenSSH delayed-zlib compatibility |
| `:delayed`     | Request RFC 8308 compression after authentication      |

```lisp
(ssh:with-connection (client "bob@example.com" :compression :delayed)
  (ssh:run-command client "uname -a"))
```

If delayed compression cannot be negotiated, the connection continues without
compression.

### Rekeying

Automatic rekeying supports packet, byte, and time triggers.  `RekeyLimit`
supplies byte/time settings; `:rekey-byte-limit` and `:rekey-seconds-limit`
override them with positive integers, `nil` to disable that trigger, or
`:default` for the library default. Omitting them uses config and then
defaults. OpenSSH strict KEX is negotiated when available and resets each
direction's packet sequence after NEWKEYS, including rekeys.

## Compatibility and limitations

### Supported algorithms

| Category                                | Algorithms                                                                                                             |
|-----------------------------------------|------------------------------------------------------------------------------------------------------------------------|
| Key exchange                            | `curve25519-sha256`, `curve25519-sha256@libssh.org`, `diffie-hellman-group14-sha256`                                   |
| Host keys and public-key authentication | `ssh-ed25519`, `rsa-sha2-512`, `rsa-sha2-256`                                                                          |
| Ciphers                                 | `aes128-ctr`, `aes256-ctr`, `aes128-gcm@openssh.com`, `aes256-gcm@openssh.com`, `AEAD_AES_128_GCM`, `AEAD_AES_256_GCM` |
| MACs                                    | `hmac-sha2-256`, `hmac-sha2-512`; GCM uses its authenticated-encryption profile                                        |
| Compression                             | `none`, `zlib`, `zlib@openssh.com`                                                                                     |

RSA client authentication prefers SHA-512, then SHA-256. The `ssh-rsa`
public-key blob format does not imply an SHA-1 signature. For a temporary
legacy-server exception, enable SHA-1 client signatures before connecting:

```lisp
(pushnew :cl-ssh-legacy-rsa-sha1 *features*)
```

Without `server-sig-algs`, the client retries with SHA-1 only if the RSA-SHA2
attempt fails and the server still offers public-key authentication.
After partial success, the client signals `ssh:auth-partial-success` so the
caller can continue with the next authentication factor.
This setting does not enable SHA-1 host-key negotiation. Prefer upgrading the
server.

### Protocol scope

The client implements SSH 2 transport, authentication, and session channels for
the supported algorithms. This does not imply complete coverage of every SSH
RFC. SFTP follows the v3 [file-transfer
draft](https://datatracker.ietf.org/doc/html/draft-spaghetti-sshm-filexfer-00),
with the [OpenSSH
extensions](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL)
described under [file transfers](#file-transfers).

Current limitations:

- No configurable timeouts or deadlines for most blocking network operations,
  including SSH negotiation and authentication, command execution, shell reads,
  SFTP requests, and normal channel/session cleanup. A stalled or unreachable
  server, or one that never sends EOF/CLOSE or a required reply, can leave the
  caller waiting indefinitely until the underlying connection reports failure or
  the operation is interrupted externally. This also applies when a command has
  finished but the server does not complete the channel shutdown.
- No server mode, port/X11 forwarding, or `ssh-agent` support.
- No hostbased authentication, password-change requests, or DNS SSHFP validation.
- No ECDSA/NIST ECDH, Ed448, Curve448, or post-quantum key exchange.
- No shell signal requests or terminal window-size changes.
- SFTP v3 only; no recursive copies, automatic resume, or remote-to-remote copies.

## Development

### Setup and offline tests

```shell
git clone https://github.com/jmeissen/cl-ssh
cd cl-ssh
qlot install
sbcl --disable-debugger --load .qlot/setup.lisp --eval '(asdf:test-system :ssh)' --quit
```

The `ssh/tests` suite uses [Parachute](https://codeberg.org/shinmera/parachute)
and offline fixtures. To run it on ECL:

```shell
qlot exec ecl --eval '(ql:quickload :ssh)' --eval '(asdf:test-system :ssh)' --nodebug -q --eval '(uiop:quit)'
```

Passphrase-protected client-key tests run only on SBCL because Ironclad's
bcrypt-pbkdf is slow on some implementations, including ECL.

### Integration tests

The integration script runs OpenSSH services through Docker Compose on
`127.0.0.1:2222-2228`:

```shell
./scripts/run-integration-tests.sh
```

Set `SSH_TEST_REBUILD=1` to rebuild the image.
For manual runs, configure `SSH_TEST_HOST`, `SSH_TEST_PORT`,
`SSH_TEST_RSA_SHA2_256_PORT`, `SSH_TEST_SSH_RSA_PORT`, `SSH_TEST_KBDINT_PORT`,
`SSH_TEST_USER`, `SSH_TEST_PASSWORD`, and `SSH_TEST_KNOWN_HOSTS`,
then run `asdf:test-system :ssh/integration-tests`.
The optional authentication-banner case uses `SSH_TEST_BANNER_PORT` and
`SSH_TEST_BANNER_TEXT`.

Set `SSH_TEST_SFTP_SERVER` to a local OpenSSH `sftp-server` executable
(e.g. `/usr/libexec/sftp-server` on macOS or `/usr/lib/openssh/sftp-server`
on Linux) to enable the additional SFTP test over stdio.
Check the output for `SKIP:` messages: the aggregate pass/skip count does not
reliably distinguish these optional cases. Live tests check OpenSSH
interoperability; the offline suite also covers malformed protocol data.

### Fuzzing

The `ssh/fuzz` system replays parser inputs for packets, KEX/extensions,
keys/signatures, config, known hosts, SFTP, and zlib. Run:

```shell
bash scripts/run-fuzz.sh replay
bash scripts/run-fuzz.sh verify
bash scripts/run-fuzz.sh coverage
```

Replay uses committed inputs; verify fails on retained faults; coverage reports
SBCL parser-source coverage. Mutation additionally requires Radamsa and runs
each case in a fresh process with time and memory limits:

```shell
SSH_FUZZ_ITERATIONS=100 SSH_FUZZ_COVERAGE_FEEDBACK=1 \
  bash scripts/run-fuzz.sh mutate packet
```

## License and acknowledgements

cl-ssh is distributed under the [MIT license](LICENSE).
The bundled zlib inflater derives from 3bz and the deflater from Salza2;
their provenance and component licenses are retained alongside the
[inflater](src/compression/zlib/inflate/ORIGIN.md) and
[deflater](src/compression/zlib/deflate/ORIGIN.md).

See [CHANGELOG.md](CHANGELOG.md) for release history and migration notes.
