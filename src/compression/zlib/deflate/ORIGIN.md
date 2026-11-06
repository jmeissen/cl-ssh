# Salza2 provenance

This directory contains the streaming zlib/DEFLATE encoder core derived from
Salza2 by Zachary Beane and contributors.

Source copied from:

- Repository: https://github.com/jmeissen/salza2
- Revision: `497ebeaaa883a0a215d7d5fa22e72532b1b48d21`
- Salza2 system version: 2.1

The code was copied and reduced for cl-ssh's RFC 4253 streaming zlib use. The
package declaration was changed to `ssh/compression/zlib/deflate`. The gzip
wrapper, checksum implementations, stream finalization, reset/reuse support,
Gray-stream adapter, file/data convenience API, and Salza2 test-suite
dependencies are not retained. SSH uses a continuous zlib stream with a
partial flush at each packet boundary and discards the context when it is
replaced.

The Salza2 file boundaries and public protocol were additionally normalized around the SSH packet lifecycle.

The original BSD license is retained in `LICENSE.txt` and in the copied
source headers.
