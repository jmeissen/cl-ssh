# 3bz origin and attribution

This zlib/DEFLATE inflater is derived from 3bz, written by Bart Botta.

- Upstream project: <https://github.com/3b/3bz>
- Upstream revision: `a7769aefc6f5a20d20dc95cb91911ebe2cdb8aad`
- Upstream author: Bart Botta (`00003b at gmail.com`)
- Upstream license declaration: MIT

The pinned upstream `3bz.asd` declares MIT and credits Bart Botta; its source
tree has no separate license file. `LICENSE.txt` supplies the MIT text and
attribution for this bundled copy. The project-level `LICENSE` does not replace
this component's attribution.

The code was copied into cl-ssh so the SSH decompression path does not depend
on the external 3bz system. Stream, gzip, CFFI, Babel, and convenience-file
interfaces were removed. The retained vector-backed zlib/DEFLATE core was
organized under `ssh/compression/zlib/inflate`, and wrapped in the stateful
`make-inflater` / `inflate-chunk` API used by the SSH transport.

Regression fixtures and their tests were adapted from 3bz's portable tests.
