# Fixes for upstream crates

Each patch here is a fix for a crate of another project. A session of
podcrates cannot write outside PodUtils, so the owner sends each one.
Apply a patch at the root of the crate's source with `patch -p1`.

| Patch | Crate | Fix | Entry |
| --- | --- | --- | --- |
| `kcp-0.6.0-wrapping.patch` | `kcp` 0.6.0 | `timediff` wraps; `update_ack` computes in 64 bits and saturates; `peeksize` adds to a `usize`, so `frg` 255 does not overflow | T-526 |
