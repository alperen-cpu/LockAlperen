# keepass 0.17.0 (patched copy)

Upstream: https://crates.io/crates/keepass/0.17.0 (MIT, see `LICENSE`).

The only change is in `src/compression.rs`: `GZipCompression::decompress` reads
at most `MAX_DECOMPRESSED` (384 MiB) and fails beyond that. Upstream reads the
whole gzip stream into memory, so a small KDBX file with the right password
could inflate to gigabytes and crash the app (gzip bomb). The bound covers the
importer's own limits (64 MiB file, 256 MiB of attachments in total).

When upgrading keepass: check whether upstream bounds decompression; if not,
copy the new version here and apply the same change.

`cargo audit` does not see this crate (it is a path dependency): check new
keepass advisories by hand.
