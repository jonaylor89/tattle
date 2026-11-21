SHA-256 of each release binary, one file per version (`v<version>.sha256`).
`install.sh` only runs a downloaded release whose hash matches the file for the
version in `Cargo.toml`; otherwise it builds from source. Written by the
release workflow (`.github/workflows/release-plz.yml`), which builds and attests
those binaries from the release tag, and merged through a reviewed PR.
