# Venezia Alpine precompiled NIFs

The binary build uses Venezia's exact builder image:
hexpm/elixir:1.20.0-erlang-27.3.4.11-alpine-3.21.7, OTP 27, Rust 1.96.0,
production Mix compilation, CMake, and RUSTFLAGS=-C target-feature=-crt-static.
The base is pinned to multi-platform manifest digest
sha256:fdc742374710541224a0d520d81fcd8e9a50828dccffe4cbd2638b871f41ab7f.
Compilation runs inside the requested platform, optionally under Docker
Buildx emulation. It does not explicitly cross-compile or produce glibc output.

## Generate binaries

Run from this monorepo with Docker Buildx and initialized official submodules:

~~~sh
git submodule update --init --recursive
bin/build-precompiled linux/amd64
bin/build-precompiled linux/arm64
# Or build both sequentially:
bin/build-precompiled all
~~~

Only those two platform names or all are accepted. The CLI requires committed,
clean source inputs, including the official submodules; existing generated
precompiled artifacts are excluded from this check. No in-container Git
verification is needed. Source compilation uses CHAIN_NIFS_MODE=source.

Each execution creates a new .cache/precompiled.XXXXXX staging directory.
Buildx exports a scratch stage containing only six files per platform: three
shared objects and three manifests. After each platform succeeds, the CLI
copies only its known files to the actual projects. It never deletes existing
output, commits files or publishes images. No build runs until invoked.

| Platform | Target directory |
| --- | --- |
| linux/amd64 | x86_64-unknown-linux-musl |
| linux/arm64 | aarch64-unknown-linux-musl |

Each project's layout is:

~~~text
nifs/PROJECT/priv/precompiled/TARGET/PROJECT_nif.so
nifs/PROJECT/priv/precompiled/TARGET/manifest.json
~~~

TensorCash, for example, exports tensorcash_nif.so. No BEAM modules, source,
compiler or caches are exported. Later the consuming Mix release compiles
Elixir wrappers and packages the checked binaries in the application's priv.
Go and Node are unnecessary for binary generation; independent oracle checks
remain separate validation gates.

## Manifest contract

Manifests contain schema_version=1, project (app string, e.g. tensorcash_nif),
target (Rust musl triple), otp_major=27, and sha256 (lowercase hex SHA-256 of
the adjacent shared object). Additional provenance fields are source_revision,
build_base, rust_version (actual rustc --version), rustflags, and upstream_pins
for both official submodules.

Review and commit sources before regenerating binaries. The source revision
records HEAD at invocation; it does not establish bit-for-bit reproducibility.
SHA-256 protects consistency, not authenticity against malicious repository
changes. Review binaries and manifests with their source changes.

The monorepo-root Docker context exclusions must omit all host caches, deps,
native target directories, generated native outputs and Git metadata while
including official submodule source. The CLI never uses Venezia's broader
research workspace as its Docker context.

## Runtime acceptance

Generation alone does not prove runtime compatibility. Validate both platforms
against Venezia's actual Alpine runtime with Rust/Cargo/Go absent, compile
wrappers in precompiled mode, inspect shared-library dependencies, and exercise
real NIF calls. Keep required runtime libraries such as libgcc according to
that inspection. Ubuntu/glibc and macOS artifacts cannot replace musl binaries.

Parano1d production proofs retain upstream CPU requirements: SSE4.1/PCLMULQDQ
on x86-64, or NEON/PMULL on AArch64. No target-cpu=native flag is used. Emulated
checks do not establish production CPU capabilities. Existing protocol,
bounds, mutation and audit checks remain applicable when regenerating output.
