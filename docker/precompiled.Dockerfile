# syntax=docker/dockerfile:1.7
# Runs natively inside the requested platform (including Buildx emulation).
ARG BUILD_BASE=hexpm/elixir:1.20.0-erlang-27.3.4.11-alpine-3.21.7@sha256:fdc742374710541224a0d520d81fcd8e9a50828dccffe4cbd2638b871f41ab7f
FROM ${BUILD_BASE} AS build
ARG BUILD_BASE
ARG TARGETARCH
ARG SOURCE_REVISION=unknown
ARG PARANO1D_REVISION
ARG LIBOQS_REVISION
ENV MIX_ENV=prod     CHAIN_NIFS_MODE=source     RUSTUP_HOME=/opt/rustup     CARGO_HOME=/opt/cargo     PATH=/opt/cargo/bin:${PATH}     RUSTFLAGS="-C target-feature=-crt-static"     ERL_FLAGS="+S 2:2"
RUN apk add --no-cache build-base cmake linux-headers pkgconf       curl ca-certificates git python3     && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup.sh     && sh /tmp/rustup.sh -y --profile minimal --default-toolchain none     && rustup toolchain install 1.96.0 --profile minimal --no-self-update     && rustup default 1.96.0     && mix local.hex --force     && mix local.rebar --force
WORKDIR /src
COPY . .
# No wrapper: source compilation does not require Git metadata or oracle tools.
RUN set -eu; for project in parano1d tensorcash blocknet; do       (cd nifs/"$project" && mix deps.get --only prod --check-locked && mix compile);     done
RUN <<'SHELL'
set -eu
case "$TARGETARCH" in
  amd64) target=x86_64-unknown-linux-musl ;;
  arm64) target=aarch64-unknown-linux-musl ;;
  *) echo "Unsupported architecture: $TARGETARCH" >&2; exit 2 ;;
esac
export target SOURCE_REVISION BUILD_BASE PARANO1D_REVISION LIBOQS_REVISION
python3 - <<'PY'
import hashlib, json, os, pathlib, shutil, subprocess
for project in ("parano1d", "tensorcash", "blocknet"):
    app = project + "_nif"
    source = pathlib.Path("nifs") / project / "priv/native" / (app + ".so")
    destination = pathlib.Path("/export/nifs") / project / "priv/precompiled" / os.environ["target"]
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination / source.name)
    manifest = {
        "schema_version": 1, "project": app, "target": os.environ["target"],
        "otp_major": 27, "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "source_revision": os.environ["SOURCE_REVISION"],
        "build_base": os.environ["BUILD_BASE"],
        "rust_version": subprocess.check_output(["rustc", "--version"], text=True).strip(),
        "rustflags": os.environ["RUSTFLAGS"],
        "upstream_pins": {"parano1d": os.environ["PARANO1D_REVISION"],
                          "liboqs": os.environ["LIBOQS_REVISION"]},
    }
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
PY
SHELL
# Binary distribution only: no BEAM files, source, compiler or downloaded caches.
FROM scratch AS artifacts
COPY --from=build /export/ /
