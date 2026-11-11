# syntax=docker/dockerfile:1
ARG ELIXIR_IMAGE=hexpm/elixir:1.20.0-erlang-27.3.4.11-alpine-3.21.7@sha256:fdc742374710541224a0d520d81fcd8e9a50828dccffe4cbd2638b871f41ab7f
FROM ${ELIXIR_IMAGE} AS package
ENV MIX_ENV=prod CHAIN_NIFS_MODE=precompiled ERL_FLAGS="+S 2:2"
WORKDIR /src
COPY nifs nifs
COPY docker/runtime-smoke docker/runtime-smoke
COPY nifs/blocknet/mix.lock docker/runtime-smoke/mix.lock
RUN for tool in rustc cargo rustup cmake gcc cc make go node npm; do \
      if command -v "$tool"; then exit 1; fi; \
    done
WORKDIR /src/docker/runtime-smoke
RUN mix local.hex --force && mix deps.get --check-locked \
    && mix compile --warnings-as-errors && mix release

FROM package AS tests
WORKDIR /src
RUN for project in parano1d tensorcash blocknet; do \
      (cd "nifs/$project" && mix deps.get --check-locked \
       && MIX_ENV=test mix test --warnings-as-errors) || exit 1; \
    done

FROM alpine:3.21.7 AS runtime
RUN apk add --no-cache libgcc libstdc++ ncurses-libs openssl ca-certificates
WORKDIR /opt/app
COPY --from=package /src/docker/runtime-smoke/_build/prod/rel/chain_nifs_smoke ./
ENV ERL_FLAGS="+S 2:2"
CMD ["bin/chain_nifs_smoke", "eval", "ChainNifsSmoke.run()"]
