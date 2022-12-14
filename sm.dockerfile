FROM rust:latest AS builder

WORKDIR /tss-wasm
COPY ./ .

RUN apt-get update \
    && apt-get install -y --no-install-recommends libssl-dev libc6-dev 

## install wasm-pack
RUN curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

## compile sm server
RUN cargo build --examples --release

FROM debian:buster-slim
# Import from builder.

WORKDIR /tss-wasm

# Copy our build
ARG BUILDARCH
COPY --from=builder /tss-wasm/target/release/examples/gg18_sm_manager ./
COPY --from=builder /tss-wasm/Rocket.toml ./
COPY --from=builder /usr/lib/$BUILDARCH-linux-gnu/libssl.so.1.1 /usr/lib/$BUILDARCH-linux-gnu/
COPY --from=builder /usr/lib/$BUILDARCH-linux-gnu/libcrypto.so.1.1 /usr/lib/$BUILDARCH-linux-gnu/

EXPOSE 8000:8000
CMD ["/tss-wasm/gg18_sm_manager"]

