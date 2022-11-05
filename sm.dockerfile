FROM rust:latest AS builder

WORKDIR /tss-wasm
COPY ./ .

# RUN wget https://www.openssl.org/source/openssl-1.1.1o.tar.gz
# RUN tar -zxvf openssl-1.1.1o.tar.gz
# RUN cd openssl-1.1.1o \
#     && ./config \
#     && make \
#     && make install
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
COPY --from=builder /tss-wasm/target/release/examples/gg18_sm_manager ./
COPY --from=builder /tss-wasm/Rocket.toml ./
COPY --from=builder /usr/lib/aarch64-linux-gnu/libssl.so.1.1 /usr/lib/aarch64-linux-gnu/
COPY --from=builder /usr/lib/aarch64-linux-gnu/libcrypto.so.1.1 /usr/lib/aarch64-linux-gnu/

EXPOSE 8000:8000
CMD ["/tss-wasm/gg18_sm_manager"]

