FROM rust:latest AS builder

WORKDIR /tss-wasm
COPY ./ .

## TODO: install wasm-pack

## TODO: compile sm server


FROM debian:buster-slim

# Import from builder.

WORKDIR /tss-wasm

# Copy our build
COPY --from=builder /tss-wasm/target/release/examples/gg18_sm_manager ./
COPY --from=builder /tss-wasm/Rocket.toml ./

CMD ["/tss-wasm/gg18_sm_manager"]
