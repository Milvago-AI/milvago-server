FROM rust:1.96.1-trixie@sha256:1f0dbad1df66647807e6952d1db85d0b2bda7606cb2139d82517e4f009967376 AS dlp
WORKDIR /build/dlp-engine
RUN rustup target add wasm32-unknown-unknown
COPY dlp-engine/ ./
RUN cargo test --locked && cargo build --release --locked --target wasm32-unknown-unknown

FROM dlp AS discovery
WORKDIR /build/discovery-engine
COPY discovery-engine/ ./
RUN cargo test --locked && cargo build --release --locked --target wasm32-unknown-unknown

FROM node:26.13.0-trixie-slim@sha256:e4db4c914bf8ad241bd24804fc25d272d89bad97e68cdc8a1414862790a02c39 AS ui
WORKDIR /build/console
RUN node -e 'if (process.versions.node !== "26.13.0") process.exit(1)'
COPY console/package*.json ./
RUN npm ci --ignore-scripts
COPY console/ ./
COPY --from=dlp /build/dlp-engine/target/wasm32-unknown-unknown/release/milvago_dlp_engine.wasm public/dlp_engine.wasm
COPY --from=discovery /build/discovery-engine/target/wasm32-unknown-unknown/release/milvago_discovery_engine.wasm public/discovery_engine.wasm
COPY deploy/theme/milvago/login/resources/js/milvago.js /build/deploy/theme/milvago/login/resources/js/milvago.js
RUN npm test && npm run build
FROM golang:1.27.4-trixie@sha256:b54b2639de8c1bfe538ec5ffc45f29b1932235ac5f6d63c059853646677112d9 AS api
WORKDIR /build/server
COPY server/go.mod server/go.sum ./
RUN go mod download
COPY server/ ./
COPY --from=dlp /build/dlp-engine/target/wasm32-unknown-unknown/release/milvago_dlp_engine.wasm internal/app/dlp_engine.wasm
COPY --from=discovery /build/discovery-engine/target/wasm32-unknown-unknown/release/milvago_discovery_engine.wasm internal/app/discovery_engine.wasm
RUN go test ./... && CGO_ENABLED=0 go build -trimpath -o /milvago ./cmd/milvago
FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
USER 65532:65532
COPY --from=api /milvago /milvago
COPY licenses/ /licenses/
COPY --from=discovery /build/discovery-engine/LICENSE /licenses/discovery-engine-LICENSE
COPY --from=discovery /build/discovery-engine/NOTICE /licenses/discovery-engine-NOTICE
COPY --from=ui /build/console/dist /console
ENV STATIC_DIR=/console
EXPOSE 4020
ENTRYPOINT ["/milvago"]
