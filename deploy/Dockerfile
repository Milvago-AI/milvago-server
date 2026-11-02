FROM node:26.13.0-trixie-slim@sha256:e4db4c914bf8ad241bd24804fc25d272d89bad97e68cdc8a1414862790a02c39 AS ui
WORKDIR /build/console
COPY console/package*.json ./
RUN npm ci --ignore-scripts
COPY console/ ./
RUN npm test && npm run build
FROM golang:1.27.3-trixie@sha256:c65ecfe613b539ac74c62a4c3b2c27e8f8a6076384c8f27e8a3c0f3be17cc385 AS api
WORKDIR /build/server
COPY server/go.mod server/go.sum ./
RUN go mod download
COPY server/ ./
RUN go test ./... && CGO_ENABLED=0 go build -trimpath -o /milvago ./cmd/milvago
FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
USER 65532:65532
COPY --from=api /milvago /milvago
COPY --from=ui /build/console/dist /console
ENV STATIC_DIR=/console
EXPOSE 4020
ENTRYPOINT ["/milvago"]
