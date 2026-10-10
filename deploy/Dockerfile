FROM node:26.10.0-bookworm-slim@sha256:662933cf47f013bc8e4beb31a6116448427a82057ba7c42c97e4c5ba766504c2 AS ui
WORKDIR /build/console
COPY console/package*.json ./
RUN npm ci --ignore-scripts
COPY console/ ./
RUN npm test && npm run build
FROM golang:1.27.1-bookworm@sha256:8d48e12ec56735e9358640898b9d9b9fcca110612ed8a5567438c0a1baa24e66 AS api
WORKDIR /build/server
COPY server/go.mod server/go.sum ./
RUN go mod download
COPY server/ ./
RUN go test ./... && CGO_ENABLED=0 go build -trimpath -o /milvago ./cmd/milvago
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
USER 65532:65532
COPY --from=api /milvago /milvago
COPY --from=ui /build/console/dist /console
ENV STATIC_DIR=/console
EXPOSE 4020
ENTRYPOINT ["/milvago"]
