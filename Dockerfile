# syntax=docker/dockerfile:1

# ---- build -------------------------------------------------------------------
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Build arg overrides the VERSION file (used by the release workflow).
ARG VERSION=
RUN V="${VERSION:-$(tr -d '[:space:]' < VERSION)}" \
 && CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X proxydns/internal/app.Version=${V}" \
      -o /out/proxydns ./cmd/proxydns \
 && mkdir -p /out/data

# ---- runtime -----------------------------------------------------------------
# distroless: no shell, no package manager, runs as non-root (65532).
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/proxydns /usr/local/bin/proxydns
COPY --from=build --chown=65532:65532 /out/data /data

ENV PROXYDNS_LISTEN=0.0.0.0:8080 \
    PROXYDNS_DATA_DIR=/data \
    PROXYDNS_KEY_MODE=passphrase

USER 65532:65532
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD ["/usr/local/bin/proxydns", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/proxydns"]
CMD ["serve"]
