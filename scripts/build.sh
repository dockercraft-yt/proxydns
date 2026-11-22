#!/bin/sh
# Builds everything inside Docker – no local Go installation required.
#
#   scripts/build.sh test      run vet + tests
#   scripts/build.sh server    headless server binaries (Linux + Windows)  -> dist/
#   scripts/build.sh desktop   desktop window binaries (Linux + Windows)   -> dist/
#   scripts/build.sh docker    Docker image proxydns:latest
#   scripts/build.sh all       everything above
set -eu

cd "$(dirname "$0")/.."
VERSION="${VERSION:-$(tr -d "[:space:]" < VERSION)}"
LDFLAGS="-s -w -X proxydns/internal/app.Version=${VERSION}"
GO_IMAGE="golang:1.26-alpine"
DESKTOP_IMAGE="proxydns-desktop-builder"

# Go module/build caches in named volumes speed up repeated builds.
docker volume create proxydns-gomod >/dev/null
docker volume create proxydns-gocache >/dev/null
docker run --rm -v proxydns-gomod:/a -v proxydns-gocache:/b alpine chown -R "$(id -u):$(id -g)" /a /b

run() { # run <image> <command>
  docker run --rm \
    -v "$PWD":/src -w /src \
    -v proxydns-gomod:/gopath -e GOPATH=/gopath \
    -v proxydns-gocache:/gocache -e GOCACHE=/gocache \
    -e HOME=/tmp -e GOFLAGS=-buildvcs=false \
    -u "$(id -u):$(id -g)" \
    "$1" sh -c "$2"
}

do_test() {
  run "$GO_IMAGE" 'go vet ./... && go test -count=1 ./...'
}

do_server() {
  mkdir -p dist
  run "$GO_IMAGE" "
    CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags '$LDFLAGS' -o dist/proxydns-linux-amd64 ./cmd/proxydns &&
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags '$LDFLAGS' -o dist/proxydns-windows-amd64.exe ./cmd/proxydns"
}

do_desktop() {
  mkdir -p dist
  docker build -q -t "$DESKTOP_IMAGE" -f build/desktop-linux.Dockerfile build >/dev/null
  # Linux: CGO + WebKitGTK 4.1
  run "$DESKTOP_IMAGE" "
    CGO_ENABLED=1 go build -tags desktop,production,webkit2_41 -trimpath -ldflags '$LDFLAGS' -o dist/proxydns-desktop-linux-amd64 ./cmd/proxydns-desktop"
  # Windows: Wails uses WebView2 without CGO, so it cross-compiles directly.
  run "$GO_IMAGE" "
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -tags desktop,production -trimpath -ldflags '$LDFLAGS -H windowsgui' -o dist/proxydns-desktop-windows-amd64.exe ./cmd/proxydns-desktop"
}

do_docker() {
  docker build --build-arg VERSION="$VERSION" -t proxydns:latest .
}

case "${1:-all}" in
  test) do_test ;;
  server) do_server ;;
  desktop) do_desktop ;;
  docker) do_docker ;;
  all) do_test; do_server; do_desktop; do_docker ;;
  *) echo "usage: $0 [test|server|desktop|docker|all]" >&2; exit 2 ;;
esac
ls -la dist 2>/dev/null || true
