# Build environment for the Linux desktop binary (Wails needs CGO + WebKitGTK headers).
FROM golang:1.26-bookworm
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential pkg-config libgtk-3-dev libwebkit2gtk-4.1-dev \
 && rm -rf /var/lib/apt/lists/*
