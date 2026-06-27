# ── Stage 1: build ────────────────────────────────────────────────────────────
# Use the same toolchain declared in go.mod (go 1.24 + toolchain go1.25.x).
# golang:1.25 gives us the exact toolchain without pinning a patch digest here;
# the binary is fully reproducible because CGO_ENABLED=0 produces a static binary.
FROM golang:1.25 AS builder

WORKDIR /src

# Copy go.mod first for layer caching. There is no go.sum because the module
# has zero third-party runtime dependencies (all stdlib). go mod download is a
# no-op but keeps the COPY go.mod layer separate from the source copy.
COPY go.mod ./
RUN go mod download

# Copy the rest of the source and build a static binary.
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /modelvet \
    ./cmd/modelvet

# ── Stage 2: minimal runtime ──────────────────────────────────────────────────
# gcr.io/distroless/static-debian12 has no shell, no package manager, and no
# libc — the smallest possible attack surface for a static Go binary.
FROM gcr.io/distroless/static-debian12:nonroot

# Copy the compiled binary from the builder stage.
COPY --from=builder /modelvet /modelvet

# The distroless:nonroot image already runs as UID 65532 (nonroot) by default.
# We declare it explicitly so `docker inspect` and security scanners report it.
USER nonroot:nonroot

# Default entrypoint. Usage:
#   docker run --rm -v /path/to/models:/data <image> scan /data
#
# Mount the directory containing your model files at /data.
# Example scanning a single file:
#   docker run --rm -v $(pwd)/model.pt:/data/model.pt:ro <image> scan /data/model.pt
ENTRYPOINT ["/modelvet"]
