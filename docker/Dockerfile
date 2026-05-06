# Multi-stage build: static Linux binary for the lab (no cgo; eBPF not included).
FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ghostcatcher ./cmd/agent

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
	&& rm -rf /var/lib/apt/lists/*
COPY --from=build /out/ghostcatcher /usr/local/bin/ghostcatcher
RUN install -d -m 0755 /var/lib/ghostcatcher /etc/ghostcatcher
# Default: single scan; override in compose for long-running
ENTRYPOINT ["/usr/local/bin/ghostcatcher"]
CMD ["run", "-config", "/etc/ghostcatcher/lab.config.yaml", "-once"]
