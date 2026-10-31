# Feynos Fit friends & challenges server
# Build:  docker compose up -d --build
# Published as ghcr.io/feynos-lin/feynosfit-server (see .github/workflows/server.yml).
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build
ARG TARGETOS=linux TARGETARCH=amd64
WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w" -o /out/feynos-server . \
 && mkdir -p /out/data

# Tiny image: just the binary, no shell, runs as an unprivileged user.
FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.source="https://github.com/Feynos-Lin/Feynosfit" \
      org.opencontainers.image.title="Feynos Fit server" \
      org.opencontainers.image.description="Self-hosted friends, step challenges and fast-food search for the Feynos Fit app" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /out/feynos-server /feynos-server
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
ENV DATA_DIR=/data LISTEN_ADDR=:8095
VOLUME /data
EXPOSE 8095 8097
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/feynos-server", "healthcheck"]
ENTRYPOINT ["/feynos-server"]
CMD ["serve"]
