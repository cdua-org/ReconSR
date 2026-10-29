FROM golang:1.27.3-alpine3.24@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS go-builder

WORKDIR /build

ARG VERSION=dev

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY modules/ ./modules/
COPY schema/ ./schema/

RUN mkdir -p /out/etc/ssl/certs /out/usr/local/bin /out/configs /out/storage /out/data /out/lang /out/reports /out/logs && \
    chmod 0755 /out/etc /out/etc/ssl /out/etc/ssl/certs && \
    chmod 0700 /out/configs /out/storage /out/data /out/lang /out/reports /out/logs && \
    cp /etc/ssl/certs/ca-certificates.crt /out/etc/ssl/certs/ca-certificates.crt && \
    chmod 0444 /out/etc/ssl/certs/ca-certificates.crt && \
    CGO_ENABLED=0 go build -ldflags="-s -w -X 'cdua-org/ReconSR/internal/cli.AppVersion=${VERSION}'" -trimpath -o /out/usr/local/bin/ReconSR ./cmd/ReconSR-cli

FROM scratch AS app

COPY --from=go-builder /out/etc /etc
COPY --from=go-builder /out/configs /configs
COPY --from=go-builder /out/storage /storage
COPY --from=go-builder /out/data /data
COPY --from=go-builder /out/lang /lang
COPY --from=go-builder /out/reports /reports
COPY --from=go-builder /out/logs /logs
COPY --from=go-builder --chmod=0555 /out/usr/local/bin/ReconSR /usr/local/bin/ReconSR

ENV RECONSR_LOG_DIR=true

ENTRYPOINT ["/usr/local/bin/ReconSR"]
