# Build the container from the verified GitHub Release archive so its CLI and
# bundled dependency licenses are identical to the downloadable release.
FROM --platform=$BUILDPLATFORM alpine:3.23 AS release
RUN apk add --no-cache ca-certificates curl
ARG RELEASE_TAG
ARG TARGETARCH
RUN set -eu; \
    case "$RELEASE_TAG" in v[0-9]*-beta.[0-9]*) ;; *) exit 1 ;; esac; \
    case "$TARGETARCH" in amd64|arm64) ;; *) exit 1 ;; esac; \
    archive="ravel_${RELEASE_TAG}_linux_${TARGETARCH}.tar.gz"; \
    base="https://github.com/Pirikara/Ravel/releases/download/${RELEASE_TAG}"; \
    mkdir -p /release /bundle; \
    cd /release; \
    curl --fail --location --retry 10 --retry-all-errors --retry-delay 2 --output "$archive" "$base/$archive"; \
    curl --fail --location --retry 10 --retry-all-errors --retry-delay 2 --output SHA256SUMS "$base/SHA256SUMS"; \
    awk -v name="$archive" '$2 == name { print }' SHA256SUMS > selected.sum; \
    test "$(wc -l < selected.sum)" -eq 1; \
    sha256sum -c selected.sum; \
    tar -xzf "$archive" --strip-components=1 -C /bundle; \
    test -x /bundle/ravel

FROM alpine:3.23
ARG RELEASE_TAG
LABEL org.opencontainers.image.source="https://github.com/Pirikara/Ravel" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="$RELEASE_TAG"
COPY --from=release /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=release /bundle/ /opt/ravel/
ENV HOME=/tmp
WORKDIR /work
USER 65532:65532
ENTRYPOINT ["/opt/ravel/ravel"]
