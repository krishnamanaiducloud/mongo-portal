# syntax=docker/dockerfile:1.12
#
# MongoDB management portal images.
#
#   --target production  (default)  Chainguard static: the binary, CA bundle,
#                                    tzdata. No shell, no package manager.
#   --target debug                   Same binary plus approved troubleshooting
#                                    tools (busybox, curl, dig, openssl, ss/ip,
#                                    ps, jq, mongosh). No package manager.
#
# Both variants contain the identical compiled application. Base images are
# pinned by digest; update them with Dependabot or `crane digest`.

ARG NODE_IMAGE=cgr.dev/chainguard/node:latest-dev@sha256:8e34ebb063dd6af4232c01466eb3813dc94ff68d06ed624652830427e032d64b
ARG GO_IMAGE=cgr.dev/chainguard/go:latest@sha256:df7855cc0c48551eda61a00688daab16030dea2992627270d363eb8500857050
ARG WOLFI_IMAGE=cgr.dev/chainguard/wolfi-base:latest@sha256:81211e15a86ea1d5357f284482af45730c51de45eaf10ad9ce205d6bfc2df323
ARG STATIC_IMAGE=cgr.dev/chainguard/static:latest@sha256:17367e4d3ae2b46c3290858e483fac09be085c92b372360fe3bf6a6150848fde

# ---------------------------------------------------------------- frontend
FROM --platform=$BUILDPLATFORM ${NODE_IMAGE} AS web
# Throwaway build stage: root is only used to write the build directory.
# hadolint ignore=DL3002
USER root
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY web/ ./
RUN npm run build

# ----------------------------------------------------------------- backend
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY cmd ./cmd
COPY internal ./internal
COPY --from=web /web/dist ./internal/webui/dist
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -buildvcs=false \
      -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
      -o /out/mongo-portal ./cmd/portal

# ------------------------------------------------------ debug: tool rootfs
# Packages are installed into an empty root for the *target* architecture,
# so no emulation is needed and apk-tools itself is not part of the image.
# The apk database is kept so scanners and SBOM tools see every package.
FROM --platform=$BUILDPLATFORM ${WOLFI_IMAGE} AS debug-rootfs
ARG TARGETARCH
SHELL ["/bin/sh", "-o", "pipefail", "-c"]
# Wolfi is a rolling distribution: package versions are fixed by the
# digest-pinned base image's repository snapshot at build time and recorded
# in the image's apk database and SBOM. SHELL above enables pipefail
# (busybox sh supports it; hadolint only recognises bash/ash for DL4006).
# hadolint ignore=DL3018,DL4006
RUN set -eu; \
    case "${TARGETARCH}" in amd64) arch=x86_64 ;; arm64) arch=aarch64 ;; *) echo "unsupported ${TARGETARCH}"; exit 1 ;; esac; \
    mkdir -p /rootfs; \
    apk add --root /rootfs --initdb --arch "${arch}" --no-cache --no-scripts \
      --keys-dir /etc/apk/keys --repositories-file /etc/apk/repositories \
      wolfi-baselayout ca-certificates-bundle tzdata glibc libgcc libstdc++ \
      busybox curl bind-tools openssl iproute2 procps jq; \
    # --no-scripts skips busybox's applet-symlink trigger; create the links
    # from the target package's own applet list (paths are relative; /bin and
    # /sbin are relative symlinks to usr/bin in Wolfi).
    bb=usr/bin/busybox; \
    test -x "/rootfs/${bb}"; \
    list=/rootfs/etc/busybox-paths.d/busybox; \
    if [ ! -s "$list" ]; then busybox --list-full > /tmp/applets; list=/tmp/applets; fi; \
    sed 's#^/##' "$list" | while read -r applet; do \
      [ -n "${applet}" ] || continue; \
      if [ ! -e "/rootfs/${applet}" ] && [ ! -L "/rootfs/${applet}" ]; then \
        mkdir -p "/rootfs/$(dirname "${applet}")"; ln -s "/${bb}" "/rootfs/${applet}"; \
      fi; \
    done; \
    test -e /rootfs/bin/sh; \
    rm -rf /rootfs/var/cache/apk /rootfs/etc/apk/cache

# ---------------------------------------------- debug: official mongosh CLI
FROM --platform=$BUILDPLATFORM ${WOLFI_IMAGE} AS mongosh
ARG TARGETARCH
ARG MONGOSH_VERSION=2.13.0
ARG MONGOSH_SHA256_AMD64=b2089e67641a28aa621476c4d62c69f66b9a41484baba24d8a8b1f5f96e92d0b
ARG MONGOSH_SHA256_ARM64=a124ec6680c70ceabc61696bbd110f0da05d7c52524ed402ae9511b5aec7fe32
SHELL ["/bin/sh", "-o", "pipefail", "-c"]
# curl is only used in this throwaway download stage; the artifact is
# verified against the pinned SHA-256 above. pipefail is set via SHELL.
# hadolint ignore=DL3018,DL4006
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) a=x64; sum="${MONGOSH_SHA256_AMD64}" ;; \
      arm64) a=arm64; sum="${MONGOSH_SHA256_ARM64}" ;; \
      *) exit 1 ;; esac; \
    apk add --no-cache curl; \
    curl -fsSL --proto '=https' --tlsv1.2 -o /tmp/mongosh.tgz \
      "https://downloads.mongodb.com/compass/mongosh-${MONGOSH_VERSION}-linux-${a}.tgz"; \
    echo "${sum}  /tmp/mongosh.tgz" | sha256sum -c -; \
    mkdir -p /out /tmp/x; tar -xzf /tmp/mongosh.tgz -C /tmp/x --strip-components=1; \
    install -m 0755 /tmp/x/bin/mongosh /out/mongosh; \
    install -m 0644 /tmp/x/LICENSE-mongosh /out/LICENSE-mongosh; \
    install -m 0644 /tmp/x/.sbom.json /out/mongosh.sbom.json

# -------------------------------------------------------------- debug image
FROM scratch AS debug
ARG VERSION=dev
ARG COMMIT=unknown
COPY --from=debug-rootfs /rootfs/ /
COPY --from=mongosh /out/mongosh /usr/bin/mongosh
COPY --from=mongosh /out/LICENSE-mongosh /usr/share/licenses/mongosh/LICENSE
COPY --from=mongosh /out/mongosh.sbom.json /usr/share/licenses/mongosh/sbom.json
COPY --from=build /out/mongo-portal /usr/bin/mongo-portal
# HOME and TMPDIR point to /tmp, which is an emptyDir in Kubernetes, so the
# image works with an arbitrary UID and a read-only root filesystem.
ENV HOME=/tmp TMPDIR=/tmp SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt PATH=/usr/bin:/bin:/usr/sbin:/sbin
LABEL org.opencontainers.image.title="mongo-portal-debug" \
      org.opencontainers.image.description="MongoDB management portal (diagnostic variant)" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.source="https://github.com/krishnamanaiducloud/mongo-express" \
      org.opencontainers.image.licenses="MIT"
USER 65532:0
EXPOSE 8080 9090
HEALTHCHECK --interval=30s --timeout=5s CMD ["/usr/bin/mongo-portal", "healthcheck"]
ENTRYPOINT ["/usr/bin/mongo-portal"]

# --------------------------------------------------------- production image
FROM ${STATIC_IMAGE} AS production
ARG VERSION=dev
ARG COMMIT=unknown
COPY --from=build /out/mongo-portal /usr/bin/mongo-portal
ENV HOME=/tmp TMPDIR=/tmp
LABEL org.opencontainers.image.title="mongo-portal" \
      org.opencontainers.image.description="MongoDB management portal" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.source="https://github.com/krishnamanaiducloud/mongo-express" \
      org.opencontainers.image.licenses="MIT"
USER 65532:0
EXPOSE 8080 9090
HEALTHCHECK --interval=30s --timeout=5s CMD ["/usr/bin/mongo-portal", "healthcheck"]
ENTRYPOINT ["/usr/bin/mongo-portal"]
