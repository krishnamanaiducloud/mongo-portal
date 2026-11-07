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

ARG NODE_IMAGE=cgr.dev/chainguard/node:latest-dev@sha256:f6d993b56d7ed81f72deaf7409c79b36b1066582b93bf4fdb8e51f0a31243244
ARG GO_IMAGE=cgr.dev/chainguard/go:latest-dev@sha256:ed70318f7b4f2e4a82e1dbc363f7a13be3a5805081f86ed9d1ec02d2694c222f
ARG WOLFI_IMAGE=cgr.dev/chainguard/wolfi-base:latest@sha256:8509ee4351a2e501b7f98201f2e2642396e82020c61a589cacdcfe74b9de46c1
ARG STATIC_IMAGE=cgr.dev/chainguard/static:latest@sha256:fc42af33e643f20d08baf03cddcc1c02ba57052dfb02edb0d79f3fc47bcea8d9

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
    # Packages come from the public Wolfi repository (the base image trusts its key). On some
    # networks a long apk download session stalls, so the signed index and each package are
    # fetched separately with retries (curl, build stage only), then installed offline: apk
    # still verifies the index signature and every package checksum.
    repo=https://packages.wolfi.dev/os; \
    printf '%s\n' "${repo}" > /tmp/repositories; \
    for attempt in 1 2 3 4 5; do \
      if apk add --no-cache --repositories-file /tmp/repositories curl; then break; fi; \
      [ "${attempt}" -lt 5 ] || exit 1; echo "apk add curl failed (attempt ${attempt}), retrying" >&2; sleep 5; \
    done; \
    get() { curl -fsSL --proto '=https' --retry 5 --retry-all-errors --connect-timeout 20 --max-time 300 -o "$2" "$1"; }; \
    mkdir -p "/tmp/repo/${arch}" /tmp/sim /rootfs; \
    get "${repo}/${arch}/APKINDEX.tar.gz" "/tmp/repo/${arch}/APKINDEX.tar.gz"; \
    pkgs="wolfi-baselayout ca-certificates-bundle tzdata glibc libgcc libstdc++ busybox curl bind-tools openssl iproute2 procps jq"; \
    apk add --root /tmp/sim --initdb --arch "${arch}" --keys-dir /etc/apk/keys --repository /tmp/repo \
      --no-network --no-progress; \
    # shellcheck disable=SC2086
    apk add --root /tmp/sim --arch "${arch}" --keys-dir /etc/apk/keys --repository /tmp/repo \
      --no-network --simulate --no-progress ${pkgs} \
      | sed -n 's/^([^)]*) Installing \([^ ]*\) (\([^)]*\)).*/\1-\2.apk/p' > /tmp/files; \
    test -s /tmp/files; \
    while read -r f; do get "${repo}/${arch}/${f}" "/tmp/repo/${arch}/${f}"; done < /tmp/files; \
    # shellcheck disable=SC2086
    apk add --root /rootfs --initdb --arch "${arch}" --no-network --no-cache --no-scripts \
      --keys-dir /etc/apk/keys --repository /tmp/repo ${pkgs}; \
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
ARG MONGOSH_VERSION=2.14.1
ARG MONGOSH_SHA256_AMD64=8d24940ebe3675959b518fd41ea16b4e2182d6a75c09777db09cfa64e18834a1
ARG MONGOSH_SHA256_ARM64=cd7f1ae986baa400b021a2c0688aa3b64d6afcc3f7ab07833417a049e0cbf98b
SHELL ["/bin/sh", "-o", "pipefail", "-c"]
# curl is only used in this throwaway download stage; the artifact is
# verified against the pinned SHA-256 above. pipefail is set via SHELL.
# hadolint ignore=DL3018,DL4006
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) a=x64; sum="${MONGOSH_SHA256_AMD64}" ;; \
      arm64) a=arm64; sum="${MONGOSH_SHA256_ARM64}" ;; \
      *) exit 1 ;; esac; \
    printf '%s\n' https://packages.wolfi.dev/os > /tmp/repositories; \
    for attempt in 1 2 3 4 5; do \
      if apk add --no-cache --repositories-file /tmp/repositories curl; then break; fi; \
      [ "${attempt}" -lt 5 ] || exit 1; echo "apk add failed (attempt ${attempt}), retrying" >&2; sleep 5; \
    done; \
    curl -fsSL --proto '=https' --tlsv1.2 --retry 5 --retry-all-errors --connect-timeout 20 -o /tmp/mongosh.tgz \
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
      org.opencontainers.image.source="https://github.com/krishnamanaiducloud/mongo-portal" \
      org.opencontainers.image.url="https://github.com/krishnamanaiducloud/mongo-portal" \
      org.opencontainers.image.vendor="Mohankrishna" \
      org.opencontainers.image.authors="Mohankrishna"
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
      org.opencontainers.image.source="https://github.com/krishnamanaiducloud/mongo-portal" \
      org.opencontainers.image.url="https://github.com/krishnamanaiducloud/mongo-portal" \
      org.opencontainers.image.vendor="Mohankrishna" \
      org.opencontainers.image.authors="Mohankrishna"
USER 65532:0
EXPOSE 8080 9090
HEALTHCHECK --interval=30s --timeout=5s CMD ["/usr/bin/mongo-portal", "healthcheck"]
ENTRYPOINT ["/usr/bin/mongo-portal"]
