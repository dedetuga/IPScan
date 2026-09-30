# Canonical build: cross-compile the Go backend, then package the .eap with the
# official Axis ACAP Native SDK so the produced package matches Axis' own format.
#
# Build (from the project root), e.g. for an ARTPEC-8 camera (aarch64):
#
#   DOCKER_BUILDKIT=1 docker build \
#     --build-arg GOARCH=arm64 --build-arg SDK_ARCH=aarch64 \
#     -o type=local,dest=./out .
#
# For ARTPEC-7 / older (armv7hf):
#
#   DOCKER_BUILDKIT=1 docker build \
#     --build-arg GOARCH=arm --build-arg GOARM=7 --build-arg SDK_ARCH=armv7hf \
#     -o type=local,dest=./out .
#
# The resulting *.eap is written to ./out/.

# ---------- stage 1: build the Go binary (stdlib only, offline) --------
FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY app/ ./
ARG GOARCH=arm64
ARG GOARM=
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${GOARCH} GOARM=${GOARM} \
    go build -trimpath -ldflags="-s -w -X main.flavor=modern" -o ipscan .

# ---------- stage 2: package with the Axis Native SDK -------------------------
ARG SDK_ARCH=aarch64
ARG SDK_VERSION=12.5.0
ARG UBUNTU=24.04
FROM axisecp/acap-native-sdk:${SDK_VERSION}-${SDK_ARCH}-ubuntu${UBUNTU} AS pack
WORKDIR /opt/app
COPY app/manifest.json ./manifest.json
COPY app/Makefile      ./Makefile
COPY app/LICENSE       ./LICENSE
COPY app/html          ./html
COPY --from=build /src/ipscan ./ipscan
# acap-build reads manifest.json, runs the (no-op) Makefile, and runs eap-create.
RUN . /opt/axis/acapsdk/environment-setup-* && acap-build .

# ---------- stage 3: export just the .eap -------------------------------------
FROM scratch AS export
COPY --from=pack /opt/app/*.eap /
