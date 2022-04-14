# Build the firewall-controller binary
FROM golang:1.19 as builder

ENV KUBEBUILDER_DOWNLOAD_URL=https://github.com/kubernetes-sigs/kubebuilder/releases/download
ENV KUBEBUILDER_VER=v3.3.0
RUN set -ex \
 && mkdir -p /usr/local/bin \
 && curl -L ${KUBEBUILDER_DOWNLOAD_URL}/v${KUBEBUILDER_VER}/kubebuilder_linux_amd64 -o /usr/local/bin/kubebuilder \
 && chmod +x /usr/local/bin/kubebuilder

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY .git/ .git/
COPY Makefile Makefile
COPY main.go main.go
COPY api/ api/
COPY controllers/ controllers/
COPY config config/
COPY pkg/ pkg/
COPY hack/ hack/

# Install kubenuilder
ENV KUBEBUILDER_ASSETS=/usr/local/bin
RUN make kubebuilder

# Build
RUN make test all

# Final Image
FROM debian:10
WORKDIR /
COPY --from=builder /workspace/bin/firewall-controller .
RUN apt update \
 && apt install -y --no-install-recommends nftables
ENTRYPOINT ["/firewall-controller"]
