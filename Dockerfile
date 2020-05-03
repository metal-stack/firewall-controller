# Build the firewall-controller binary
FROM golang:1.14 as builder

ENV KUBEBUILDER_DOWNLOAD_URL=https://github.com/kubernetes-sigs/kubebuilder/releases/download
ENV KUBEBUILDER_VER=2.3.1
ENV KUBEBUILDER_ASSETS=/usr/local/bin
RUN set -ex \
 && mkdir -p /tmp/kubebuilder /usr/local/bin \
 && curl -L ${KUBEBUILDER_DOWNLOAD_URL}/v${KUBEBUILDER_VER}/kubebuilder_${KUBEBUILDER_VER}_linux_amd64.tar.gz -o /tmp/kubebuilder-${KUBEBUILDER_VER}-linux-amd64.tar.gz \
 && tar xzvf /tmp/kubebuilder-${KUBEBUILDER_VER}-linux-amd64.tar.gz -C /tmp/kubebuilder --strip-components=1 \
 && mv /tmp/kubebuilder/bin/* ${KUBEBUILDER_ASSETS}/

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
COPY pkg/ pkg/
COPY statik/ statik/
COPY hack/ hack/

# Build
RUN make test all

# Use distroless as minimal base image to package the firewall-controller binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/bin/firewall-controller .
USER nonroot:nonroot

ENTRYPOINT ["/firewall-controller"]
