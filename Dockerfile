# Build the firewall-controller binary
FROM golang:1.19 as builder

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

# Build
RUN make test all

# Final Image
FROM debian:10
WORKDIR /
COPY --from=builder /workspace/bin/firewall-controller .
RUN apt update \
 && apt install -y --no-install-recommends nftables
ENTRYPOINT ["/firewall-controller"]
