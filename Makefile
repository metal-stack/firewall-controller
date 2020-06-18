.ONESHELL:
SHA := $(shell git rev-parse --short=8 HEAD)
GITVERSION := $(shell git describe --long --all)
BUILDDATE := $(shell GO111MODULE=off go run ${COMMONDIR}/time.go)
VERSION := $(or ${VERSION},$(shell git describe --tags --exact-match 2> /dev/null || git symbolic-ref -q --short HEAD || git rev-parse --short HEAD))

# Image URL to use all building/pushing image targets
DOCKER_TAG := $(or ${GITHUB_TAG_NAME}, latest)
DOCKER_IMG ?= metalstack/firewall-controller:${DOCKER_TAG}
# Produce CRDs that work back to Kubernetes 1.11 (no version conversion)
CRD_OPTIONS ?= "crd:trivialVersions=true"

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

all: firewall-controller

# Run tests
test: generate fmt vet manifests
	go test ./... -short -coverprofile cover.out

test-all: generate fmt vet manifests
	go test ./... -v -coverprofile cover.out

test-integration: generate fmt vet manifests
	go test ./... -v Integration

# Build firewall-controller binary
firewall-controller: statik generate fmt vet test
	go build \
		-tags netgo \
		-trimpath \
		-ldflags \
			"-X 'github.com/metal-stack/v.Version=$(VERSION)' \
			-X 'github.com/metal-stack/v.Revision=$(GITVERSION)' \
			-X 'github.com/metal-stack/v.GitSHA1=$(SHA)' \
			-X 'github.com/metal-stack/v.BuildDate=$(BUILDDATE)'" \
		-o bin/firewall-controller main.go
	strip bin/firewall-controller

# Run against the configured Kubernetes cluster in ~/.kube/config
run: generate fmt vet manifests
	go run ./main.go

# Install CRDs into a cluster
install: manifests
	kustomize build config/crd | kubectl apply -f -

# Uninstall CRDs from a cluster
uninstall: manifests
	kustomize build config/crd | kubectl delete -f -

# Deploy controller in the configured Kubernetes cluster in ~/.kube/config
deploy: manifests
	cd config/manager && kustomize edit set image controller=${DOCKER_IMG}
	kustomize build config/default | kubectl apply -f -

# Generate manifests e.g. CRD, RBAC etc.
manifests: controller-gen
	$(CONTROLLER_GEN) $(CRD_OPTIONS) rbac:roleName=manager-role webhook paths="./..." output:crd:artifacts:config=config/crd/bases

# Run go fmt against code
fmt:
	go fmt ./...

# Run go vet against code
vet:
	go vet ./...

# Generate code
generate: controller-gen statik manifests
	$(STATIK) -src=pkg/nftables -include='*.tpl' -dest=pkg/nftables -ns tpl
	$(STATIK) -src=config/crd/bases -ns crd
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

# Build the docker image
docker-build:
	docker build . -t ${DOCKER_IMG}

# Push the docker image
docker-push:
	docker push ${DOCKER_IMG}

# find or download controller-gen
# download controller-gen if necessary
.PHONY: controller-gen
controller-gen:
ifeq (, $(shell which controller-gen))
	@{ \
	set -e ;\
	CONTROLLER_GEN_TMP_DIR=$$(mktemp -d) ;\
	cd $$CONTROLLER_GEN_TMP_DIR ;\
	go mod init tmp ;\
	go get sigs.k8s.io/controller-tools/cmd/controller-gen@v0.3.0 ;\
	rm -rf $$CONTROLLER_GEN_TMP_DIR ;\
	}
CONTROLLER_GEN=$(GOBIN)/controller-gen
else
CONTROLLER_GEN=$(shell which controller-gen)
endif

# find or download statik
.PHONY: statik
statik:
ifeq (, $(shell which statik))
	@{ \
	set -e ;\
	STATIK_TMP_DIR=$$(mktemp -d) ;\
	cd $$STATIK_TMP_DIR ;\
	go mod init tmp ;\
	go get github.com/rakyll/statik ;\
	rm -rf $$STATIK_TMP_DIR ;\
	}
STATIK=$(GOBIN)/statik
else
STATIK=$(shell which statik)
endif
