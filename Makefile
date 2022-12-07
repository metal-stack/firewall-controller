.ONESHELL:
SHA := $(shell git rev-parse --short=8 HEAD)
GITVERSION := $(shell git describe --long --all)
BUILDDATE := $(shell GO111MODULE=off go run ${COMMONDIR}/time.go)
VERSION := $(or ${GITHUB_TAG_NAME},$(shell git describe --tags --exact-match 2> /dev/null || git symbolic-ref -q --short HEAD || git rev-parse --short HEAD))

# Image URL to use all building/pushing image targets
DOCKER_TAG := $(or ${GITHUB_TAG_NAME}, latest)
DOCKER_IMG ?= ghcr.io/metal-stack/firewall-controller:${DOCKER_TAG}
# this version is used to include template from the metal-networker to the firewall-controller
# version should be not that far away from the compile dependency in go.mod
METAL_NETWORKER_VERSION := v0.8.3

# Kubebuilder installation environment variables
KUBEBUILDER_DOWNLOAD_URL := https://github.com/kubernetes-sigs/kubebuilder/releases/download
KUBEBUILDER_VER := 3.3.0
KUBEBUILDER_ASSETS ?= /usr/local/kubebuilder/bin
K8S_VERSION := 1.22.1

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

all: firewall-controller

# Run tests
test: generate fmt vet manifests
	KUBEBUILDER_ASSETS=${KUBEBUILDER_ASSETS} go test ./... -short -coverprofile cover.out

test-all: generate fmt vet manifests kubebuilder
	KUBEBUILDER_ASSETS=${KUBEBUILDER_ASSETS} go test ./... -v -coverprofile cover.out

test-integration: generate fmt vet manifests
	KUBEBUILDER_ASSETS=${KUBEBUILDER_ASSETS} go test ./... -v Integration

test-envtest:
	@if ! which $(SETUP_ENVTEST) > /dev/null; then echo "setup-envtest needs to be installed. you can use setup-envtest target to achieve this."; exit 1; fi
	KUBEBUILDER_ASSETS="$(shell $(SETUP_ENVTEST) use --arch=amd64 --bin-dir $(PWD)/bin -p path)" go test ./... -v -coverprofile cover.out

clean:
	rm -rf bin/* pkg/network/frr.firewall.tpl

# Build firewall-controller binary
firewall-controller: generate fmt vet
	CGO_ENABLED=0 go build \
		-tags netgo \
		-trimpath \
		-ldflags \
			"-X 'github.com/metal-stack/v.Version=$(VERSION)' \
			-X 'github.com/metal-stack/v.Revision=$(GITVERSION)' \
			-X 'github.com/metal-stack/v.GitSHA1=$(SHA)' \
			-X 'github.com/metal-stack/v.BuildDate=$(BUILDDATE)'" \
		-o bin/firewall-controller main.go
	strip bin/firewall-controller
	sha256sum bin/firewall-controller > bin/firewall-controller.sha256

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
manifests: controller-gen fetch-template
	$(CONTROLLER_GEN) crd rbac:roleName=manager-role webhook paths="./..." output:crd:artifacts:config=config/crd/bases

# Fetch firewall template
fetch-template:
	# FIXME: If this is embedded into the networker, why not just use from embedded source?
	wget https://raw.githubusercontent.com/metal-stack/metal-networker/${METAL_NETWORKER_VERSION}/pkg/netconf/tpl/frr.firewall.tpl -O ./pkg/network/frr.firewall.tpl

# Run go fmt against code
fmt:
	go fmt ./...

# Run go vet against code
vet:
	go vet ./...

# Run golangci-lint
lint:
	docker run --rm -v $(PWD):/app -w /app golangci/golangci-lint:v1.44.2 golangci-lint run -v

# Generate code
generate: controller-gen manifests
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

# Build the docker image
docker-build:
	docker build . -t ${DOCKER_IMG}

# Push the docker image
docker-push:
	docker push ${DOCKER_IMG}

kubebuilder:
	set -ex \
 		&& mkdir -p /tmp/kubebuilder ${KUBEBUILDER_ASSETS} \
 		&& curl -L ${KUBEBUILDER_DOWNLOAD_URL}/v${KUBEBUILDER_VER}/kubebuilder_linux_amd64 -o ${KUBEBUILDER_ASSETS}/kubebuilder \
 		&& chmod +x ${KUBEBUILDER_ASSETS}/kubebuilder \
 		&& curl -sSLo /tmp/kubebuilder/envtest-bins.tar.gz "https://go.kubebuilder.io/test-tools/${K8S_VERSION}/linux/amd64" \
 		&& tar -C ${KUBEBUILDER_ASSETS} --strip-components=2 -zvxf /tmp/kubebuilder/envtest-bins.tar.gz

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
	go install sigs.k8s.io/controller-tools/cmd/controller-gen@v0.10.0 ;\
	rm -rf $$CONTROLLER_GEN_TMP_DIR ;\
	}
CONTROLLER_GEN=$(GOBIN)/controller-gen
else
CONTROLLER_GEN=$(shell which controller-gen)
endif

.PHONY: setup-envtest
setup-envtest:
ifeq (, $(shell which setup-envtest))
	@{ \
	set -e ;\
	TMP_DIR=$$(mktemp -d) ;\
	cd $$TMP_DIR ;\
	go mod init tmp ;\
	go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest ;\
	rm -rf $$TMP_DIR ;\
	}
SETUP_ENVTEST=$(GOBIN)/setup-envtest
else
SETUP_ENVTEST=$(shell which setup-envtest)
endif
