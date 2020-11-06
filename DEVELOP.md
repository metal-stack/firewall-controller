# Develop Setup

1. download kubebuilder
1. download kustomize from [kustomize](https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2Fv3.5.4/kustomize_v3.5.4_linux_amd64.tar.gz)
1. init project and run kubebuilder
   ```bash
   kubebuilder init --domain metal-stack.io
   kubebuilder create api --group firewall --version v1 --kind Network
   ```
1. run test
   ```bash
   export KUBEBUILDER_ASSETS=/usr/local/kubebuilder/bin # path-to-kubebuilder/bin
   make test
   ```

## Testing locally

```bash
# make binary
make

# start the controller
bin/firewall-controller --hosts-file ./hosts --enable-signature-check=false

# install kind (k8s in docker)

# create a local kind cluster
kind create cluster

# deploy manifests
k apply -f deploy

# watch results
k describe -n firewall firewall
cat nftables.v4
cat hosts
```