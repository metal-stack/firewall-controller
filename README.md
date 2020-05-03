# Firewall Controller


## Initial Setup

1. download kubebuilder
1. download kustomize from https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2Fv3.5.4/kustomize_v3.5.4_linux_amd64.tar.gz
1. init project and run kubebuilder

```bash
kubebuilder init --domain metal-stack.io
kubebuilder create api --group firewall --version v1 --kind Network
```

1. run test

```bash
export KUBEBUILDER_ASSETS=~/dev/kubebuilder_2.3.1_linux_amd64/bin
make test
```

## Testing locally

1. install nftables_exporter: `go install github.com/Sheridan/nftables_exporter`

```bash
# start kind cluster
kind create cluster

# start exporters
node_exporter &
nftables_exporter --config ./nftables_exporter.yaml &

# deploy manifests
k apply -f deploy

# start the controller
bin/firewall-controller --hosts-file ./hosts

# watch results
k describe networktraffic
k describe -n firewall firewall
cat nftables.v4
cat hosts
```
