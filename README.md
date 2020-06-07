# Firewall Controller

## Initial Setup

1. download kubebuilder
1. download kustomize from [kustomize](https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2Fv3.5.4/kustomize_v3.5.4_linux_amd64.tar.gz)
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

```bash
# start kind cluster
kind create cluster

# deploy manifests
k apply -f deploy

# start the controller
bin/firewall-controller --hosts-file ./hosts

# watch results
k describe -n firewall firewall
cat nftables.v4
cat hosts
```

## Suricata

By default only basic statistics are reported via the firewall crd, but id ids is enabled all events can be forwarded to a specified destination.

- The basic statistics a gathered via the unix-command socket of suricata and the `iface-stat <vrf10409>` command sent to the controlling socket.
  There is a go library available to make calls to the unix-command socket of suricata: [go-suricata](https://github.com/ks2211/go-suricata)
- Forwarding of all events is controlled by the `fever` daemon [Fever](https://github.com/DCSO/fever) which is configured by this controller if IDS is set to enabled.
