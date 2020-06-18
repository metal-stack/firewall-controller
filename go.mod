module github.com/metal-stack/firewall-controller

go 1.14

require (
	github.com/ghodss/yaml v1.0.0
	github.com/go-logr/logr v0.1.0
	github.com/google/go-cmp v0.4.1
	github.com/google/nftables v0.0.0-20200316075819-7127d9d22474
	github.com/hashicorp/go-multierror v1.1.0
	github.com/ks2211/go-suricata v0.0.0-20200410030237-20f6d74abae6
	github.com/metal-stack/v v1.0.2
	github.com/pkg/errors v0.9.1 // indirect
	github.com/rakyll/statik v0.1.7
	github.com/txn2/txeh v1.3.0
	k8s.io/api v0.18.4
	k8s.io/apiextensions-apiserver v0.18.4
	k8s.io/apimachinery v0.18.4
	k8s.io/client-go v0.18.4
	sigs.k8s.io/controller-runtime v0.6.0
	sigs.k8s.io/yaml v1.2.0
)
