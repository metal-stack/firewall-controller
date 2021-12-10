module github.com/metal-stack/firewall-controller

go 1.16

require (
	github.com/go-logr/logr v1.0.0
	github.com/google/go-cmp v0.5.6
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/nftables v0.0.0-20211209220838-6f19c4381e13
	github.com/hashicorp/go-multierror v1.1.1
	github.com/ks2211/go-suricata v0.0.0-20200823200910-986ce1470707
	github.com/metal-stack/metal-go v0.16.1
	github.com/metal-stack/metal-lib v0.9.0
	github.com/metal-stack/metal-networker v0.7.2
	github.com/metal-stack/v v1.0.3
	github.com/txn2/txeh v1.3.0
	github.com/vishvananda/netlink v1.1.0
	k8s.io/api v0.22.2
	k8s.io/apiextensions-apiserver v0.22.2
	k8s.io/apimachinery v0.22.2
	k8s.io/client-go v0.22.2
	sigs.k8s.io/controller-runtime v0.10.3
	sigs.k8s.io/yaml v1.3.0
)

replace github.com/go-logr/logr => github.com/go-logr/logr v0.4.0
