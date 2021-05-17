package nftables

import (
	"embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/go-logr/logr"
	"github.com/hashicorp/go-multierror"

	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"

	mn "github.com/metal-stack/metal-lib/pkg/net"
	"github.com/vishvananda/netlink"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
)

const (
	defaultIpv4RuleFile = "/etc/nftables/firewall-controller.v4"
	nftablesService     = "nftables.service"
	nftBin              = "/usr/sbin/nft"
	systemctlBin        = "/bin/systemctl"
)

//go:embed *.tpl
var templates embed.FS

//go:generate mockgen -destination=./mocks/mock_fqdncache.go -package=mocks . FQDNCache
type FQDNCache interface {
	UpdateDNSServerAddr(addr string)
	GetSetsForRendering() (result []firewallv1.IPSet)
	GetSetsForFQDN(fqdn firewallv1.FQDNSelector, update bool) (result []firewallv1.IPSet)
}

// Firewall assembles nftable rules based on k8s entities
type Firewall struct {
	log logr.Logger

	spec                       firewallv1.FirewallSpec
	clusterwideNetworkPolicies *firewallv1.ClusterwideNetworkPolicyList
	services                   *corev1.ServiceList

	primaryPrivateNet *firewallv1.FirewallNetwork
	networkMap        networkMap
	cache             FQDNCache

	dryRun                 bool
	logAcceptedConnections bool
}

type networkMap map[string]firewallv1.FirewallNetwork

type nftablesRules []string

type forwardingRules struct {
	Ingress nftablesRules
	Egress  nftablesRules
}

// NewDefaultFirewall creates a new default nftables firewall.
func NewDefaultFirewall() *Firewall {
	defaultSpec := firewallv1.FirewallSpec{}
	return NewFirewall(&firewallv1.ClusterwideNetworkPolicyList{}, &corev1.ServiceList{}, defaultSpec, nil, logr.Discard())
}

// NewFirewall creates a new nftables firewall object based on k8s entities
func NewFirewall(
	nps *firewallv1.ClusterwideNetworkPolicyList,
	svcs *corev1.ServiceList,
	spec firewallv1.FirewallSpec,
	cache FQDNCache,
	log logr.Logger,
) *Firewall {
	networkMap := networkMap{}
	var primaryPrivateNet *firewallv1.FirewallNetwork
	for i, n := range spec.FirewallNetworks {
		if n.Networktype == nil {
			continue
		}
		if *n.Networktype == mn.PrivatePrimaryShared || *n.Networktype == mn.PrivatePrimaryUnshared {
			primaryPrivateNet = &spec.FirewallNetworks[i]
		}
		networkMap[*n.Networkid] = n
	}

	return &Firewall{
		spec:                       spec,
		clusterwideNetworkPolicies: nps,
		services:                   svcs,
		primaryPrivateNet:          primaryPrivateNet,
		networkMap:                 networkMap,
		dryRun:                     spec.DryRun,
		logAcceptedConnections:     spec.LogAcceptedConnections,
		cache:                      cache,
		log:                        log,
	}
}

func (f *Firewall) ipv4RuleFile() string {
	if f.spec.Ipv4RuleFile != "" {
		return f.spec.Ipv4RuleFile
	}
	return defaultIpv4RuleFile
}

// Flush flushes the nftables rules that were deduced from a k8s resources
// after that the firewall is a "plain metal firewall" with default policy accept in the forward chain.
func (f *Firewall) Flush() error {
	_, err := os.Stat(f.ipv4RuleFile())
	if os.IsNotExist(err) {
		return f.reload()
	}
	// only remove if rule file exists
	err = os.Remove(f.ipv4RuleFile())
	if err != nil {
		return fmt.Errorf("could not delete ipv4 rule file: %w", err)
	}
	return f.reload()
}

// Reconcile drives the nftables firewall against the desired state by comparison with the current rule file.
func (f *Firewall) Reconcile() error {
	tmpFile, err := os.CreateTemp(filepath.Dir(f.ipv4RuleFile()), "."+filepath.Base(f.ipv4RuleFile()))
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())

	err = f.reconcileIfaceAddresses()
	if err != nil {
		return err
	}

	desired := tmpFile.Name()
	err = f.renderFile(desired)
	if err != nil {
		return err
	}

	if equal(f.ipv4RuleFile(), desired) {
		f.log.Info("no changes in nftables detected", "existing rules", f.ipv4RuleFile(), "new rules", desired)
		return nil
	}

	err = os.Rename(desired, f.ipv4RuleFile())
	if err != nil {
		return err
	}
	f.log.Info("changes in nftables detected, reloading nft", "existing rules", f.ipv4RuleFile(), "new rules", desired)

	if f.dryRun {
		return nil
	}
	err = f.reload()
	if err != nil {
		return err
	}
	return nil
}

func (f *Firewall) renderFile(file string) error {
	fd, err := newFirewallRenderingData(f)
	if err != nil {
		return err
	}

	err = fd.write(file)
	if err != nil {
		return err
	}
	if f.dryRun {
		return nil
	}
	err = f.validate(file)
	if err != nil {
		return err
	}
	return nil
}

func (f *Firewall) validate(file string) error {
	c := exec.Command(nftBin, "-c", "-f", file)
	out, err := c.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nftables file '%s' is invalid: %s, err: %w", file, string(out), err)
	}
	return nil
}

func (f *Firewall) reconcileIfaceAddresses() error {
	var errors *multierror.Error

	for _, n := range f.networkMap {
		if n.Networktype == nil {
			continue
		}

		if *n.Networktype != mn.External {
			continue
		}

		wantedIPs := sets.NewString()
		for _, i := range f.spec.EgressRules {
			if i.NetworkID == *n.Networkid {
				wantedIPs.Insert(i.IPs...)
				break
			}
		}

		link, _ := netlink.LinkByName(fmt.Sprintf("vlan%d", *n.Vrf))
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			errors = multierror.Append(errors, err)
			continue
		}

		actualIPs := sets.NewString()
		for _, addr := range addrs {
			actualIPs.Insert(addr.IP.String())
		}

		toAdd := wantedIPs.Difference(actualIPs)
		toRemove := actualIPs.Difference(wantedIPs)

		// do not remove IPs that were initially used during machine allocation!
		toRemove.Delete(n.Ips...)

		if f.dryRun {
			f.log.Info("skipping reconciling ips for", "network", n.Networkid, "adding", toAdd, "removing", toRemove)
			continue
		}
		f.log.Info("reconciling ips for", "network", n.Networkid, "adding", toAdd, "removing", toRemove)

		for add := range toAdd {
			addr, _ := netlink.ParseAddr(fmt.Sprintf("%s/32", add))
			err = netlink.AddrAdd(link, addr)
			if err != nil {
				errors = multierror.Append(errors, err)
			}
		}

		for delete := range toRemove {
			addr, _ := netlink.ParseAddr(fmt.Sprintf("%s/32", delete))
			err = netlink.AddrDel(link, addr)
			if err != nil {
				errors = multierror.Append(errors, err)
			}
		}
	}

	return errors.ErrorOrNil()
}

func (f *Firewall) reload() error {
	c := exec.Command(systemctlBin, "reload", nftablesService)
	err := c.Run()
	if err != nil {
		return fmt.Errorf("could not reload nftables service, err: %w", err)
	}
	return nil
}
