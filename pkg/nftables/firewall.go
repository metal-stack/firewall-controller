package nftables

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"

	"github.com/hashicorp/go-multierror"
	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
	_ "github.com/metal-stack/firewall-controller/pkg/nftables/statik"
	"github.com/vishvananda/netlink"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
)

const (
	defaultIpv4RuleFile = "/etc/nftables/firewall-controller.v4"
	nftablesService     = "nftables.service"
	nftBin              = "/usr/sbin/nft"
	systemctlBin        = "/bin/systemctl"
)

// Firewall assembles nftable rules based on k8s entities
type Firewall struct {
	spec                       firewallv1.FirewallSpec
	clusterwideNetworkPolicies *firewallv1.ClusterwideNetworkPolicyList
	services                   *corev1.ServiceList

	primaryPrivateNet *firewallv1.Network
	networkMap        networkMap

	dryRun bool
}

type networkMap map[string]firewallv1.Network

type nftablesRules []string

type forwardingRules struct {
	Ingress nftablesRules
	Egress  nftablesRules
}

// NewDefaultFirewall creates a new default nftables firewall.
func NewDefaultFirewall() *Firewall {
	defaultSpec := firewallv1.FirewallSpec{}
	return NewFirewall(&firewallv1.ClusterwideNetworkPolicyList{}, &v1.ServiceList{}, defaultSpec)
}

// NewFirewall creates a new nftables firewall object based on k8s entities
func NewFirewall(nps *firewallv1.ClusterwideNetworkPolicyList, svcs *corev1.ServiceList, spec firewallv1.FirewallSpec) *Firewall {
	networkMap := networkMap{}
	var primaryPrivateNet *firewallv1.Network
	for i, n := range spec.Networks {
		if n.ParentNetworkID != "" && !n.Underlay && !n.PrivateSuper && !n.Shared {
			primaryPrivateNet = &spec.Networks[i]
		}
		networkMap[n.ID] = n
	}

	return &Firewall{
		spec:                       spec,
		clusterwideNetworkPolicies: nps,
		services:                   svcs,
		primaryPrivateNet:          primaryPrivateNet,
		networkMap:                 networkMap,
		dryRun:                     spec.DryRun,
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
	tmpFile, err := ioutil.TempFile("/var/tmp", "firewall-controller_nftables.v4")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())

	desired := tmpFile.Name()
	err = f.renderFile(desired)
	if err != nil {
		return err
	}
	if equal(f.ipv4RuleFile(), desired) {
		return nil
	}
	err = os.Rename(desired, f.ipv4RuleFile())
	if err != nil {
		return err
	}
	if f.dryRun {
		return nil
	}
	err = f.reconcileIfaceAddresses()
	if err != nil {
		return err
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
	for _, i := range f.spec.Snat {
		n, ok := f.networkMap[i.Network]
		if !ok {
			errors = multierror.Append(errors, fmt.Errorf("could not find network %s in networks", i.Network))
			continue
		}

		if n.Underlay || n.PrivateSuper || n.Shared {
			errors = multierror.Append(errors, fmt.Errorf("it is unsupported to configure snat for underlay, private super or shared private networks"))
			continue
		}

		link, _ := netlink.LinkByName(fmt.Sprintf("vlan%d", n.Vrf))
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			errors = multierror.Append(errors, err)
		}

		actualIPs := []string{}
		for _, addr := range addrs {
			actualIPs = append(actualIPs, addr.IP.String())
		}

		d := diff(i.IPs, actualIPs)
		for _, add := range d.toAdd {
			addr, _ := netlink.ParseAddr(fmt.Sprintf("%s/32", add))
			err = netlink.AddrAdd(link, addr)
			if err != nil {
				errors = multierror.Append(errors, err)
			}
		}

		for _, delete := range d.toRemove {
			// do not remove IPs that were initially used during machine allocation!
			isFixed := false
			for _, fixedIP := range n.IPs {
				if delete == fixedIP {
					isFixed = true
					break
				}
			}
			if isFixed {
				continue
			}
			addr, _ := netlink.ParseAddr(fmt.Sprintf("%s/32", delete))
			err = netlink.AddrDel(link, addr)
			if err != nil {
				errors = multierror.Append(errors, err)
			}
		}
	}
	return errors
}

func (f *Firewall) reload() error {
	c := exec.Command(systemctlBin, "reload", nftablesService)
	err := c.Run()
	if err != nil {
		return fmt.Errorf("could not reload nftables service, err: %w", err)
	}
	return nil
}
