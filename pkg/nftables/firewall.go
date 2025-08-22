package nftables

import (
	"embed"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/metal-stack/firewall-controller/v2/pkg/dns"

	"github.com/metal-stack/firewall-controller/v2/pkg/network"

	"github.com/go-logr/logr"
	"github.com/vishvananda/netlink"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/record"

	mn "github.com/metal-stack/metal-lib/pkg/net"
	"github.com/metal-stack/metal-networker/pkg/netconf"

	firewallv2 "github.com/metal-stack/firewall-controller-manager/api/v2"
	firewallv1 "github.com/metal-stack/firewall-controller/v2/api/v1"

	_ "go.uber.org/mock/mockgen/model" // required for go:generate to work
)

const (
	defaultIpv4RuleFile = "/etc/nftables/firewall-controller.v4"
	nftablesService     = "nftables.service"
	nftBin              = "/usr/sbin/nft"
	systemctlBin        = "/bin/systemctl"
)

//go:embed *.tpl
var templates embed.FS

//go:generate ../../bin/mockgen -destination=./mocks/mock_fqdncache.go -package=mocks . FQDNCache
type FQDNCache interface {
	GetSetsForRendering(fqdns []firewallv1.FQDNSelector) (result []dns.RenderIPSet)
	GetSetsForFQDN(fqdn firewallv1.FQDNSelector) (result []firewallv1.IPSet)
	IsInitialized() bool
	CacheAddr() (string, error)
}

// Firewall assembles nftable rules based on k8s entities
type Firewall struct {
	log logr.Logger

	recorder record.EventRecorder

	firewall                   *firewallv2.Firewall
	clusterwideNetworkPolicies *firewallv1.ClusterwideNetworkPolicyList
	services                   *corev1.ServiceList

	primaryPrivateNet *firewallv2.FirewallNetwork
	networkMap        networkMap
	cache             FQDNCache

	enableDNS              bool
	dryRun                 bool
	logAcceptedConnections bool
}

type networkMap map[string]firewallv2.FirewallNetwork

type nftablesRules []string

type forwardingRules struct {
	Ingress nftablesRules
	Egress  nftablesRules
}

// NewFirewall creates a new nftables firewall object based on k8s entities
func NewFirewall(
	firewall *firewallv2.Firewall,
	cwnps *firewallv1.ClusterwideNetworkPolicyList,
	svcs *corev1.ServiceList,
	cache FQDNCache,
	log logr.Logger,
	recorder record.EventRecorder,
) *Firewall {
	networkMap := networkMap{}
	var primaryPrivateNet *firewallv2.FirewallNetwork
	for i, n := range firewall.Status.FirewallNetworks {
		if n.NetworkType == nil {
			continue
		}
		if *n.NetworkType == mn.PrivatePrimaryShared || *n.NetworkType == mn.PrivatePrimaryUnshared {
			primaryPrivateNet = &firewall.Status.FirewallNetworks[i]
		}
		networkMap[*n.NetworkID] = n
	}

	return &Firewall{
		firewall:                   firewall,
		clusterwideNetworkPolicies: cwnps,
		services:                   svcs,
		primaryPrivateNet:          primaryPrivateNet,
		networkMap:                 networkMap,
		dryRun:                     firewall.Spec.DryRun,
		logAcceptedConnections:     firewall.Spec.LogAcceptedConnections,
		cache:                      cache,
		enableDNS:                  len(cwnps.GetFQDNs()) > 0,
		log:                        log,
		recorder:                   recorder,
	}
}

func (f *Firewall) ipv4RuleFile() string {
	if f.firewall.Spec.Ipv4RuleFile != "" {
		return f.firewall.Spec.Ipv4RuleFile
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
func (f *Firewall) Reconcile() (updated bool, err error) {
	tmpFile, err := os.CreateTemp(filepath.Dir(f.ipv4RuleFile()), "."+filepath.Base(f.ipv4RuleFile()))
	if err != nil {
		return
	}
	defer func() {
		_ = os.Remove(tmpFile.Name())
	}()

	err = f.reconcileIfaceAddresses()
	if err != nil {
		return
	}

	desired := tmpFile.Name()
	err = f.renderFile(desired)
	if err != nil {
		return
	}

	if equal(f.ipv4RuleFile(), desired) {
		f.log.Info("no changes in nftables detected", "existing rules", f.ipv4RuleFile(), "new rules", desired)
		return
	}

	err = os.Rename(desired, f.ipv4RuleFile())
	if err != nil {
		return
	}
	f.log.Info("changes in nftables detected, reloading nft", "existing rules", f.ipv4RuleFile(), "new rules", desired)

	if f.dryRun {
		return
	}
	err = f.reload()
	if err != nil {
		return
	}

	return true, nil
}

func (f *Firewall) ReconcileNetconfTables() error {
	c, err := netconf.New(network.GetLogger(), network.MetalNetworkerConfig)
	if err != nil || c == nil {
		return fmt.Errorf("failed to init networker config: %w", err)
	}

	c.Networks = network.GetNewNetworks(f.firewall, c.Networks)

	configurator, err := netconf.NewConfigurator(netconf.Firewall, *c, f.enableDNS)
	if err != nil {
		return fmt.Errorf("failed to init networker configurator: %w", err)
	}
	configurator.ConfigureNftables(netconf.ForwardPolicyAccept)

	return nil
}

func getConfiguredIPs(networkID string) []string {
	c, err := netconf.New(network.GetLogger(), network.MetalNetworkerConfig)
	if err != nil || c == nil {
		return nil
	}
	var ips []string
	for _, nw := range c.Networks {
		if nw.Networkid == nil || *nw.Networkid != networkID {
			continue
		}
		for _, ip := range nw.Ips {
			ips = append(ips, ip)
		}
	}
	return ips
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
	var errs []error

	for _, n := range f.networkMap {
		if n.NetworkType == nil || n.NetworkID == nil {
			continue
		}

		if *n.NetworkType != mn.External {
			continue
		}

		configureIPs := getConfiguredIPs(*n.NetworkID)

		wantedIPs := sets.NewString(configureIPs...)
		for _, i := range f.firewall.Spec.EgressRules {
			if i.NetworkID == *n.NetworkID {
				wantedIPs.Insert(i.IPs...)
				break
			}
		}

		linkName := fmt.Sprintf("vlan%d", *n.Vrf)
		link, err := netlink.LinkByName(linkName)
		if err != nil {
			var notFound netlink.LinkNotFoundError
			if errors.As(err, &notFound) {
				f.log.Info("skipping link because not found", "name", linkName)
			}
			return fmt.Errorf("unable to detect link by name: %w", err)
		}
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		actualIPs := sets.NewString()
		for _, addr := range addrs {
			actualIPs.Insert(addr.IP.String())
		}

		toAdd := wantedIPs.Difference(actualIPs)
		toRemove := actualIPs.Difference(wantedIPs)

		// do not remove IPs that were initially used during machine allocation!
		toRemove.Delete(n.IPs...)

		if f.dryRun {
			f.log.Info("skipping reconciling ips for", "network", n.NetworkID, "adding", toAdd, "removing", toRemove)
			continue
		}
		f.log.Info("reconciling ips for", "network", n.NetworkID, "adding", toAdd, "removing", toRemove)

		for add := range toAdd {
			parsedAddr, err := netip.ParseAddr(add)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			addr, _ := netlink.ParseAddr(fmt.Sprintf("%s/%d", parsedAddr.String(), parsedAddr.BitLen()))
			err = netlink.AddrAdd(link, addr)
			if err != nil {
				errs = append(errs, err)
			}
		}

		for delete := range toRemove {
			parsedAddr, err := netip.ParseAddr(delete)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			addr, _ := netlink.ParseAddr(fmt.Sprintf("%s/%d", parsedAddr.String(), parsedAddr.BitLen()))
			err = netlink.AddrDel(link, addr)
			if err != nil {
				errs = append(errs, err)
			}
		}
	}

	return errors.Join(errs...)
}

func (f *Firewall) reload() error {
	c := exec.Command(systemctlBin, "reload", nftablesService)
	err := c.Run()
	if err != nil {
		return fmt.Errorf("could not reload nftables service, err: %w", err)
	}
	return nil
}
