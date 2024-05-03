package nftables

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"text/template"

	"github.com/metal-stack/firewall-controller/v2/pkg/dns"
	"github.com/metal-stack/firewall-controller/v2/pkg/helper"
	"go4.org/netipx"
)

// firewallRenderingData holds the data available in the nftables template
type firewallRenderingData struct {
	ForwardingRules  forwardingRules
	RateLimitRules   nftablesRules
	SnatRules        nftablesRules
	Sets             []dns.RenderIPSet
	InternalPrefixes string
	PrivateVrfID     uint
	DnsProxy         *dnsProxyData
}

type dnsProxyData struct {
	Enabled      bool
	DNSAddrs     []string
	DNSPort      int
	ExternalIPs  []string
	PrimaryIface string
	NodeCidrs    []string
}

func newFirewallRenderingData(f *Firewall) (*firewallRenderingData, error) {
	ingress, egress := nftablesRules{}, nftablesRules{}
	for ind, np := range f.clusterwideNetworkPolicies.Items {
		err := np.Spec.Validate()
		if err != nil {
			continue
		}

		i, e, u := clusterwideNetworkPolicyRules(f.cache, np, f.logAcceptedConnections)
		ingress = append(ingress, i...)
		egress = append(egress, e...)
		f.clusterwideNetworkPolicies.Items[ind] = u
	}

	var serviceAllowedSet *netipx.IPSet
	if len(f.firewall.Spec.AllowedNetworks.Ingress) > 0 {
		// the ips for services are only checked if the accesstype is forbidden
		a, err := helper.BuildNetworksIPSet(f.firewall.Spec.AllowedNetworks.Ingress)
		if err != nil {
			return nil, err
		}
		serviceAllowedSet = a
	}

	for _, svc := range f.services.Items {
		ingress = append(ingress, serviceRules(svc, serviceAllowedSet, f.logAcceptedConnections, f.recorder)...)
	}

	snatRules, err := snatRules(f)
	if err != nil {
		return &firewallRenderingData{}, err
	}

	var (
		sets []dns.RenderIPSet

		dnsProxy = &dnsProxyData{
			Enabled:  false,
			DNSAddrs: []string{"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"},
			DNSPort:  53,
		}
	)
	if f.cache.IsInitialized() {
		sets = f.cache.GetSetsForRendering(f.clusterwideNetworkPolicies.GetFQDNs())

		if f.firewall.Spec.DNSPort != nil {
			dnsProxy.DNSPort = int(*f.firewall.Spec.DNSPort)
		}

		rules, err := clusterwideNetworkPolicyEgressDNSCacheRules(f.cache, dnsProxy.DNSPort, f.logAcceptedConnections)
		if err != nil {
			return &firewallRenderingData{}, err
		}

		if f.firewall.Spec.DNSServerAddress != "" {
			dnsProxy.DNSAddrs = strings.Split(f.firewall.Spec.DNSServerAddress, ",")
		}

		for _, nw := range f.networkMap {
			if nw.NetworkType == nil || *nw.NetworkType != "external" {
				continue
			}

			dnsProxy.ExternalIPs = append(dnsProxy.ExternalIPs, nw.IPs...)
		}

		dnsProxy.PrimaryIface = fmt.Sprintf("%d", *f.primaryPrivateNet.Vrf)
		dnsProxy.NodeCidrs = append(dnsProxy.NodeCidrs, f.primaryPrivateNet.Prefixes...)

		egress = append(egress, rules...)
	}

	return &firewallRenderingData{
		DnsProxy:         dnsProxy,
		PrivateVrfID:     uint(*f.primaryPrivateNet.Vrf),
		InternalPrefixes: strings.Join(f.firewall.Spec.InternalPrefixes, ", "),
		ForwardingRules: forwardingRules{
			Ingress: ingress,
			Egress:  egress,
		},
		RateLimitRules: rateLimitRules(f),
		SnatRules:      snatRules,
		Sets:           sets,
	}, nil
}

func (d *firewallRenderingData) write(file string) error {
	c, err := d.renderString()
	if err != nil {
		return err
	}
	err = os.WriteFile(file, []byte(c), 0600)
	if err != nil {
		return fmt.Errorf("error writing to nftables file '%s': %w", file, err)
	}
	return nil
}

func (d *firewallRenderingData) renderString() (string, error) {
	var b bytes.Buffer

	tplString, err := d.readTpl()
	if err != nil {
		return "", err
	}

	tpl := template.Must(
		template.New("v4").
			Funcs(template.FuncMap{"StringsJoin": strings.Join}).
			Parse(tplString),
	)

	err = tpl.Execute(&b, d)
	if err != nil {
		return "", err
	}

	return b.String(), nil
}

func (d *firewallRenderingData) readTpl() (string, error) {
	r, err := templates.Open("nftables.tpl")
	if err != nil {
		return "", err
	}
	defer r.Close()
	bytes, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}
