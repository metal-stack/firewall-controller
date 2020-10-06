package nftables

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"text/template"

	"github.com/rakyll/statik/fs"
)

// firewallRenderingData holds the data available in the nftables template
type firewallRenderingData struct {
	ForwardingRules  forwardingRules
	RateLimitRules   nftablesRules
	SnatRules        nftablesRules
	InternalPrefixes string
	PrivateVrfID     uint

	statikFS http.FileSystem
}

func newFirewallRenderingData(f *Firewall) (*firewallRenderingData, error) {
	ingress, egress := []string{}, []string{}
	for _, np := range f.clusterwideNetworkPolicies.Items {
		if len(np.Spec.Egress) > 0 {
			egress = append(egress, egressForNetworkPolicy(np)...)
		}
		if len(np.Spec.Ingress) > 0 {
			ingress = append(ingress, ingressForNetworkPolicy(np)...)
		}
	}

	for _, svc := range f.services.Items {
		ingress = append(ingress, ingressForService(svc)...)
	}

	snatRules, err := snatRules(f)
	if err != nil {
		return &firewallRenderingData{}, err
	}

	statikFS, err := fs.NewWithNamespace("tpl")
	if err != nil {
		panic(err)
	}

	return &firewallRenderingData{
		statikFS:         statikFS,
		PrivateVrfID:     f.primaryPrivateNet.Vrf,
		InternalPrefixes: strings.Join(f.spec.InternalPrefixes, ", "),
		ForwardingRules: forwardingRules{
			Egress:  uniqueSorted(egress),
			Ingress: uniqueSorted(ingress),
		},
		RateLimitRules: rateLimitRules(f),
		SnatRules:      snatRules,
	}, nil
}

func (d *firewallRenderingData) write(file string) error {
	c, err := d.renderString()
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(file, []byte(c), 0644)
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

	tpl := template.Must(template.New("v4").Parse(tplString))

	err = tpl.Execute(&b, d)
	if err != nil {
		return "", err
	}

	return b.String(), nil
}

func (d *firewallRenderingData) readTpl() (string, error) {
	r, err := d.statikFS.Open("/nftables.tpl")
	if err != nil {
		return "", err
	}
	defer r.Close()
	bytes, err := ioutil.ReadAll(r)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

type snatRule struct {
	sourceNetworks string
	oifname        string
	to             string
	comment        string
}

func (s *snatRule) String() string {
	return fmt.Sprintf(`ip saddr { %s } oifname "%s" counter snat %s comment "%s"`, s.sourceNetworks, s.oifname, s.to, s.comment)
}

// snatRules generates the nftables rules for SNAT based on the firewall spec
func snatRules(f *Firewall) (nftablesRules, error) {
	if f.primaryPrivateNet == nil {
		return nil, fmt.Errorf("no primary private network found")
	}

	rules := nftablesRules{}
	for _, s := range f.spec.Snat {
		n, there := f.networkMap[s.Network]
		if !there {
			return nil, fmt.Errorf("network not found")
		}

		hmap := []string{}
		for k, i := range s.IPs {
			ip := net.ParseIP(i)
			if ip == nil {
				return nil, fmt.Errorf("could not parse ip %s", i)
			}

			innets := false
			for _, prefix := range n.Prefixes {
				_, cidr, err := net.ParseCIDR(prefix)
				if err != nil {
					return nil, fmt.Errorf("could not parse cidr %s", prefix)
				}

				if cidr.Contains(ip) {
					innets = true
					break
				}
			}

			if !innets {
				return nil, fmt.Errorf("ip %s is not in any prefix of network %s", i, s.Network)
			}
			hmap = append(hmap, fmt.Sprintf("%d : %s", k, ip.String()))
		}

		var to string
		if len(s.IPs) == 0 {
			return nil, fmt.Errorf("need to specify at least one address for SNAT")
		} else if len(s.IPs) == 1 {
			to = s.IPs[0]
		} else {
			to = fmt.Sprintf("to jhash ip daddr . tcp sport mod %d map { %s }", len(s.IPs), strings.Join(hmap, ", "))
		}

		snatRule := snatRule{
			comment:        fmt.Sprintf("snat for %s", s.Network),
			sourceNetworks: strings.Join(f.primaryPrivateNet.Prefixes, ", "),
			oifname:        fmt.Sprintf("vlan%d", n.Vrf),
			to:             to,
		}
		rules = append(rules, snatRule.String())
	}
	return rules, nil
}

// rateLimitRules generates the nftables rules for rate limiting networks based on the firewall spec
func rateLimitRules(f *Firewall) nftablesRules {
	rules := nftablesRules{}
	for _, l := range f.spec.RateLimits {
		n, ok := f.networkMap[l.Network]
		if !ok {
			continue
		}
		if n.Underlay {
			continue
		}
		rules = append(rules, fmt.Sprintf(`meta iifname "%s" limit rate over %d mbytes/second counter name drop_ratelimit drop`, fmt.Sprintf("vrf%d", n.Vrf), l.Rate))
	}
	return rules
}
