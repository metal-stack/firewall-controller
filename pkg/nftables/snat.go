package nftables

import (
	"fmt"
	"net"
	"strings"

	mn "github.com/metal-stack/metal-lib/pkg/net"
)

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
	sourceNetworks := strings.Join(f.primaryPrivateNet.Prefixes, ", ")

	rules := nftablesRules{}
	for _, s := range f.firewall.Spec.EgressRules {
		n, there := f.networkMap[s.NetworkID]
		if !there {
			return nil, fmt.Errorf("network not found")
		}

		if n.Networktype == nil || *n.Networktype != mn.External {
			continue
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
				return nil, fmt.Errorf("ip %s is not in any prefix of network %s", i, s.NetworkID)
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
			comment:        fmt.Sprintf("snat for %s", s.NetworkID),
			sourceNetworks: sourceNetworks,
			oifname:        fmt.Sprintf("vlan%d", *n.Vrf),
			to:             to,
		}
		rules = append(rules, snatRule.String())
	}

	enableDNS := len(f.clusterwideNetworkPolicies.GetFQDNs()) > 0
	if enableDNS {
		escapeDNSRules := []string{
			fmt.Sprintf(`ip saddr { %s } tcp dport { 53 } accept comment "escape snat for dns proxy tcp"`, sourceNetworks),
			fmt.Sprintf(`ip saddr { %s } udp dport { 53 } accept comment "escape snat for dns proxy udp"`, sourceNetworks),
		}
		return append(escapeDNSRules, uniqueSorted(rules)...), nil
	}

	return uniqueSorted(rules), nil
}
