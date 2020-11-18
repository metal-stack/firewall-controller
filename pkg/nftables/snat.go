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

	rules := nftablesRules{}
	for _, s := range f.spec.EgressRules {
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
			sourceNetworks: strings.Join(f.primaryPrivateNet.Prefixes, ", "),
			oifname:        fmt.Sprintf("vlan%d", *n.Vrf),
			to:             to,
		}
		rules = append(rules, snatRule.String())
	}
	return uniqueSorted(rules), nil
}
