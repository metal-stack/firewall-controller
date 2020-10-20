package nftables

import "fmt"

// rateLimitRules generates the nftables rules for rate limiting networks based on the firewall spec
func rateLimitRules(f *Firewall) nftablesRules {
	rules := nftablesRules{}
	for _, l := range f.spec.RateLimits {
		n, ok := f.networkMap[l.Network]
		if !ok {
			continue
		}
		if *n.Underlay {
			continue
		}
		rules = append(rules, fmt.Sprintf(`meta iifname "%s" limit rate over %d mbytes/second counter name drop_ratelimit drop`, fmt.Sprintf("vrf%d", *n.Vrf), l.Rate))
	}
	return uniqueSorted(rules)
}
