package nftables

import (
	"fmt"
	"strings"

	networkingv1 "k8s.io/api/networking/v1"

	firewallv1 "github.com/metal-stack/firewall-controller/v2/api/v1"
)

type ruleBase struct {
	comment string
	base    []string
}

// clusterwideNetworkPolicyRules generates nftables rules for a clusterwidenetworkpolicy
func clusterwideNetworkPolicyRules(
	cache FQDNCache,
	np firewallv1.ClusterwideNetworkPolicy,
	logAcceptedConnections bool,
) (ingress nftablesRules, egress nftablesRules, updated firewallv1.ClusterwideNetworkPolicy) {
	updated = np

	if len(np.Spec.Egress) > 0 {
		egress, updated = clusterwideNetworkPolicyEgressRules(cache, np, logAcceptedConnections)
	}
	if len(np.Spec.Ingress) > 0 {
		ingress = append(ingress, clusterwideNetworkPolicyIngressRules(np, logAcceptedConnections)...)
	}

	return
}

func clusterwideNetworkPolicyIngressRules(np firewallv1.ClusterwideNetworkPolicy, logAcceptedConnections bool) (rules nftablesRules) {
	for _, i := range np.Spec.Ingress {
		allow := []string{}
		except := []string{}
		for _, ipBlock := range i.From {
			allow = append(allow, ipBlock.CIDR)
			except = append(except, ipBlock.Except...)
		}
		common := []string{}
		if len(except) > 0 {
			common = append(common, fmt.Sprintf("ip saddr != { %s }", strings.Join(except, ", ")))
		}
		if len(allow) > 0 {
			common = append(common, fmt.Sprintf("ip saddr { %s }", strings.Join(allow, ", ")))
		}
		tcpPorts, udpPorts := calculatePorts(i.Ports)
		comment := fmt.Sprintf("accept traffic for k8s network policy %s", np.Name)
		if len(tcpPorts) > 0 {
			rules = append(rules, assembleDestinationPortRule(common, "tcp", tcpPorts, logAcceptedConnections, comment+" tcp"))
		}
		if len(udpPorts) > 0 {
			rules = append(rules, assembleDestinationPortRule(common, "udp", udpPorts, logAcceptedConnections, comment+" udp"))
		}
	}

	return uniqueSorted(rules)
}

func clusterwideNetworkPolicyEgressDNSCacheRules(cache FQDNCache, logAcceptedConnections bool) (nftablesRules, error) {
	addr, err := cache.CacheAddr()
	if err != nil {
		return nil, err
	}
	base := []string{"ip saddr == @cluster_prefixes", fmt.Sprintf("ip daddr { %s }", addr)}
	comment := "accept intercepted traffic for dns cache"
	return nftablesRules{
		assembleDestinationPortRule(base, "tcp", []string{"53"}, logAcceptedConnections, comment+" tcp"),
		assembleDestinationPortRule(base, "udp", []string{"53"}, logAcceptedConnections, comment+" udp"),
	}, nil
}

func clusterwideNetworkPolicyEgressRules(
	cache FQDNCache,
	np firewallv1.ClusterwideNetworkPolicy,
	logAcceptedConnections bool,
) (rules nftablesRules, updated firewallv1.ClusterwideNetworkPolicy) {
	var fqdnState firewallv1.FQDNState
	for _, e := range np.Spec.Egress {
		tcpPorts, udpPorts := calculatePorts(e.Ports)
		ruleBases := []ruleBase{}
		if len(e.To) > 0 {
			allow, except := clusterwideNetworkPolicyEgressToRules(e)
			rb := []string{"ip saddr == @cluster_prefixes"}
			if len(except) > 0 {
				rb = append(rb, fmt.Sprintf("ip daddr != { %s }", strings.Join(except, ", ")))
			}
			if len(allow) > 0 {
				if allow[0] != "0.0.0.0/0" {
					rb = append(rb, fmt.Sprintf("ip daddr { %s }", strings.Join(allow, ", ")))
				}
			}
			ruleBases = append(ruleBases, ruleBase{base: rb})
		} else if len(e.ToFQDNs) > 0 && cache.IsInitialized() {
			rbs, u := clusterwideNetworkPolicyEgressToFQDNRules(cache, fqdnState, e)
			ruleBases = append(ruleBases, rbs...)
			fqdnState = u
		}

		comment := fmt.Sprintf("accept traffic for np %s", np.Name)
		for _, rb := range ruleBases {
			if len(tcpPorts) > 0 {
				rules = append(rules, assembleDestinationPortRule(rb.base, "tcp", tcpPorts, logAcceptedConnections, comment+" tcp"+rb.comment))
			}
			if len(udpPorts) > 0 {
				rules = append(rules, assembleDestinationPortRule(rb.base, "udp", udpPorts, logAcceptedConnections, comment+" udp"+rb.comment))
			}
		}
	}

	np.Status.FQDNState = fqdnState
	return uniqueSorted(rules), np
}

func clusterwideNetworkPolicyEgressToRules(e firewallv1.EgressRule) (allow, except []string) {
	for _, ipBlock := range e.To {
		allow = append(allow, ipBlock.CIDR)
		except = append(except, ipBlock.Except...)
	}

	return
}

func clusterwideNetworkPolicyEgressToFQDNRules(
	cache FQDNCache,
	fqdnState firewallv1.FQDNState,
	e firewallv1.EgressRule,
) (rules []ruleBase, updatedState firewallv1.FQDNState) {
	if fqdnState == nil {
		fqdnState = firewallv1.FQDNState{}
	}

	for _, fqdn := range e.ToFQDNs {
		fqdnName := fqdn.MatchName
		if fqdnName == "" {
			fqdnName = fqdn.MatchPattern
		}

		fqdnState[fqdnName] = cache.GetSetsForFQDN(fqdn)
		for _, set := range fqdnState[fqdnName] {
			rb := []string{"ip saddr == @cluster_prefixes"}
			rb = append(rb, fmt.Sprintf(string(set.Version)+" daddr @%s", set.SetName))
			rules = append(rules, ruleBase{comment: fmt.Sprintf(", fqdn: %s", fqdn.GetName()), base: rb})
		}
	}

	return rules, fqdnState
}

func calculatePorts(ports []networkingv1.NetworkPolicyPort) (tcpPorts, udpPorts []string) {
	for _, p := range ports {
		proto := proto(p.Protocol)
		portStr := fmt.Sprint(p.Port)
		if p.EndPort != nil {
			portStr = fmt.Sprintf("%s-%d", p.Port, *p.EndPort)
		}
		switch proto {
		case "tcp":
			tcpPorts = append(tcpPorts, portStr)
		case "udp":
			udpPorts = append(udpPorts, portStr)
		}
	}
	return tcpPorts, udpPorts
}
