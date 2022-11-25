package nftables

import (
	"fmt"
	"strings"

	networkingv1 "k8s.io/api/networking/v1"

	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
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
		comment := fmt.Sprintf("accept traffic for k8s network policy %s", np.ObjectMeta.Name)
		if len(tcpPorts) > 0 {
			rules = append(rules, assembleDestinationPortRule(common, "tcp", tcpPorts, logAcceptedConnections, comment+" tcp"))
		}
		if len(udpPorts) > 0 {
			rules = append(rules, assembleDestinationPortRule(common, "udp", udpPorts, logAcceptedConnections, comment+" udp"))
		}
	}

	return uniqueSorted(rules)
}

func clusterwideNetworkPolicyEgressRules(
	cache FQDNCache,
	np firewallv1.ClusterwideNetworkPolicy,
	logAcceptedConnections bool,
) (rules nftablesRules, updated firewallv1.ClusterwideNetworkPolicy) {
	for i, e := range np.Spec.Egress {
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
		} else if len(e.ToFQDNs) > 0 && cache != nil {
			// Generate allow rules based on DNS selectors
			rbs, u := clusterwideNetworkPolicyEgressToFQDNRules(cache, e)
			np.Spec.Egress[i] = u
			ruleBases = append(ruleBases, rbs...)
		}

		comment := fmt.Sprintf("accept traffic for np %s", np.ObjectMeta.Name)
		for _, rb := range ruleBases {
			if len(tcpPorts) > 0 {
				rules = append(rules, assembleDestinationPortRule(rb.base, "tcp", tcpPorts, logAcceptedConnections, comment+" tcp"+rb.comment))
			}
			if len(udpPorts) > 0 {
				rules = append(rules, assembleDestinationPortRule(rb.base, "udp", udpPorts, logAcceptedConnections, comment+" udp"+rb.comment))
			}
		}
	}

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
	e firewallv1.EgressRule,
) (rules []ruleBase, updated firewallv1.EgressRule) {
	for i, fqdn := range e.ToFQDNs {
		fqdn.Sets = cache.GetSetsForFQDN(fqdn, true)
		e.ToFQDNs[i] = fqdn

		for _, set := range fqdn.Sets {
			rb := []string{"ip saddr == @cluster_prefixes"}
			rb = append(rb, fmt.Sprintf(string(set.Version)+" daddr @%s", set.SetName))
			rules = append(rules, ruleBase{comment: fmt.Sprintf(", fqdn: %s", fqdn.GetName()), base: rb})
		}
	}

	return rules, e
}

func calculatePorts(ports []networkingv1.NetworkPolicyPort) (tcpPorts, udpPorts []string) {
	for _, p := range ports {
		proto := proto(p.Protocol)
		portStr := fmt.Sprint(p.Port)
		if p.EndPort != nil {
			portStr = fmt.Sprintf("%s-%d", p.Port, *p.EndPort)
		}
		if proto == "tcp" {
			tcpPorts = append(tcpPorts, portStr)
		} else if proto == "udp" {
			udpPorts = append(udpPorts, portStr)
		}
	}
	return tcpPorts, udpPorts
}
