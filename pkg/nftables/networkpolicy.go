package nftables

import (
	"fmt"
	"strings"

	networkingv1 "k8s.io/api/networking/v1"

	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
)

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

		// Generate allow/except rules
		allow := []string{}
		except := []string{}
		if len(e.To) > 0 {
			allow, except = clusterwideNetworkPolicyEgressToRules(e)
		} else if len(e.ToFQDNs) > 0 {
			// Generate allow rules based on DNS selectors
			allow, np.Spec.Egress[i] = clusterwideNetworkPolicyEgressToFQDNRules(cache, e)
		}

		ruleBases := [][]string{}
		if len(e.To) > 0 {
			rb := []string{"ip saddr == @cluster_prefixes"}
			if len(except) > 0 {
				rb = append(rb, fmt.Sprintf("ip daddr != { %s }", strings.Join(except, ", ")))
			}
			if len(allow) > 0 {
				if allow[0] != "0.0.0.0/0" {
					rb = append(rb, fmt.Sprintf("ip daddr { %s }", strings.Join(allow, ", ")))
				}
			}
			ruleBases = append(ruleBases, rb)
		} else {
			for _, a := range allow {
				rb := []string{"ip saddr == @cluster_prefixes"}
				rb = append(rb, fmt.Sprintf("ip daddr @%s", a))
				ruleBases = append(ruleBases, rb)
			}
		}

		comment := fmt.Sprintf("accept traffic for np %s", np.ObjectMeta.Name)
		for _, rb := range ruleBases {
			if len(tcpPorts) > 0 {
				rules = append(rules, assembleDestinationPortRule(rb, "tcp", tcpPorts, logAcceptedConnections, comment+" tcp"))
			}
			if len(udpPorts) > 0 {
				rules = append(rules, assembleDestinationPortRule(rb, "udp", udpPorts, logAcceptedConnections, comment+" udp"))
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

func clusterwideNetworkPolicyEgressToFQDNRules(cache FQDNCache, e firewallv1.EgressRule) (allow []string, updated firewallv1.EgressRule) {
	for i, fqdn := range e.ToFQDNs {
		fqdn.Sets = cache.GetSetsForFQDN(fqdn)
		allow = append(allow, fqdn.Sets...)
		e.ToFQDNs[i] = fqdn
	}

	return allow, e
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
