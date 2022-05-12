package nftables

import (
	"fmt"
	"strings"

	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
	networkingv1 "k8s.io/api/networking/v1"
)

// clusterwideNetworkPolicyRules generates nftables rules for a clusterwidenetworkpolicy
func clusterwideNetworkPolicyRules(np firewallv1.ClusterwideNetworkPolicy, logAcceptedConnections bool) (nftablesRules, nftablesRules) {
	ingress, egress := nftablesRules{}, nftablesRules{}
	if len(np.Spec.Egress) > 0 {
		egress = append(egress, clusterwideNetworkPolicyEgressRules(np, logAcceptedConnections)...)
	}
	if len(np.Spec.Ingress) > 0 {
		ingress = append(ingress, clusterwideNetworkPolicyIngressRules(np, logAcceptedConnections)...)
	}
	return ingress, egress
}

func clusterwideNetworkPolicyIngressRules(np firewallv1.ClusterwideNetworkPolicy, logAcceptedConnections bool) nftablesRules {
	ingress := np.Spec.Ingress
	if ingress == nil {
		return nil
	}
	rules := nftablesRules{}
	for _, i := range ingress {
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

func clusterwideNetworkPolicyEgressRules(np firewallv1.ClusterwideNetworkPolicy, logAcceptedConnections bool) nftablesRules {
	egress := np.Spec.Egress
	if egress == nil {
		return nil
	}
	rules := nftablesRules{}
	for _, e := range egress {
		tcpPorts, udpPorts := calculatePorts(e.Ports)
		allow := []string{}
		except := []string{}
		for _, ipBlock := range e.To {
			allow = append(allow, ipBlock.CIDR)
			except = append(except, ipBlock.Except...)
		}
		ruleBase := []string{"ip saddr == @cluster_prefixes"}
		if len(except) > 0 {
			ruleBase = append(ruleBase, fmt.Sprintf("ip daddr != { %s }", strings.Join(except, ", ")))
		}
		if len(allow) > 0 {
			if allow[0] != "0.0.0.0/0" {
				ruleBase = append(ruleBase, fmt.Sprintf("ip daddr { %s }", strings.Join(allow, ", ")))
			}
		}
		comment := fmt.Sprintf("accept traffic for np %s", np.ObjectMeta.Name)
		if len(tcpPorts) > 0 {
			rules = append(rules, assembleDestinationPortRule(ruleBase, "tcp", tcpPorts, logAcceptedConnections, comment+" tcp"))
		}
		if len(udpPorts) > 0 {
			rules = append(rules, assembleDestinationPortRule(ruleBase, "udp", udpPorts, logAcceptedConnections, comment+" udp"))
		}
	}
	return uniqueSorted(rules)
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
