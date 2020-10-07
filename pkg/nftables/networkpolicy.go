package nftables

import (
	"fmt"
	"strings"

	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
)

// clusterwideNetworkPolicyRules generates nftables rules for a clusterwidenetworkpolicy
func clusterwideNetworkPolicyRules(np firewallv1.ClusterwideNetworkPolicy) (nftablesRules, nftablesRules) {
	ingress, egress := nftablesRules{}, nftablesRules{}
	if len(np.Spec.Egress) > 0 {
		egress = append(egress, clusterwideNetworkPolicyEgressRules(np)...)
	}
	if len(np.Spec.Ingress) > 0 {
		ingress = append(ingress, clusterwideNetworkPolicyIngressRules(np)...)
	}
	return ingress, egress
}

func clusterwideNetworkPolicyIngressRules(np firewallv1.ClusterwideNetworkPolicy) nftablesRules {
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
		tcpPorts := []string{}
		udpPorts := []string{}
		for _, p := range i.Ports {
			proto := proto(p.Protocol)
			if proto == "tcp" {
				tcpPorts = append(tcpPorts, fmt.Sprint(p.Port))
			} else if proto == "udp" {
				udpPorts = append(udpPorts, fmt.Sprint(p.Port))
			}
		}
		comment := fmt.Sprintf("accept traffic for k8s network policy %s", np.ObjectMeta.Name)
		if len(tcpPorts) > 0 {
			rules = append(rules, assembleDestinationPortRule(common, "tcp", tcpPorts, comment+" tcp"))
		}
		if len(udpPorts) > 0 {
			rules = append(rules, assembleDestinationPortRule(common, "udp", udpPorts, comment+" udp"))
		}
	}
	return uniqueSorted(rules)
}

func clusterwideNetworkPolicyEgressRules(np firewallv1.ClusterwideNetworkPolicy) nftablesRules {
	egress := np.Spec.Egress
	if egress == nil {
		return nil
	}
	rules := nftablesRules{}
	for _, e := range egress {
		tcpPorts := []string{}
		udpPorts := []string{}
		for _, p := range e.Ports {
			proto := proto(p.Protocol)
			if proto == "tcp" {
				tcpPorts = append(tcpPorts, fmt.Sprint(p.Port))
			} else if proto == "udp" {
				udpPorts = append(udpPorts, fmt.Sprint(p.Port))
			}
		}
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
			rules = append(rules, assembleDestinationPortRule(ruleBase, "tcp", tcpPorts, comment+" tcp"))
		}
		if len(udpPorts) > 0 {
			rules = append(rules, assembleDestinationPortRule(ruleBase, "udp", udpPorts, comment+" udp"))
		}
	}
	return uniqueSorted(rules)
}
