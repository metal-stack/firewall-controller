package nftables

import (
	"fmt"
	"strings"

	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
)

func ingressForNetworkPolicy(np firewallv1.ClusterwideNetworkPolicy) []string {
	ingress := np.Spec.Ingress
	if ingress == nil {
		return nil
	}
	rules := []string{}
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
	return rules
}

func egressForNetworkPolicy(np firewallv1.ClusterwideNetworkPolicy, podLister podLister) []string {
	egress := np.Spec.Egress
	if egress == nil {
		return nil
	}
	rules := []string{}
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
		if podLister != nil && len(e.MatchLabels) > 0 {
			pods := podLister(e.MatchLabels)
			podIPs := []string{}
			for _, p := range pods.Items {
				podIPs = append(podIPs, fmt.Sprintf("%s/32", p.Status.PodIP))
			}
			if len(podIPs) > 0 {
				ruleBase = []string{fmt.Sprintf("ip saddr { %s }", strings.Join(podIPs, ", "))}
			}
		}
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
	return rules
}
