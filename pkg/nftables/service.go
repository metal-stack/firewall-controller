package nftables

import (
	"fmt"
	"net"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

func isCIDR(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	return err != nil
}

func isIP(ip string) bool {
	i := net.ParseIP(ip)
	return i != nil
}

// serviceRules generates nftables rules base on a k8s service definition
func serviceRules(svc corev1.Service) nftablesRules {
	if svc.Spec.Type != corev1.ServiceTypeLoadBalancer && svc.Spec.Type != corev1.ServiceTypeNodePort {
		return nil
	}

	from := []string{}
	for _, lbsr := range svc.Spec.LoadBalancerSourceRanges {
		if !isCIDR(lbsr) && !isIP(lbsr) {
			continue
		}
	}

	from = append(from, svc.Spec.LoadBalancerSourceRanges...)
	to := []string{}
	if svc.Spec.Type == corev1.ServiceTypeLoadBalancer {
		if svc.Spec.LoadBalancerIP != "" {
			if isIP(svc.Spec.LoadBalancerIP) {
				to = append(to, svc.Spec.LoadBalancerIP)
			}
		}
		for _, e := range svc.Status.LoadBalancer.Ingress {
			if isIP(e.IP) {
				to = append(to, e.IP)
			}
		}
	}

	// avoid empty rules
	if len(from) == 0 && len(to) == 0 {
		return nil
	}

	ruleBase := []string{}
	if len(from) > 0 {
		ruleBase = append(ruleBase, fmt.Sprintf("ip saddr { %s }", strings.Join(from, ", ")))
	}

	if len(to) > 0 {
		ruleBase = append(ruleBase, fmt.Sprintf("ip daddr { %s }", strings.Join(to, ", ")))
	}

	tcpPorts := []string{}
	udpPorts := []string{}
	for _, p := range svc.Spec.Ports {
		proto := proto(&p.Protocol)
		if proto == "tcp" {
			tcpPorts = append(tcpPorts, fmt.Sprint(p.Port))
		} else if proto == "udp" {
			udpPorts = append(udpPorts, fmt.Sprint(p.Port))
		}
	}
	comment := fmt.Sprintf("accept traffic for k8s service %s/%s", svc.ObjectMeta.Namespace, svc.ObjectMeta.Name)
	rules := nftablesRules{}
	if len(tcpPorts) > 0 {
		rules = append(rules, assembleDestinationPortRule(ruleBase, "tcp", tcpPorts, comment))
	}
	if len(udpPorts) > 0 {
		rules = append(rules, assembleDestinationPortRule(ruleBase, "udp", udpPorts, comment))
	}
	return uniqueSorted(rules)
}
