package nftables

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

func ingressForService(svc corev1.Service) []string {
	if svc.Spec.Type != corev1.ServiceTypeLoadBalancer && svc.Spec.Type != corev1.ServiceTypeNodePort {
		return nil
	}

	from := []string{svc.Spec.LoadBalancerSourceRanges}
	to := []string{}
	if svc.Spec.Type == corev1.ServiceTypeLoadBalancer {
		if svc.Spec.LoadBalancerIP != "" {
			to = append(to, svc.Spec.LoadBalancerIP)
		}
		for _, e := range svc.Status.LoadBalancer.Ingress {
			to = append(to, e.IP)
		}
	}

	// avoid empty rules
	if len(from) == 0 and len(to) == 0 {
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
	rules := []string{}
	if len(tcpPorts) > 0 {
		rules = append(rules, assembleDestinationPortRule(ruleBase, "tcp", tcpPorts, comment))
	}
	if len(udpPorts) > 0 {
		rules = append(rules, assembleDestinationPortRule(ruleBase, "udp", udpPorts, comment))
	}
	return rules
}
