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
	allow := []string{}
	if len(svc.Spec.LoadBalancerSourceRanges) == 0 {
		allow = append(allow, "0.0.0.0/0")
	}
	allow = append(allow, svc.Spec.LoadBalancerSourceRanges...)
	common := []string{}
	if len(allow) > 0 {
		common = append(common, fmt.Sprintf("ip saddr { %s }", strings.Join(allow, ", ")))
	}
	ips := []string{}
	if svc.Spec.LoadBalancerIP != "" {
		ips = append(ips, svc.Spec.LoadBalancerIP)
	}
	for _, e := range svc.Status.LoadBalancer.Ingress {
		ips = append(ips, e.IP)
	}
	common = append(common, fmt.Sprintf("ip daddr { %s }", strings.Join(ips, ", ")))
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
		rules = append(rules, assembleDestinationPortRule(common, "tcp", tcpPorts, comment))
	}
	if len(udpPorts) > 0 {
		rules = append(rules, assembleDestinationPortRule(common, "udp", udpPorts, comment))
	}
	return rules
}
