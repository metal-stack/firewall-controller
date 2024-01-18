package nftables

import (
	"fmt"
	"net"
	"strings"

	"github.com/metal-stack/firewall-controller/v2/pkg/helper"
	"go4.org/netipx"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/record"
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
func serviceRules(svc corev1.Service, allowed *netipx.IPSet, logAcceptedConnections bool, recorder record.EventRecorder) nftablesRules {
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
		to = appendServiceIP(to, svc, allowed, svc.Spec.LoadBalancerIP, recorder)
		for _, e := range svc.Status.LoadBalancer.Ingress {
			to = appendServiceIP(to, svc, allowed, e.IP, recorder)
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
		p := p
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
		rules = append(rules, assembleDestinationPortRule(ruleBase, "tcp", tcpPorts, logAcceptedConnections, comment))
	}
	if len(udpPorts) > 0 {
		rules = append(rules, assembleDestinationPortRule(ruleBase, "udp", udpPorts, logAcceptedConnections, comment))
	}
	return uniqueSorted(rules)
}

func appendServiceIP(to []string, svc corev1.Service, allowed *netipx.IPSet, ip string, recorder record.EventRecorder) []string {
	if ip != "" && isIP(ip) {
		if allowed != nil {
			// if there is an allowed-ipset restriction, we check if the given IP is contained in this set
			if ok, _ := helper.ValidateCIDR(&svc, ip+"/32", allowed, recorder); ok {
				to = append(to, ip)
			}
		} else {
			to = append(to, ip)
		}
	}
	return to
}
