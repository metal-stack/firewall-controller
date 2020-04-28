package nftables

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"text/template"

	firewallv1 "github.com/metal-stack/firewall-builder/api/v1"
	corev1 "k8s.io/api/core/v1"
)

// FirewallResources holds the k8s entities that serve as input for the generation of firewall rules.
type FirewallResources struct {
	NetworkPolicyList *firewallv1.ClusterwideNetworkPolicyList
	ServiceList       *corev1.ServiceList
}

// FirewallRules hold the nftable rules that are generated from k8s entities.
type FirewallRules struct {
	IngressRules []string
	EgressRules  []string
}

func (fr *FirewallResources) AssembleRules() *FirewallRules {
	result := &FirewallRules{}
	for _, np := range fr.NetworkPolicyList.Items {
		if len(np.Spec.Egress) > 0 {
			result.EgressRules = append(result.EgressRules, egressRulesForNetworkPolicy(np)...)
		}
		if len(np.Spec.Ingress) > 0 {
			result.IngressRules = append(result.IngressRules, ingressRulesForNetworkPolicy(np)...)
		}
	}
	for _, svc := range fr.ServiceList.Items {
		result.IngressRules = append(result.IngressRules, ingressRulesForService(svc)...)
	}
	result.EgressRules = uniqueSorted(result.EgressRules)
	result.IngressRules = uniqueSorted(result.IngressRules)
	return result
}

// HasChanged checks whether new firewall rules have changed in comparison to the last run
func (r *FirewallRules) HasChanged(oldRules *FirewallRules) bool {
	if oldRules == nil {
		return true
	}

	if len(r.IngressRules) != len(oldRules.IngressRules) {
		return true
	}

	if len(r.EgressRules) != len(oldRules.EgressRules) {
		return true
	}

	for k, v := range r.IngressRules {
		if oldRules.IngressRules[k] != v {
			return true
		}
	}

	for k, v := range r.EgressRules {
		if oldRules.EgressRules[k] != v {
			return true
		}
	}

	return false
}

func uniqueSorted(elements []string) []string {
	t := map[string]bool{}
	for _, e := range elements {
		t[e] = true
	}
	r := []string{}
	for k := range t {
		r = append(r, k)
	}
	sort.Strings(r)
	return r
}

// Render renders the firewall rules to a string
func (r *FirewallRules) Render() (string, error) {
	var b bytes.Buffer
	tpl := template.Must(template.New("v4").Parse(nftableTemplateIpv4))
	err := tpl.Execute(&b, r)
	if err != nil {
		return "", err
	}
	return b.String(), nil
}

func ingressRulesForNetworkPolicy(np firewallv1.ClusterwideNetworkPolicy) []string {
	ingress := np.Spec.Ingress
	if ingress == nil {
		return nil
	}
	if np.ObjectMeta.Namespace != "" {
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

func ingressRulesForService(svc corev1.Service) []string {
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

func egressRulesForNetworkPolicy(np firewallv1.ClusterwideNetworkPolicy) []string {
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
		common := []string{}
		if len(except) > 0 {
			common = append(common, fmt.Sprintf("ip daddr != { %s }", strings.Join(except, ", ")))
		}
		if len(allow) > 0 {
			common = append(common, fmt.Sprintf("ip daddr { %s }", strings.Join(allow, ", ")))
		}
		comment := fmt.Sprintf("accept traffic for np %s", np.ObjectMeta.Name)
		if len(tcpPorts) > 0 {
			rules = append(rules, assembleDestinationPortRule(common, "tcp", tcpPorts, comment+" tcp"))
		}
		if len(udpPorts) > 0 {
			rules = append(rules, assembleDestinationPortRule(common, "udp", udpPorts, comment+" udp"))
		}
	}
	return rules
}

func assembleDestinationPortRule(common []string, protocol string, ports []string, comment string) string {
	parts := common
	parts = append(parts, fmt.Sprintf("%s dport { %s }", protocol, strings.Join(ports, ", ")))
	parts = append(parts, "counter")
	parts = append(parts, "accept")
	if comment != "" {
		parts = append(parts, "comment", fmt.Sprintf(`"%s"`, comment))
	}
	return strings.Join(parts, " ")
}

func proto(p *corev1.Protocol) string {
	proto := "tcp"
	if p != nil {
		proto = strings.ToLower(string(*p))
	}
	return proto
}
