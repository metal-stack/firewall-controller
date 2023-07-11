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
	baseout []string
	basein  []string
}

// clusterwideNetworkPolicyRules generates nftables rules for a clusterwidenetworkpolicy
func clusterwideNetworkPolicyRules(
	cache FQDNCache,
	np firewallv1.ClusterwideNetworkPolicy,
	logAcceptedConnections bool,
) (ingress nftablesRules, egress nftablesRules, tcpmss nftablesRules, updated firewallv1.ClusterwideNetworkPolicy) {
	updated = np

	if len(np.Spec.Egress) > 0 {
		egress, tcpmss, updated = clusterwideNetworkPolicyEgressRules(cache, np, logAcceptedConnections)
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
) (rules nftablesRules, tcpmss nftablesRules, updated firewallv1.ClusterwideNetworkPolicy) {
	for _, e := range np.Spec.Egress {
		tcpPorts, udpPorts := calculatePorts(e.Ports)

		ruleBases := []ruleBase{}
		if len(e.To) > 0 {
			allow, except := clusterwideNetworkPolicyEgressToRules(e)
			rb := []string{"ip saddr == @cluster_prefixes"}
			rbmssout := []string{""}
			rbmssin := []string{""}
			if len(except) > 0 {
				rb = append(rb, fmt.Sprintf("ip daddr != { %s }", strings.Join(except, ", ")))
				rbmssout = append(rb, fmt.Sprintf("ip daddr != { %s }", strings.Join(except, ", ")))
				rbmssin = append(rb, fmt.Sprintf("ip saddr != { %s }", strings.Join(except, ", ")))
			}
			if len(allow) > 0 {
				if allow[0] != "0.0.0.0/0" {
					rb = append(rb, fmt.Sprintf("ip daddr { %s }", strings.Join(allow, ", ")))
					rbmssout = append(rb, fmt.Sprintf("ip daddr { %s }", strings.Join(allow, ", ")))
					rbmssin = append(rb, fmt.Sprintf("ip saddr { %s }", strings.Join(allow, ", ")))
				}
			}
			ruleBases = append(ruleBases, ruleBase{base: rb, baseout: rbmssin, basein: rbmssout})
		} else if len(e.ToFQDNs) > 0 && cache.IsInitialized() {
			// Generate allow rules based on DNS selectors
			rbs, u := clusterwideNetworkPolicyEgressToFQDNRules(cache, np.Status.FQDNState, e)
			np.Status.FQDNState = u
			ruleBases = append(ruleBases, rbs...)
		}

		comment := fmt.Sprintf("accept traffic for np %s", np.ObjectMeta.Name)
		for _, rb := range ruleBases {
			if len(tcpPorts) > 0 {
				rules = append(rules, assembleDestinationPortRule(rb.base, "tcp", tcpPorts, logAcceptedConnections, comment+" tcp"+rb.comment))
				if e.TcpMss != nil {
					tcpmss = append(tcpmss, fmt.Sprintf("%s tcp dport { %s } tcp flags syn tcp option maxseg size set %d", rb.baseout, strings.Join(tcpPorts, ", "), e.TcpMss))
					tcpmss = append(tcpmss, fmt.Sprintf("%s tcp sport { %s } tcp flags syn tcp option maxseg size set %d", rb.basein, strings.Join(tcpPorts, ", "), e.TcpMss))
				}
			} else {
				if e.TcpMss != nil {
					tcpmss = append(tcpmss, fmt.Sprintf("%s tcp flags syn tcp option maxseg size set %d", rb.baseout, e.TcpMss))
					tcpmss = append(tcpmss, fmt.Sprintf("%s tcp flags syn tcp option maxseg size set %d", rb.basein, e.TcpMss))
				}
			}
			if len(udpPorts) > 0 {
				rules = append(rules, assembleDestinationPortRule(rb.base, "udp", udpPorts, logAcceptedConnections, comment+" udp"+rb.comment))
			}
		}
	}

	return uniqueSorted(rules), uniqueSorted(tcpmss), np
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
	fqdnState firewallv1.FQDNState,
	e firewallv1.EgressRule,
) (rules []ruleBase, updatedState firewallv1.FQDNState) {
	if fqdnState == nil {
		fqdnState = firewallv1.FQDNState{}
	}

	for _, fqdn := range e.ToFQDNs {
		fqdnName := fqdn.MatchName
		if fqdnName == "" {
			fqdnName = fqdn.MatchPattern
		}

		fqdnState[fqdnName] = cache.GetSetsForFQDN(fqdn, fqdnState[fqdnName])
		for _, set := range fqdnState[fqdnName] {
			rb := []string{"ip saddr == @cluster_prefixes"}
			rb = append(rb, fmt.Sprintf(string(set.Version)+" daddr @%s", set.SetName))
			rules = append(rules, ruleBase{comment: fmt.Sprintf(", fqdn: %s", fqdn.GetName()), base: rb})
		}
	}

	return rules, fqdnState
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
