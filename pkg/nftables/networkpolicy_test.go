package nftables

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
	corev1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/pointer"
)

func port(p int) *intstr.IntOrString {
	intstr := intstr.FromInt(p)
	return &intstr
}

func TestClusterwideNetworkPolicyRules(t *testing.T) {
	tcp := corev1.ProtocolTCP
	udp := corev1.ProtocolUDP

	type want struct {
		ingress   nftablesRules
		egress    nftablesRules
		ingressAL nftablesRules
		egressAL  nftablesRules
	}

	tests := []struct {
		name  string
		input firewallv1.ClusterwideNetworkPolicy
		want  want
	}{
		{
			name: "policy with ingress and egress parts",
			input: firewallv1.ClusterwideNetworkPolicy{
				Spec: firewallv1.PolicySpec{
					Egress: []firewallv1.EgressRule{
						{
							To: []networking.IPBlock{
								{
									CIDR:   "1.1.0.0/24",
									Except: []string{"1.1.0.1"},
								},
								{
									CIDR: "1.1.1.0/24",
								},
							},
							Ports: []networking.NetworkPolicyPort{
								{
									Protocol: &tcp,
									Port:     port(53),
								},
								{
									Protocol: &udp,
									Port:     port(53),
								},
								{
									Protocol: &tcp,
									Port:     port(443),
									EndPort:  pointer.Int32(448),
								},
							},
						},
					},
					Ingress: []firewallv1.IngressRule{
						{
							From: []networking.IPBlock{
								{
									CIDR:   "1.1.0.0/24",
									Except: []string{"1.1.0.1"},
								},
							},
							Ports: []networking.NetworkPolicyPort{
								{
									Protocol: &tcp,
									Port:     port(80),
								},
								{
									Protocol: &tcp,
									Port:     port(443),
									EndPort:  pointer.Int32(448),
								},
							},
						},
					},
				},
			},
			want: want{
				ingress: nftablesRules{
					`ip saddr != { 1.1.0.1 } ip saddr { 1.1.0.0/24 } tcp dport { 80, 443-448 } counter accept comment "accept traffic for k8s network policy  tcp"`,
				},
				egress: nftablesRules{
					`ip saddr == @cluster_prefixes ip daddr != { 1.1.0.1 } ip daddr { 1.1.0.0/24, 1.1.1.0/24 } tcp dport { 53, 443-448 } counter accept comment "accept traffic for np  tcp"`,
					`ip saddr == @cluster_prefixes ip daddr != { 1.1.0.1 } ip daddr { 1.1.0.0/24, 1.1.1.0/24 } udp dport { 53 } counter accept comment "accept traffic for np  udp"`,
				},
				ingressAL: nftablesRules{
					`ip saddr != { 1.1.0.1 } ip saddr { 1.1.0.0/24 } tcp dport { 80, 443-448 } counter log prefix "nftables-firewall-accepted: " accept comment "accept traffic for k8s network policy  tcp"`,
				},
				egressAL: nftablesRules{
					`ip saddr == @cluster_prefixes ip daddr != { 1.1.0.1 } ip daddr { 1.1.0.0/24, 1.1.1.0/24 } tcp dport { 53, 443-448 } counter log prefix "nftables-firewall-accepted: " accept comment "accept traffic for np  tcp"`,
					`ip saddr == @cluster_prefixes ip daddr != { 1.1.0.1 } ip daddr { 1.1.0.0/24, 1.1.1.0/24 } udp dport { 53 } counter log prefix "nftables-firewall-accepted: " accept comment "accept traffic for np  udp"`,
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ingress, egress := clusterwideNetworkPolicyRules(tt.input, false)
			if !cmp.Equal(ingress, tt.want.ingress) {
				t.Errorf("clusterwideNetworkPolicyRules() ingress diff: %v", cmp.Diff(ingress, tt.want.ingress))
			}
			if !cmp.Equal(egress, tt.want.egress) {
				t.Errorf("clusterwideNetworkPolicyRules() egress diff: %v", cmp.Diff(egress, tt.want.egress))
			}
			ingressAL, egressAL := clusterwideNetworkPolicyRules(tt.input, true)
			if !cmp.Equal(ingressAL, tt.want.ingressAL) {
				t.Errorf("clusterwideNetworkPolicyRules() ingress with accessLog diff: %v", cmp.Diff(ingress, tt.want.ingress))
			}
			if !cmp.Equal(egressAL, tt.want.egressAL) {
				t.Errorf("clusterwideNetworkPolicyRules() egress with accessLog diff: %v", cmp.Diff(egress, tt.want.egress))
			}
		})
	}
}

func TestClusterwideNetworkPolicyEgressRules(t *testing.T) {
	tcp := corev1.ProtocolTCP
	udp := corev1.ProtocolUDP

	type want struct {
		egress   nftablesRules
		egressAL nftablesRules
	}

	tests := []struct {
		name  string
		input firewallv1.ClusterwideNetworkPolicy
		want  want
	}{
		{
			name: "multiple protocols, multiple ip block + exception egress policy",
			input: firewallv1.ClusterwideNetworkPolicy{
				Spec: firewallv1.PolicySpec{
					Egress: []firewallv1.EgressRule{
						{
							To: []networking.IPBlock{
								{
									CIDR:   "1.1.0.0/24",
									Except: []string{"1.1.0.1"},
								},
								{
									CIDR: "1.1.1.0/24",
								},
							},
							Ports: []networking.NetworkPolicyPort{
								{
									Protocol: &tcp,
									Port:     port(53),
								},
								{
									Protocol: &udp,
									Port:     port(53),
								},
							},
						},
					},
				},
			},
			want: want{
				egress: nftablesRules{
					`ip saddr == @cluster_prefixes ip daddr != { 1.1.0.1 } ip daddr { 1.1.0.0/24, 1.1.1.0/24 } tcp dport { 53 } counter accept comment "accept traffic for np  tcp"`,
					`ip saddr == @cluster_prefixes ip daddr != { 1.1.0.1 } ip daddr { 1.1.0.0/24, 1.1.1.0/24 } udp dport { 53 } counter accept comment "accept traffic for np  udp"`,
				},
				egressAL: nftablesRules{
					`ip saddr == @cluster_prefixes ip daddr != { 1.1.0.1 } ip daddr { 1.1.0.0/24, 1.1.1.0/24 } tcp dport { 53 } counter log prefix "nftables-firewall-accepted: " accept comment "accept traffic for np  tcp"`,
					`ip saddr == @cluster_prefixes ip daddr != { 1.1.0.1 } ip daddr { 1.1.0.0/24, 1.1.1.0/24 } udp dport { 53 } counter log prefix "nftables-firewall-accepted: " accept comment "accept traffic for np  udp"`,
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			egress := clusterwideNetworkPolicyEgressRules(tt.input, false)
			if !cmp.Equal(egress, tt.want.egress) {
				t.Errorf("clusterwideNetworkPolicyEgressRules() diff: %v", cmp.Diff(egress, tt.want.egress))
			}
			egressAL := clusterwideNetworkPolicyEgressRules(tt.input, true)
			if !cmp.Equal(egressAL, tt.want.egressAL) {
				t.Errorf("clusterwideNetworkPolicyEgressRules() with accessLog diff: %v", cmp.Diff(egressAL, tt.want.egressAL))
			}
		})
	}
}
