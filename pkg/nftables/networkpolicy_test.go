package nftables

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/pointer"

	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
	"github.com/metal-stack/firewall-controller/pkg/nftables/mocks"
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
					`ip saddr != { 1.1.0.1 } ip saddr { 1.1.0.0/24 } tcp dport { 80, 443-448 } log prefix "nftables-firewall-accepted: " limit rate 10/second`,
					`ip saddr != { 1.1.0.1 } ip saddr { 1.1.0.0/24 } tcp dport { 80, 443-448 } counter accept comment "accept traffic for k8s network policy  tcp"`,
				},
				egressAL: nftablesRules{
					`ip saddr == @cluster_prefixes ip daddr != { 1.1.0.1 } ip daddr { 1.1.0.0/24, 1.1.1.0/24 } tcp dport { 53, 443-448 } log prefix "nftables-firewall-accepted: " limit rate 10/second`,
					`ip saddr == @cluster_prefixes ip daddr != { 1.1.0.1 } ip daddr { 1.1.0.0/24, 1.1.1.0/24 } tcp dport { 53, 443-448 } counter accept comment "accept traffic for np  tcp"`,
					`ip saddr == @cluster_prefixes ip daddr != { 1.1.0.1 } ip daddr { 1.1.0.0/24, 1.1.1.0/24 } udp dport { 53 } log prefix "nftables-firewall-accepted: " limit rate 10/second`,
					`ip saddr == @cluster_prefixes ip daddr != { 1.1.0.1 } ip daddr { 1.1.0.0/24, 1.1.1.0/24 } udp dport { 53 } counter accept comment "accept traffic for np  udp"`,
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ingress, egress, _ := clusterwideNetworkPolicyRules(nil, tt.input, false)
			if !cmp.Equal(ingress, tt.want.ingress) {
				t.Errorf("clusterwideNetworkPolicyRules() ingress diff: %v", cmp.Diff(ingress, tt.want.ingress))
			}
			if !cmp.Equal(egress, tt.want.egress) {
				t.Errorf("clusterwideNetworkPolicyRules() egress diff: %v", cmp.Diff(egress, tt.want.egress))
			}

			ingressAL, egressAL, _ := clusterwideNetworkPolicyRules(nil, tt.input, true)
			if !cmp.Equal(ingressAL, tt.want.ingressAL) {
				t.Errorf("clusterwideNetworkPolicyRules() ingress with accessLog diff: %v", cmp.Diff(ingressAL, tt.want.ingressAL))
			}
			if !cmp.Equal(egressAL, tt.want.egressAL) {
				t.Errorf("clusterwideNetworkPolicyRules() egress with accessLog diff: %v", cmp.Diff(egressAL, tt.want.egressAL))
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
		name   string
		input  firewallv1.ClusterwideNetworkPolicy
		record func(*mocks.MockFQDNCache)
		want   want
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
			record: func(cache *mocks.MockFQDNCache) {},
			want: want{
				egress: nftablesRules{
					`ip saddr == @cluster_prefixes ip daddr != { 1.1.0.1 } ip daddr { 1.1.0.0/24, 1.1.1.0/24 } tcp dport { 53 } counter accept comment "accept traffic for np  tcp"`,
					`ip saddr == @cluster_prefixes ip daddr != { 1.1.0.1 } ip daddr { 1.1.0.0/24, 1.1.1.0/24 } udp dport { 53 } counter accept comment "accept traffic for np  udp"`,
				},
				egressAL: nftablesRules{
					`ip saddr == @cluster_prefixes ip daddr != { 1.1.0.1 } ip daddr { 1.1.0.0/24, 1.1.1.0/24 } tcp dport { 53 } log prefix "nftables-firewall-accepted: " limit rate 10/second`,
					`ip saddr == @cluster_prefixes ip daddr != { 1.1.0.1 } ip daddr { 1.1.0.0/24, 1.1.1.0/24 } tcp dport { 53 } counter accept comment "accept traffic for np  tcp"`,
					`ip saddr == @cluster_prefixes ip daddr != { 1.1.0.1 } ip daddr { 1.1.0.0/24, 1.1.1.0/24 } udp dport { 53 } log prefix "nftables-firewall-accepted: " limit rate 10/second`,
					`ip saddr == @cluster_prefixes ip daddr != { 1.1.0.1 } ip daddr { 1.1.0.0/24, 1.1.1.0/24 } udp dport { 53 } counter accept comment "accept traffic for np  udp"`,
				},
			},
		},
		{
			name: "DNS based egress policies",
			input: firewallv1.ClusterwideNetworkPolicy{
				Spec: firewallv1.PolicySpec{
					Egress: []firewallv1.EgressRule{
						{
							ToFQDNs: []firewallv1.FQDNSelector{
								{
									MatchName: "test.com",
								},
								{
									MatchPattern: "*.test.com",
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
			record: func(cache *mocks.MockFQDNCache) {
				cache.
					EXPECT().
					GetSetsForFQDN(gomock.Any(), true).
					Return([]firewallv1.IPSet{{SetName: "test", Version: firewallv1.IPv4}})
				cache.
					EXPECT().
					GetSetsForFQDN(gomock.Any(), true).
					Return([]firewallv1.IPSet{{SetName: "test2", Version: firewallv1.IPv6}})
			},
			want: want{
				egress: nftablesRules{
					`ip saddr == @cluster_prefixes ip daddr @test tcp dport { 53 } counter accept comment "accept traffic for np  tcp, fqdn: test.com"`,
					`ip saddr == @cluster_prefixes ip daddr @test udp dport { 53 } counter accept comment "accept traffic for np  udp, fqdn: test.com"`,
					`ip saddr == @cluster_prefixes ip6 daddr @test2 tcp dport { 53 } counter accept comment "accept traffic for np  tcp, fqdn: *.test.com"`,
					`ip saddr == @cluster_prefixes ip6 daddr @test2 udp dport { 53 } counter accept comment "accept traffic for np  udp, fqdn: *.test.com"`,
				},
			},
		},
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	fqdnCache := mocks.NewMockFQDNCache(ctrl)
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			tt.record(fqdnCache)
			if len(tt.want.egress) > 0 {
				egress, _ := clusterwideNetworkPolicyEgressRules(fqdnCache, tt.input, false)
				if !cmp.Equal(egress, tt.want.egress) {
					t.Errorf("clusterwideNetworkPolicyEgressRules() diff: %v", cmp.Diff(egress, tt.want.egress))
				}
			}

			if len(tt.want.egressAL) > 0 {
				egressAL, _ := clusterwideNetworkPolicyEgressRules(fqdnCache, tt.input, true)
				if !cmp.Equal(egressAL, tt.want.egressAL) {
					t.Errorf("clusterwideNetworkPolicyEgressRules() with accessLog diff: %v", cmp.Diff(egressAL, tt.want.egressAL))
				}
			}
		})
	}
}
