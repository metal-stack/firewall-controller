package nftables

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"

	firewallv1 "github.com/metal-stack/firewall-controller/v2/api/v1"
	mocks "github.com/metal-stack/firewall-controller/v2/pkg/nftables/mocks/pkg/nftables"
)

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
							Ports: []firewallv1.NetworkPolicyPort{
								{
									Protocol: &tcp,
									Port:     int32(53),
								},
								{
									Protocol: &udp,
									Port:     int32(53),
								},
								{
									Protocol: &tcp,
									Port:     int32(443),
									EndPort:  new(int32(448)),
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
							Ports: []firewallv1.NetworkPolicyPort{
								{
									Protocol: &tcp,
									Port:     int32(80),
								},
								{
									Protocol: &tcp,
									Port:     int32(443),
									EndPort:  new(int32(448)),
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
					`ip saddr != { 1.1.0.1 } ip saddr { 1.1.0.0/24 } tcp dport { 80, 443-448 } log prefix "nftables-firewall-accepted: " limit rate 10/second` + "\n" + `ip saddr != { 1.1.0.1 } ip saddr { 1.1.0.0/24 } tcp dport { 80, 443-448 } counter accept comment "accept traffic for k8s network policy  tcp"`,
				},
				egressAL: nftablesRules{
					`ip saddr == @cluster_prefixes ip daddr != { 1.1.0.1 } ip daddr { 1.1.0.0/24, 1.1.1.0/24 } tcp dport { 53, 443-448 } log prefix "nftables-firewall-accepted: " limit rate 10/second` + "\n" + `ip saddr == @cluster_prefixes ip daddr != { 1.1.0.1 } ip daddr { 1.1.0.0/24, 1.1.1.0/24 } tcp dport { 53, 443-448 } counter accept comment "accept traffic for np  tcp"`,
					`ip saddr == @cluster_prefixes ip daddr != { 1.1.0.1 } ip daddr { 1.1.0.0/24, 1.1.1.0/24 } udp dport { 53 } log prefix "nftables-firewall-accepted: " limit rate 10/second` + "\n" + `ip saddr == @cluster_prefixes ip daddr != { 1.1.0.1 } ip daddr { 1.1.0.0/24, 1.1.1.0/24 } udp dport { 53 } counter accept comment "accept traffic for np  udp"`,
				},
			},
		},
	}
	for _, tt := range tests {
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
		record func(*mocks.FQDNCache)
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
							Ports: []firewallv1.NetworkPolicyPort{
								{
									Protocol: &tcp,
									Port:     int32(53),
								},
								{
									Protocol: &udp,
									Port:     int32(53),
								},
							},
						},
					},
				},
			},
			record: func(cache *mocks.FQDNCache) {},
			want: want{
				egress: nftablesRules{
					`ip saddr == @cluster_prefixes ip daddr != { 1.1.0.1 } ip daddr { 1.1.0.0/24, 1.1.1.0/24 } tcp dport { 53 } counter accept comment "accept traffic for np  tcp"`,
					`ip saddr == @cluster_prefixes ip daddr != { 1.1.0.1 } ip daddr { 1.1.0.0/24, 1.1.1.0/24 } udp dport { 53 } counter accept comment "accept traffic for np  udp"`,
				},
				egressAL: nftablesRules{
					`ip saddr == @cluster_prefixes ip daddr != { 1.1.0.1 } ip daddr { 1.1.0.0/24, 1.1.1.0/24 } tcp dport { 53 } log prefix "nftables-firewall-accepted: " limit rate 10/second` + "\n" + `ip saddr == @cluster_prefixes ip daddr != { 1.1.0.1 } ip daddr { 1.1.0.0/24, 1.1.1.0/24 } tcp dport { 53 } counter accept comment "accept traffic for np  tcp"`,
					`ip saddr == @cluster_prefixes ip daddr != { 1.1.0.1 } ip daddr { 1.1.0.0/24, 1.1.1.0/24 } udp dport { 53 } log prefix "nftables-firewall-accepted: " limit rate 10/second` + "\n" + `ip saddr == @cluster_prefixes ip daddr != { 1.1.0.1 } ip daddr { 1.1.0.0/24, 1.1.1.0/24 } udp dport { 53 } counter accept comment "accept traffic for np  udp"`,
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
							Ports: []firewallv1.NetworkPolicyPort{
								{
									Protocol: &tcp,
									Port:     int32(53),
								},
								{
									Protocol: &udp,
									Port:     int32(53),
								},
							},
						},
					},
				},
			},
			record: func(cache *mocks.FQDNCache) {
				cache.
					On("IsInitialized").
					Return(true)
				cache.
					On("GetSetsForFQDN", firewallv1.FQDNSelector{MatchName: "test.com"}).
					Return([]firewallv1.IPSet{{SetName: "test", Version: firewallv1.IPv4}})
				cache.
					On("GetSetsForFQDN", firewallv1.FQDNSelector{MatchPattern: "*.test.com"}).
					Return([]firewallv1.IPSet{{SetName: "test2", Version: firewallv1.IPv6}})
			},
			want: want{
				egress: nftablesRules{
					`ip saddr == @cluster_prefixes ip daddr @test tcp dport { 53 } counter accept comment "accept traffic for np  tcp, fqdn: test.com"`,
					`ip saddr == @cluster_prefixes ip daddr @test udp dport { 53 } counter accept comment "accept traffic for np  udp, fqdn: test.com"`,
					`ip6 saddr == @cluster_prefixes6 ip6 daddr @test2 tcp dport { 53 } counter accept comment "accept traffic for np  tcp, fqdn: *.test.com"`,
					`ip6 saddr == @cluster_prefixes6 ip6 daddr @test2 udp dport { 53 } counter accept comment "accept traffic for np  udp, fqdn: *.test.com"`,
				},
			},
		},

		{
			name: "allow to any ipv4",
			input: firewallv1.ClusterwideNetworkPolicy{
				Spec: firewallv1.PolicySpec{
					Egress: []firewallv1.EgressRule{
						{
							To: []networking.IPBlock{
								{
									CIDR:   "0.0.0.0/0",
									Except: []string{"1.1.0.1"},
								},
								{
									CIDR: "1.1.0.0/24",
								},
							},
							Ports: []firewallv1.NetworkPolicyPort{
								{
									Protocol: &tcp,
									Port:     int32(443),
								},
							},
						},
					},
				},
			},
			record: func(cache *mocks.FQDNCache) {},
			want: want{
				// an IPv4 any destination must not be added as a daddr set
				egress: nftablesRules{
					`ip saddr == @cluster_prefixes ip daddr != { 1.1.0.1 } tcp dport { 443 } counter accept comment "accept traffic for np  tcp"`,
				},
				egressAL: nftablesRules{
					`ip saddr == @cluster_prefixes ip daddr != { 1.1.0.1 } tcp dport { 443 } log prefix "nftables-firewall-accepted: " limit rate 10/second` + "\n" + `ip saddr == @cluster_prefixes ip daddr != { 1.1.0.1 } tcp dport { 443 } counter accept comment "accept traffic for np  tcp"`,
				},
			},
		},
		{
			name: "allow to any ipv6",
			input: firewallv1.ClusterwideNetworkPolicy{
				Spec: firewallv1.PolicySpec{
					Egress: []firewallv1.EgressRule{
						{
							To: []networking.IPBlock{
								{
									CIDR:   "::/0",
									Except: []string{"2001:db8::/32"},
								},
							},
							Ports: []firewallv1.NetworkPolicyPort{
								{
									Protocol: &tcp,
									Port:     int32(443),
								},
							},
						},
					},
				},
			},
			record: func(cache *mocks.FQDNCache) {},
			want: want{
				// an IPv6 any destination must not be added as a daddr set, and
				// the exception must use the ip6 keyword
				egress: nftablesRules{
					`ip6 saddr == @cluster_prefixes6 ip6 daddr != { 2001:db8::/32 } tcp dport { 443 } counter accept comment "accept traffic for np  tcp"`,
				},
				egressAL: nftablesRules{
					`ip6 saddr == @cluster_prefixes6 ip6 daddr != { 2001:db8::/32 } tcp dport { 443 } log prefix "nftables-firewall-accepted: " limit rate 10/second` + "\n" + `ip6 saddr == @cluster_prefixes6 ip6 daddr != { 2001:db8::/32 } tcp dport { 443 } counter accept comment "accept traffic for np  tcp"`,
				},
			},
		},
		{
			name: "multiple ipv6 ip blocks with exception",
			input: firewallv1.ClusterwideNetworkPolicy{
				Spec: firewallv1.PolicySpec{
					Egress: []firewallv1.EgressRule{
						{
							To: []networking.IPBlock{
								{
									CIDR:   "2001:db8::/32",
									Except: []string{"2001:db8:1::1"},
								},
								{
									CIDR: "2001:db9::/32",
								},
							},
							Ports: []firewallv1.NetworkPolicyPort{
								{
									Protocol: &tcp,
									Port:     int32(443),
								},
							},
						},
					},
				},
			},
			record: func(cache *mocks.FQDNCache) {},
			want: want{
				egress: nftablesRules{
					`ip6 saddr == @cluster_prefixes6 ip6 daddr != { 2001:db8:1::1 } ip6 daddr { 2001:db8::/32, 2001:db9::/32 } tcp dport { 443 } counter accept comment "accept traffic for np  tcp"`,
				},
			},
		},
		{
			name: "mixed ipv4 and ipv6 destinations",
			input: firewallv1.ClusterwideNetworkPolicy{
				Spec: firewallv1.PolicySpec{
					Egress: []firewallv1.EgressRule{
						{
							To: []networking.IPBlock{
								{
									CIDR: "1.1.0.0/24",
								},
								{
									CIDR: "2001:db8::/32",
								},
							},
							Ports: []firewallv1.NetworkPolicyPort{
								{
									Protocol: &tcp,
									Port:     int32(443),
								},
							},
						},
					},
				},
			},
			record: func(cache *mocks.FQDNCache) {},
			want: want{
				// one rule per address family, each with the correct keyword
				egress: nftablesRules{
					`ip saddr == @cluster_prefixes ip daddr { 1.1.0.0/24 } tcp dport { 443 } counter accept comment "accept traffic for np  tcp"`,
					`ip6 saddr == @cluster_prefixes6 ip6 daddr { 2001:db8::/32 } tcp dport { 443 } counter accept comment "accept traffic for np  tcp"`,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fqdnCache := mocks.NewFQDNCache(t)
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
