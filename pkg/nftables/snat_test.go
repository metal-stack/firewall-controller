package nftables

import (
	"errors"
	"testing"

	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
	mn "github.com/metal-stack/metal-lib/pkg/net"
	corev1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"

	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
)

func TestSnatRules(t *testing.T) {
	tcp := corev1.ProtocolTCP
	udp := corev1.ProtocolUDP
	private := "private"
	internet := "internet"
	mpls := "mpls"
	underlay := "underlay"
	vrf1 := int64(1)
	vrf2 := int64(2)
	privatePrimary := mn.PrivatePrimaryShared
	external := mn.External
	underlayNet := mn.Underlay
	tests := []struct {
		name    string
		input   firewallv1.FirewallSpec
		cwnps   firewallv1.ClusterwideNetworkPolicyList
		want    nftablesRules
		wantErr bool
		err     error
	}{
		{
			name: "snat for multiple networks",
			input: firewallv1.FirewallSpec{
				Data: firewallv1.Data{
					FirewallNetworks: []firewallv1.FirewallNetwork{
						{
							Networkid:   &private,
							Prefixes:    []string{"10.0.1.0/24"},
							Ips:         []string{"10.0.1.1"},
							Networktype: &privatePrimary,
						},
						{
							Networkid:   &internet,
							Prefixes:    []string{"185.0.0.0/24"},
							Ips:         []string{"185.0.0.1"},
							Vrf:         &vrf1,
							Networktype: &external,
						},
						{
							Networkid:   &mpls,
							Prefixes:    []string{"100.0.0.0/24"},
							Ips:         []string{"100.0.0.1"},
							Vrf:         &vrf2,
							Networktype: &external,
						},
					},
					EgressRules: []firewallv1.EgressRuleSNAT{
						{
							NetworkID: "internet",
							IPs:       []string{"185.0.0.2", "185.0.0.3"},
						}, {
							NetworkID: "mpls",
							IPs:       []string{"100.0.0.2"},
						},
					},
				},
			},
			cwnps: firewallv1.ClusterwideNetworkPolicyList{},
			want: nftablesRules{
				`ip saddr { 10.0.1.0/24 } oifname "vlan1" counter snat to jhash ip daddr . tcp sport mod 2 map { 0 : 185.0.0.2, 1 : 185.0.0.3 } comment "snat for internet"`,
				`ip saddr { 10.0.1.0/24 } oifname "vlan2" counter snat 100.0.0.2 comment "snat for mpls"`,
			},
		},
		{
			name: "escape DNS for dns-based CWNPs",
			input: firewallv1.FirewallSpec{
				Data: firewallv1.Data{
					FirewallNetworks: []firewallv1.FirewallNetwork{
						{
							Networkid:   &private,
							Prefixes:    []string{"10.0.1.0/24"},
							Ips:         []string{"10.0.1.1"},
							Networktype: &privatePrimary,
						},
						{
							Networkid:   &internet,
							Prefixes:    []string{"185.0.0.0/24"},
							Ips:         []string{"185.0.0.1"},
							Vrf:         &vrf1,
							Networktype: &external,
						},
						{
							Networkid:   &mpls,
							Prefixes:    []string{"100.0.0.0/24"},
							Ips:         []string{"100.0.0.1"},
							Vrf:         &vrf2,
							Networktype: &external,
						},
					},
					EgressRules: []firewallv1.EgressRuleSNAT{
						{
							NetworkID: "internet",
							IPs:       []string{"185.0.0.2", "185.0.0.3"},
						}, {
							NetworkID: "mpls",
							IPs:       []string{"100.0.0.2"},
						},
					},
				},
			},
			cwnps: firewallv1.ClusterwideNetworkPolicyList{
				Items: []firewallv1.ClusterwideNetworkPolicy{
					{
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
				},
			},
			want: nftablesRules{
				`ip saddr { 10.0.1.0/24 } tcp dport { 53 } accept comment "escape snat for dns proxy tcp"`,
				`ip saddr { 10.0.1.0/24 } udp dport { 53 } accept comment "escape snat for dns proxy udp"`,
				`ip saddr { 10.0.1.0/24 } oifname "vlan1" counter snat to jhash ip daddr . tcp sport mod 2 map { 0 : 185.0.0.2, 1 : 185.0.0.3 } comment "snat for internet"`,
				`ip saddr { 10.0.1.0/24 } oifname "vlan2" counter snat 100.0.0.2 comment "snat for mpls"`,
			},
		},
		{
			name: "empty snat rules",
			input: firewallv1.FirewallSpec{
				Data: firewallv1.Data{
					FirewallNetworks: []firewallv1.FirewallNetwork{
						{
							Networkid:   &private,
							Prefixes:    []string{"10.0.1.0/24"},
							Ips:         []string{"10.0.1.1"},
							Networktype: &privatePrimary,
							Vrf:         &vrf1,
						},
					},
					EgressRules: []firewallv1.EgressRuleSNAT{},
				},
			},
			cwnps: firewallv1.ClusterwideNetworkPolicyList{},
			want:  nftablesRules{},
		},
		{
			name: "no primary network",
			input: firewallv1.FirewallSpec{
				Data: firewallv1.Data{
					FirewallNetworks: []firewallv1.FirewallNetwork{
						{
							Networkid:   &underlay,
							Prefixes:    []string{"10.0.1.0/24"},
							Ips:         []string{"10.0.1.1"},
							Networktype: &underlayNet,
						},
					},
				},
			},
			cwnps:   firewallv1.ClusterwideNetworkPolicyList{},
			wantErr: true,
			err:     errors.New("no primary private network found"),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			f := NewFirewall(firewallv1.Firewall{Spec: tt.input}, &tt.cwnps, nil, nil, logr.Discard())
			got, err := snatRules(f)
			if (err != nil) != tt.wantErr {
				t.Errorf("snatRules() error = %v, wantErr %v", err, tt.err)
				return
			}

			if tt.wantErr && !cmp.Equal(err.Error(), tt.err.Error()) {
				t.Errorf("snatRules() diff: %v", cmp.Diff(err.Error(), tt.err.Error()))
				return
			}

			if !cmp.Equal(got, tt.want) {
				t.Errorf("snatRules() diff: %v", cmp.Diff(got, tt.want))
			}
		})
	}
}
