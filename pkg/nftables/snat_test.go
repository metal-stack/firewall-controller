package nftables

import (
	"errors"
	"testing"

	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
	mn "github.com/metal-stack/metal-lib/pkg/net"

	firewallv2 "github.com/metal-stack/firewall-controller-manager/api/v2"
	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
)

func TestSnatRules(t *testing.T) {
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
		input   firewallv2.Firewall
		want    nftablesRules
		wantErr bool
		err     error
	}{
		{
			name: "snat for multiple networks",
			input: firewallv2.Firewall{
				Spec: firewallv2.FirewallSpec{
					EgressRules: []firewallv2.EgressRuleSNAT{
						{
							NetworkID: "internet",
							IPs:       []string{"185.0.0.2", "185.0.0.3"},
						}, {
							NetworkID: "mpls",
							IPs:       []string{"100.0.0.2"},
						},
					},
				},
				Status: firewallv2.FirewallStatus{
					FirewallNetworks: []firewallv2.FirewallNetwork{
						{
							NetworkID:   &private,
							Prefixes:    []string{"10.0.1.0/24"},
							IPs:         []string{"10.0.1.1"},
							NetworkType: &privatePrimary,
						},
						{
							NetworkID:   &internet,
							Prefixes:    []string{"185.0.0.0/24"},
							IPs:         []string{"185.0.0.1"},
							Vrf:         &vrf1,
							NetworkType: &external,
						},
						{
							NetworkID:   &mpls,
							Prefixes:    []string{"100.0.0.0/24"},
							IPs:         []string{"100.0.0.1"},
							Vrf:         &vrf2,
							NetworkType: &external,
						},
					},
				},
			},
			want: nftablesRules{
				`ip saddr { 10.0.1.0/24 } oifname "vlan1" counter snat to jhash ip daddr . tcp sport mod 2 map { 0 : 185.0.0.2, 1 : 185.0.0.3 } comment "snat for internet"`,
				`ip saddr { 10.0.1.0/24 } oifname "vlan2" counter snat 100.0.0.2 comment "snat for mpls"`,
			},
		},
		{
			name: "empty snat rules",
			input: firewallv2.Firewall{
				Spec: firewallv2.FirewallSpec{
					EgressRules: []firewallv2.EgressRuleSNAT{},
				},
				Status: firewallv2.FirewallStatus{
					FirewallNetworks: []firewallv2.FirewallNetwork{
						{
							NetworkID:   &private,
							Prefixes:    []string{"10.0.1.0/24"},
							IPs:         []string{"10.0.1.1"},
							NetworkType: &privatePrimary,
							Vrf:         &vrf1,
						},
					},
				},
			},
			want: nftablesRules{},
		},
		{
			name: "no primary network",
			input: firewallv2.Firewall{
				Status: firewallv2.FirewallStatus{
					FirewallNetworks: []firewallv2.FirewallNetwork{
						{
							NetworkID:   &underlay,
							Prefixes:    []string{"10.0.1.0/24"},
							IPs:         []string{"10.0.1.1"},
							NetworkType: &underlayNet,
						},
					},
				},
			},
			wantErr: true,
			err:     errors.New("no primary private network found"),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			f := NewFirewall(firewallv2.Firewall{Spec: tt.input.Spec, Status: tt.input.Status}, &firewallv1.ClusterwideNetworkPolicyList{}, nil, nil, logr.Discard())
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
