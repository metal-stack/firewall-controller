package nftables

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
	mn "github.com/metal-stack/metal-lib/pkg/net"
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
		input   firewallv1.FirewallSpec
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
			want: nftablesRules{
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
			want: nftablesRules{},
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
			wantErr: true,
			err:     errors.New("no primary private network found"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewFirewall(nil, nil, tt.input)
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
