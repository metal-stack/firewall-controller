package nftables

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
)

func TestSnatRules(t *testing.T) {
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
				Networks: []firewallv1.Network{
					{
						ID:              "private",
						Prefixes:        []string{"10.0.1.0/24"},
						IPs:             []string{"10.0.1.1"},
						ParentNetworkID: "super",
					},
					{
						ID:       "internet",
						Prefixes: []string{"185.0.0.0/24"},
						IPs:      []string{"185.0.0.1"},
						Vrf:      uint(1),
					},
					{
						ID:       "mpls",
						Prefixes: []string{"100.0.0.0/24"},
						IPs:      []string{"100.0.0.1"},
						Vrf:      uint(2),
					},
				},
				Snat: []firewallv1.Snat{
					{
						Network: "internet",
						IPs:     []string{"185.0.0.2", "185.0.0.3"},
					}, {
						Network: "mpls",
						IPs:     []string{"100.0.0.2"},
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
				Networks: []firewallv1.Network{
					{
						ID:              "private",
						Prefixes:        []string{"10.0.1.0/24"},
						IPs:             []string{"10.0.1.1"},
						ParentNetworkID: "super",
					},
				},
				Snat: []firewallv1.Snat{},
			},
			want: nftablesRules{},
		},
		{
			name: "no primary network",
			input: firewallv1.FirewallSpec{
				Networks: []firewallv1.Network{
					{
						ID:       "underlay",
						Prefixes: []string{"10.0.0.0/24"},
						IPs:      []string{"10.0.0.1"},
						Underlay: true,
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
