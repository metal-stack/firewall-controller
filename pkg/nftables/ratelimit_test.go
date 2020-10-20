package nftables

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
)

func TestRateLimitRules(t *testing.T) {
	private := "private"
	internet := "internet"
	mpls := "mpls"
	vrf1 := int64(1)
	vrf2 := int64(2)
	vrf3 := int64(3)
	boolFalse := false
	tests := []struct {
		name  string
		input firewallv1.FirewallSpec
		want  nftablesRules
	}{
		{
			name: "rate limit for multiple networks",
			input: firewallv1.FirewallSpec{
				Networks: []firewallv1.MachineNetwork{
					{
						Networkid:   &private,
						Prefixes:    []string{"10.0.1.0/24"},
						Ips:         []string{"10.0.1.1"},
						Vrf:         &vrf1,
						Underlay:    &boolFalse,
						Networktype: &firewallv1.NetworkType{PrivatePrimary: true},
					},
					{
						Networkid:   &internet,
						Prefixes:    []string{"185.0.0.0/24"},
						Ips:         []string{"185.0.0.1"},
						Vrf:         &vrf2,
						Underlay:    &boolFalse,
						Networktype: &firewallv1.NetworkType{},
					},
					{
						Networkid:   &mpls,
						Prefixes:    []string{"100.0.0.0/24"},
						Ips:         []string{"100.0.0.1"},
						Vrf:         &vrf3,
						Underlay:    &boolFalse,
						Networktype: &firewallv1.NetworkType{},
					},
				},
				RateLimits: []firewallv1.RateLimit{
					{
						Network: "private",
						Rate:    uint32(100),
					}, {
						Network: "internet",
						Rate:    uint32(10),
					}, {
						Network: "mpls",
						Rate:    uint32(20),
					}, {
						Network: "underlay",
						Rate:    uint32(200),
					},
				},
			},
			want: nftablesRules{
				`meta iifname "vrf1" limit rate over 100 mbytes/second counter name drop_ratelimit drop`,
				`meta iifname "vrf2" limit rate over 10 mbytes/second counter name drop_ratelimit drop`,
				`meta iifname "vrf3" limit rate over 20 mbytes/second counter name drop_ratelimit drop`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewFirewall(nil, nil, tt.input)
			got := rateLimitRules(f)
			if !cmp.Equal(got, tt.want) {
				t.Errorf("rateLimitRules() diff: %v", cmp.Diff(got, tt.want))
			}
		})
	}
}
