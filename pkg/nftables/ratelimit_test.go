package nftables

import (
	"testing"

	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
	mn "github.com/metal-stack/metal-lib/pkg/net"

	firewallv2 "github.com/metal-stack/firewall-controller-manager/api/v2"
	firewallv1 "github.com/metal-stack/firewall-controller/v2/api/v1"
)

func TestRateLimitRules(t *testing.T) {
	private := "private"
	internet := "internet"
	mpls := "mpls"
	vrf1 := int64(1)
	vrf2 := int64(2)
	vrf3 := int64(3)
	privatePrimary := mn.PrivatePrimaryShared
	external := mn.External
	tests := []struct {
		name  string
		input firewallv2.Firewall
		want  nftablesRules
	}{
		{
			name: "rate limit for multiple networks",
			input: firewallv2.Firewall{
				Spec: firewallv2.FirewallSpec{
					RateLimits: []firewallv2.RateLimit{
						{
							NetworkID: "private",
							Rate:      uint32(100),
						}, {
							NetworkID: "internet",
							Rate:      uint32(10),
						}, {
							NetworkID: "mpls",
							Rate:      uint32(20),
						}, {
							NetworkID: "underlay",
							Rate:      uint32(200),
						},
					},
				},
				Status: firewallv2.FirewallStatus{
					FirewallNetworks: []firewallv2.FirewallNetwork{
						{
							NetworkID:   &private,
							Prefixes:    []string{"10.0.1.0/24"},
							IPs:         []string{"10.0.1.1"},
							Vrf:         &vrf1,
							NetworkType: &privatePrimary,
						},
						{
							NetworkID:   &internet,
							Prefixes:    []string{"185.0.0.0/24"},
							IPs:         []string{"185.0.0.1"},
							Vrf:         &vrf2,
							NetworkType: &external,
						},
						{
							NetworkID:   &mpls,
							Prefixes:    []string{"100.0.0.0/24"},
							IPs:         []string{"100.0.0.1"},
							Vrf:         &vrf3,
							NetworkType: &external,
						},
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
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			f := NewFirewall(&firewallv2.Firewall{Spec: tt.input.Spec, Status: tt.input.Status}, &firewallv1.ClusterwideNetworkPolicyList{}, nil, nil, logr.Discard())
			got := rateLimitRules(f)
			if !cmp.Equal(got, tt.want) {
				t.Errorf("rateLimitRules() diff: %v", cmp.Diff(got, tt.want))
			}
		})
	}
}
