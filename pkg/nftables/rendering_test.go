package nftables

import (
	"net"
	"os"
	"path"
	"testing"

	"github.com/google/go-cmp/cmp"

	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
	"github.com/metal-stack/firewall-controller/pkg/dns"
)

func TestFirewallRenderingData_renderString(t *testing.T) {
	tests := []struct {
		name    string
		data    *firewallRenderingData
		wantErr bool
	}{
		{
			name: "simple",
			data: &firewallRenderingData{
				ForwardingRules: forwardingRules{
					Egress:  []string{"egress rule"},
					Ingress: []string{"ingress rule"},
				},
				InternalPrefixes: "1.2.3.4",
				RateLimitRules:   []string{"meta iifname \"eth0\" limit rate over 10 mbytes/second counter name drop_ratelimit drop"},
				SnatRules:        []string{},
				PrivateVrfID:     uint(42),
			},
			wantErr: false,
		},
		{
			name: "more-rules",
			data: &firewallRenderingData{
				ForwardingRules: forwardingRules{
					Egress:  []string{"egress rule 1", "egress rule 2"},
					Ingress: []string{"ingress rule 1", "ingress rule 2"},
				},
				InternalPrefixes: "1.2.3.0/24, 2.3.4.0/8",
				RateLimitRules:   []string{"meta iifname \"eth0\" limit rate over 10 mbytes/second counter name drop_ratelimit drop"},
				SnatRules:        []string{"ip saddr { 10.0.0.0/8 } oifname \"vlan104009\" counter snat 185.1.2.3 comment \"snat internet\""},
				PrivateVrfID:     uint(42),
			},
			wantErr: false,
		},
		{
			name: "validated",
			data: &firewallRenderingData{
				ForwardingRules: forwardingRules{
					Egress:  []string{"ip daddr == 1.2.3.4"},
					Ingress: []string{"ip saddr == 1.2.3.4"},
				},
				InternalPrefixes: "1.2.3.4",
				RateLimitRules:   []string{},
				SnatRules:        []string{},
				PrivateVrfID:     uint(42),
			},
			wantErr: false,
		},
		{
			name: "sets",
			data: &firewallRenderingData{
				ForwardingRules: forwardingRules{
					Egress:  []string{"egress rule"},
					Ingress: []string{"ingress rule"},
				},
				InternalPrefixes: "1.2.3.4",
				RateLimitRules:   []string{"meta iifname \"eth0\" limit rate over 10 mbytes/second counter name drop_ratelimit drop"},
				SnatRules:        []string{},
				PrivateVrfID:     uint(42),
				Sets: []firewallv1.IPSet{
					{
						SetName: "test",
						IPs:     []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")},
						Version: dns.IPv4,
					},
					{
						SetName: "test2",
						IPs: []net.IP{
							net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
							net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7335")},
						Version: dns.IPv6,
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			fd := tt.data

			got, err := fd.renderString()
			if (err != nil) != tt.wantErr {
				t.Errorf("Firewall.renderString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			rendered, _ := os.ReadFile(path.Join("test_data", tt.name+".nftable.v4"))
			want := string(rendered)
			if got != want {
				t.Errorf("Firewall.renderString() diff: %v", cmp.Diff(got, want))
			}
		})
	}
}
