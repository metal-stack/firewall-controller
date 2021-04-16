package nftables

import (
	"io/ioutil"
	"path"
	"testing"

	"github.com/google/go-cmp/cmp"
	_ "github.com/metal-stack/firewall-controller/pkg/nftables/statik"
	"github.com/rakyll/statik/fs"
)

func TestFirewallRenderingData_renderString(t *testing.T) {
	statikFS, _ := fs.NewWithNamespace("tpl")
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
				statikFS:         statikFS,
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
				statikFS:         statikFS,
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
				statikFS:         statikFS,
				InternalPrefixes: "1.2.3.4",
				RateLimitRules:   []string{},
				SnatRules:        []string{},
				PrivateVrfID:     uint(42),
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
			rendered, _ := ioutil.ReadFile(path.Join("test_data", tt.name+".nftable.v4"))
			want := string(rendered)
			if got != want {
				t.Errorf("Firewall.renderString() diff: %v", cmp.Diff(got, want))
			}
		})
	}
}
