package nftables

import (
	"os/exec"
	"testing"

	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
)

// TestFirewallValidateRulesIntegration is a integration test an is skipped during normal unit testing
// this is achieved by running the test with go test -short
// to run this test you should either only execute go test
// or to run only thes integration test go test Integration
func TestFirewallValidateRulesIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	type fields struct {
		Ingress          []string
		Egress           []string
		RateLimits       []firewallv1.RateLimit
		Ipv4RuleFile     string
		DryRun           bool
		InternalPrefixes string
		PrivateVrfID     uint
	}
	tests := []struct {
		name     string
		fields   fields
		validate bool
		want     string
		wantErr  bool
	}{
		{
			name: "validated",
			fields: fields{
				Egress:           []string{"ip daddr == 1.2.3.4"},
				Ingress:          []string{"ip saddr == 1.2.3.4"},
				Ipv4RuleFile:     "nftables.v4",
				InternalPrefixes: "1.2.3.4",
				PrivateVrfID:     uint(42),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &firewallRenderingData{
				ForwardingRules: forwardingRules{
					Ingress: tt.fields.Ingress,
					Egress:  tt.fields.Egress,
				},
				InternalPrefixes: tt.fields.InternalPrefixes,
				// RateLimitRules:   tt.fields.RateLimitRules,
				PrivateVrfID: tt.fields.PrivateVrfID,
			}
			got, err := f.renderString()
			if (err != nil) != tt.wantErr {
				t.Errorf("Firewall.renderString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			c := exec.Command(nftBin, "-c", "-f", "-", got)
			out, err := c.CombinedOutput()
			if err != nil {
				t.Errorf("Firewall.renderString() produced invalid nftables ruleset:%v", string(out))
				return
			}
		})
	}
}
