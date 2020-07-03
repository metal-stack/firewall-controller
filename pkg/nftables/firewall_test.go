package nftables

import (
	"io/ioutil"
	"net/http"
	"os/exec"
	"path"
	"testing"

	"github.com/google/go-cmp/cmp"
	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
	_ "github.com/metal-stack/firewall-controller/pkg/nftables/statik"
	"github.com/rakyll/statik/fs"
)

func TestFirewall_renderString(t *testing.T) {
	statikFS, _ := fs.NewWithNamespace("tpl")
	type fields struct {
		Ingress          []string
		Egress           []string
		RateLimits       []firewallv1.RateLimit
		Ipv4RuleFile     string
		DryRun           bool
		statikFS         http.FileSystem
		InternalPrefixes string
		TrustedNetworks  string
	}
	tests := []struct {
		name     string
		fields   fields
		validate bool
		want     string
		wantErr  bool
	}{
		{
			name: "simple",
			fields: fields{
				Egress:       []string{"egress rule"},
				Ingress:      []string{"ingress rule"},
				Ipv4RuleFile: "nftables.v4",
				RateLimits: []firewallv1.RateLimit{
					{
						Interface: "eth0",
						Rate:      10,
					},
				},
				statikFS:         statikFS,
				InternalPrefixes: "1.2.3.4",
				TrustedNetworks:  "0.0.0.0/0",
			},
			wantErr: false,
		},
		{
			name: "more-rules",
			fields: fields{
				Egress:       []string{"egress rule 1", "egress rule 2"},
				Ingress:      []string{"ingress rule 1", "ingress rule 2"},
				Ipv4RuleFile: "nftables.v4",
				RateLimits: []firewallv1.RateLimit{
					{
						Interface: "eth0",
						Rate:      10,
					},
				},
				statikFS:         statikFS,
				InternalPrefixes: "1.2.3.0/24, 2.3.4.0/8",
				TrustedNetworks:  "0.0.0.0/0",
			},
			wantErr: false,
		},
		{
			name: "validated",
			fields: fields{
				Egress:           []string{"ip daddr == 1.2.3.4"},
				Ingress:          []string{"ip saddr == 1.2.3.4"},
				Ipv4RuleFile:     "nftables.v4",
				statikFS:         statikFS,
				InternalPrefixes: "1.2.3.4",
				TrustedNetworks:  "0.0.0.0/0",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &Firewall{
				Ingress:          tt.fields.Ingress,
				Egress:           tt.fields.Egress,
				RateLimits:       tt.fields.RateLimits,
				Ipv4RuleFile:     tt.fields.Ipv4RuleFile,
				DryRun:           tt.fields.DryRun,
				statikFS:         tt.fields.statikFS,
				InternalPrefixes: tt.fields.InternalPrefixes,
				TrustedNetworks:  tt.fields.TrustedNetworks,
			}
			got, err := f.renderString()
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

// TestFirewallValidateRulesIntegration is a integration test an is skipped during normal unit testing
// this is achieved by running the test with go test -short
// to run this test you should either only execute go test
// or to run only thes integration test go test Integration
func TestFirewallValidateRulesIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	statikFS, _ := fs.NewWithNamespace("tpl")
	type fields struct {
		Ingress          []string
		Egress           []string
		RateLimits       []firewallv1.RateLimit
		Ipv4RuleFile     string
		DryRun           bool
		statikFS         http.FileSystem
		InternalPrefixes string
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
				statikFS:         statikFS,
				InternalPrefixes: "1.2.3.4",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &Firewall{
				Ingress:          tt.fields.Ingress,
				Egress:           tt.fields.Egress,
				RateLimits:       tt.fields.RateLimits,
				Ipv4RuleFile:     tt.fields.Ipv4RuleFile,
				DryRun:           tt.fields.DryRun,
				statikFS:         tt.fields.statikFS,
				InternalPrefixes: tt.fields.InternalPrefixes,
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
