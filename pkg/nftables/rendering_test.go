package nftables

import (
	"errors"
	"io/ioutil"
	"path"
	"testing"

	"github.com/google/go-cmp/cmp"
	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
	_ "github.com/metal-stack/firewall-controller/pkg/nftables/statik"
	"github.com/rakyll/statik/fs"
)

func TestRateLimitRules(t *testing.T) {
	tests := []struct {
		name  string
		input firewallv1.FirewallSpec
		want  nftablesRules
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
						Vrf:             uint(1),
					},
					{
						ID:       "internet",
						Prefixes: []string{"185.0.0.0/24"},
						IPs:      []string{"185.0.0.1"},
						Vrf:      uint(2),
					},
					{
						ID:       "mpls",
						Prefixes: []string{"100.0.0.0/24"},
						IPs:      []string{"100.0.0.1"},
						Vrf:      uint(3),
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
