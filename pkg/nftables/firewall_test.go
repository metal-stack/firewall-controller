package nftables

import (
	"io/ioutil"
	"log"
	"net/http"
	"os/exec"
	"path"
	"testing"

	"github.com/ghodss/yaml"
	"github.com/google/go-cmp/cmp"
	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
	_ "github.com/metal-stack/firewall-controller/pkg/nftables/statik"
	"github.com/rakyll/statik/fs"
)

// // won't work because crd is not deployed
// func TestFetchAndAssembleWithTestData(t *testing.T) {
// 	for _, tc := range list("test_data", true) {
// 		t.Run(tc, func(t *testing.T) {
// 			tcd := path.Join("test_data", tc)
// 			c := fake.NewSimpleClientset()
// 			c.ApiextensionsV1beta1().CustomResourceDefinitions().Create(&crd)
// 			for _, i := range list(path.Join(tcd, "services"), false) {
// 				var svc corev1.Service
// 				mustUnmarshal(path.Join(tcd, "services", i), &svc)
// 				_, err := c.CoreV1().Services(svc.ObjectMeta.Namespace).Create(&svc)
// 				assert.Nil(t, err)
// 			}
// 			for _, i := range list(path.Join(tcd, "policies"), false) {
// 				var np firewallv1.ClusterwideNetworkPolicy
// 				mustUnmarshal(path.Join(tcd, "policies", i), &np)
// 				_, err := c.NetworkingV1().NetworkPolicies(np.ObjectMeta.Namespace).Create(&np)
// 				assert.Nil(t, err)
// 			}
// 			controller := NewFirewallController(c, nil)
// 			rules, err := controller.FetchAndAssemble()
// 			if err != nil {
// 				panic(err)
// 			}
// 			exp, _ := ioutil.ReadFile(path.Join(tcd, "expected.nftablev4"))
// 			rs, err := rules.Render()
// 			assert.Nil(t, err)
// 			assert.Equal(t, string(exp), rs)
// 		})
// 	}
// }

func list(path string, dirs bool) []string {
	files, err := ioutil.ReadDir(path)
	if err != nil {
		log.Fatal(err)
	}
	r := []string{}
	for _, f := range files {
		if f.IsDir() && dirs {
			r = append(r, f.Name())
		} else if !f.IsDir() && !dirs {
			r = append(r, f.Name())
		}
	}
	return r
}

func mustUnmarshal(f string, data interface{}) {
	c, _ := ioutil.ReadFile(f)
	err := yaml.Unmarshal(c, data)
	if err != nil {
		panic(err)
	}
}

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
