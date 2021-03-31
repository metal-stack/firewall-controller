/*


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestSerialization(t *testing.T) {
	asn := int64(123456)
	internet := "internet"
	external := "external"
	trueFlag := true
	vrf := int64(123456)

	tests := []struct {
		name    string
		data    *Data
		want    string
		wantErr bool
	}{
		{
			name: "test for api breaking changes in firewall spec",
			data: &Data{
				Interval:     "10s",
				DryRun:       false,
				Ipv4RuleFile: "/etc/nftables/firewall-controller.ipv4",
				RateLimits: []RateLimit{
					{
						NetworkID: "internet",
						Rate:      10,
					},
				},
				InternalPrefixes: []string{"10.0.0.0/8"},
				EgressRules: []EgressRuleSNAT{
					{
						NetworkID: "internet",
						IPs:       []string{"1.2.3.4"},
					},
				},
				FirewallNetworks: []FirewallNetwork{
					{
						Asn:                 &asn,
						Networkid:           &internet,
						Destinationprefixes: []string{"0.0.0.0/0"},
						Networktype:         &external,
						Nat:                 &trueFlag,
						Vrf:                 &vrf,
						Ips:                 []string{"1.2.3.4"},
						Prefixes:            []string{"1.2.3.0/24"},
					},
				},
			},
			want: `{
  "interval": "10s",
  "ipv4rulefile": "/etc/nftables/firewall-controller.ipv4",
  "rateLimits": [
    {
      "networkid": "internet",
      "rate": 10
    }
  ],
  "internalprefixes": [
    "10.0.0.0/8"
  ],
  "egressRules": [
    {
      "networkid": "internet",
      "ips": [
        "1.2.3.4"
      ]
    }
  ],
  "firewallNetworks": [
    {
      "asn": 123456,
      "destinationprefixes": [
        "0.0.0.0/0"
      ],
      "ips": [
        "1.2.3.4"
      ],
      "nat": true,
      "networkid": "internet",
      "networktype": "external",
      "prefixes": [
        "1.2.3.0/24"
      ],
      "vrf": 123456
    }
  ]
}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := json.MarshalIndent(tt.data, "", "  ")
			if err != nil {
				t.Error(err)
				t.Fail()
			}

			if !cmp.Equal(string(b), tt.want) {
				// CAUTION! This is really bad!
				//
				// This means that you introduced incompatible changes to the FirewallData struct (= change in the api)
				// This breaks the contract btw. gardener-extension-provider-metal and firewall-controller:
				// - a firewall-controller version with such changes will not be able to verify signatures generated by an older gepm version
				// - or other way round: newer gepm versions will generate a signature with additional fields that are not known to older firewall-controller versions potentially out there (in older metal-images)
				//
				// You may consider
				// - if you added an additional field to FirewallData: annotate it with omitempty
				// - publish a new major release of firewall-controller and rolling all cluster firewalls
				t.Errorf("json marshalling yields diff - this breaks the api btw. : %s", cmp.Diff(string(b), tt.want))
			}
		})
	}
}