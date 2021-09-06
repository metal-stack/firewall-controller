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
	"testing"

	corev1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestPolicySpec_Validate(t *testing.T) {
	tcp := corev1.ProtocolTCP
	udp := corev1.ProtocolUDP
	port1 := intstr.FromInt(8080)
	port2 := intstr.FromInt(8081)
	invalid := intstr.FromString("invalid")
	invalidPort := intstr.FromInt(99999)
	tests := []struct {
		name    string
		Ingress []IngressRule
		Egress  []EgressRule
		wantErr bool
	}{
		{
			name: "simple test",
			Ingress: []IngressRule{
				{
					From: []networking.IPBlock{
						{
							CIDR:   "1.1.0.0/16",
							Except: []string{"1.1.1.0/24"},
						},
						{
							CIDR:   "192.168.0.1/32",
							Except: []string{"192.168.0.1/32"},
						},
					},
					Ports: []networking.NetworkPolicyPort{
						{
							Protocol: nil,
							Port:     &port1,
						},
						{
							Protocol: &tcp,
							Port:     &port2,
						},
						{
							Protocol: &udp,
							Port:     &port2,
						},
					},
				},
			},
		},
		{
			name: "invalid test",
			Ingress: []IngressRule{
				{
					From: []networking.IPBlock{
						{
							CIDR:   "1.1.0.0/24",
							Except: []string{"1.1.1.0/16"},
						},
						{
							CIDR:   "192.168.0.1",
							Except: []string{"192.168.0.2"},
						},
					},
					Ports: []networking.NetworkPolicyPort{
						{
							Protocol: nil,
							Port:     &invalid,
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid port",
			Ingress: []IngressRule{
				{
					From: []networking.IPBlock{
						{
							CIDR: "1.1.0.0/24",
						},
					},
					Ports: []networking.NetworkPolicyPort{
						{
							Protocol: &tcp,
							Port:     &invalidPort,
						},
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			p := &PolicySpec{
				Ingress: tt.Ingress,
				Egress:  tt.Egress,
			}
			if err := p.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("PolicySpec.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFQDNSelector_GetRegex(t *testing.T) {
	tests := []struct {
		name          string
		selector      FQDNSelector
		expectedRegex string
	}{
		{
			name: "match all cases",
			selector: FQDNSelector{
				MatchPattern: "*",
			},
			expectedRegex: "(^(" + allowedDNSCharsREGroup + "+[.])+$)|(^[.]$)",
		},
		{
			name: "selector with match-all and literal",
			selector: FQDNSelector{
				MatchPattern: "*.com",
			},
			expectedRegex: "^" + allowedDNSCharsREGroup + "*[.]com[.]$",
		},
		{
			name: "selector with static value",
			selector: FQDNSelector{
				MatchPattern: "example.com",
			},
			expectedRegex: "^example[.]com[.]$",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if r := tt.selector.GetRegex(); tt.expectedRegex != r {
				t.Errorf("FQDNSelector.GetRegex returned %s, expected %s", r, tt.expectedRegex)
			}
		})
	}
}
