package v1

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
)

func TestPolicySpec_Validate(t *testing.T) {
	var (
		tcp         = corev1.ProtocolTCP
		udp         = corev1.ProtocolUDP
		port1       = int32(8080)
		port2       = int32(8081)
		invalidPort = int32(99999)
	)

	tests := []struct {
		name    string
		Ingress []IngressRule
		Egress  []EgressRule
		wantErr error
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
					Ports: []NetworkPolicyPort{
						{
							Protocol: nil,
							Port:     port1,
						},
						{
							Protocol: &tcp,
							Port:     port2,
						},
						{
							Protocol: &udp,
							Port:     port2,
						},
					},
				},
			},
			wantErr: errors.New("netmask size of network to be excluded \"192.168.0.1/32\" must be greater than netmask of the block CIDR \"192.168.0.1/32\""),
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
					Ports: []NetworkPolicyPort{
						{
							Protocol: &tcp,
							Port:     invalidPort,
						},
					},
				},
			},
			wantErr: errors.New("only ports between 0 and 65535 are allowed, but 99999 given"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &PolicySpec{
				Ingress: tt.Ingress,
				Egress:  tt.Egress,
			}
			err := p.Validate()
			if tt.wantErr != nil {
				assert.EqualError(t, err, tt.wantErr.Error())
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
			name: "selector with match-all at the end",
			selector: FQDNSelector{
				MatchPattern: "example.*",
			},
			expectedRegex: "^example[.]" + allowedDNSCharsREGroup + "*[.]$",
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
		t.Run(tt.name, func(t *testing.T) {
			if r := tt.selector.GetRegex(); tt.expectedRegex != r {
				t.Errorf("FQDNSelector.GetRegex returned %s, expected %s", r, tt.expectedRegex)
			}
		})
	}
}
