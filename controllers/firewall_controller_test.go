package controllers

import (
	"errors"
	"reflect"
	"testing"

	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
	corev1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestConvert(t *testing.T) {
	p := intstr.FromInt(8080)
	tcp := corev1.ProtocolTCP
	tt := []struct {
		name         string
		np           networking.NetworkPolicy
		expectedCwnp *firewallv1.ClusterwideNetworkPolicy
		expectedErr  error
	}{
		{
			"empty np yields no cnwp",
			networking.NetworkPolicy{},
			nil,
			nil,
		},
		{
			"np should yield proper cnwp",
			networking.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{
					Name: "test-np",
				},
				Spec: networking.NetworkPolicySpec{
					Egress: []networking.NetworkPolicyEgressRule{
						{
							Ports: []networking.NetworkPolicyPort{
								{
									Port:     &p,
									Protocol: &tcp,
								},
							},
							To: []networking.NetworkPolicyPeer{
								{
									IPBlock: &networking.IPBlock{
										CIDR: "0.0.0.0/0",
									},
								},
							},
						},
					},
				},
			},
			&firewallv1.ClusterwideNetworkPolicy{
				ObjectMeta: v1.ObjectMeta{
					Name:      "test-np",
					Namespace: firewallv1.ClusterwideNetworkPolicyNamespace,
				},
				Spec: firewallv1.PolicySpec{
					Egress: []firewallv1.EgressRule{
						{
							Ports: []networking.NetworkPolicyPort{
								{
									Port:     &p,
									Protocol: &tcp,
								},
							},
							To: []networking.IPBlock{
								{
									CIDR: "0.0.0.0/0",
								},
							},
						},
					},
				},
			},
			nil,
		},
		{
			"np with pod selector are ignored",
			networking.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{
					Name: "test-np",
				},
				Spec: networking.NetworkPolicySpec{
					PodSelector: v1.LabelSelector{
						MatchLabels: map[string]string{"test": "test"},
					},
				},
			},
			nil,
			nil,
		},
		{
			"np with blacklisted name are ignored",
			networking.NetworkPolicy{
				ObjectMeta: v1.ObjectMeta{
					Name: "egress-allow-http",
				},
				Spec: networking.NetworkPolicySpec{
					Egress: []networking.NetworkPolicyEgressRule{
						{
							Ports: []networking.NetworkPolicyPort{
								{
									Port:     &p,
									Protocol: &tcp,
								},
							},
							To: []networking.NetworkPolicyPeer{
								{
									IPBlock: &networking.IPBlock{
										CIDR: "0.0.0.0/0",
									},
								},
							},
						},
					},
				},
			},
			nil,
			nil,
		},
	}
	for _, tc := range tt {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			actualCwnp, actualErr := convert(tc.np)
			if !errors.Is(actualErr, tc.expectedErr) {
				t.Errorf("expected error: %v, actual error: %v", tc.expectedErr, actualErr)
			}
			if tc.expectedCwnp == nil {
				return
			}
			if !reflect.DeepEqual(actualCwnp.Spec, tc.expectedCwnp.Spec) {
				t.Errorf("expected cwnp: %v, actual cwnp: %v", tc.expectedCwnp.Spec, actualCwnp.Spec)
			}
		})
	}
}
