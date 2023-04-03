package controllers

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
	corev1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

// converts a network-policy object that was used before in a cluster-wide manner to the new CRD
func convert(np networking.NetworkPolicy) (*firewallv1.ClusterwideNetworkPolicy, error) {
	cwnp := firewallv1.ClusterwideNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      np.Name,
			Namespace: firewallv1.ClusterwideNetworkPolicyNamespace,
		},
	}
	newEgresses := []firewallv1.EgressRule{}
	for _, egress := range np.Spec.Egress {
		newTos := []networking.IPBlock{}
		for _, to := range egress.To {
			if to.NamespaceSelector != nil {
				return nil, fmt.Errorf("np %v contains a namespace selector and is not applicable for a conversion to a cluster-wide network policy", np.ObjectMeta)
			}
			if to.PodSelector != nil {
				return nil, fmt.Errorf("np %v contains a pod selector and is not applicable for a conversion to a cluster-wide network policy", np.ObjectMeta)
			}
			if to.IPBlock == nil {
				continue
			}
			newTos = append(newTos, *to.IPBlock)
		}
		if len(newTos) == 0 {
			continue
		}
		newEgresses = append(newEgresses, firewallv1.EgressRule{
			Ports: egress.Ports,
			To:    newTos,
		})
	}
	if len(newEgresses) == 0 {
		return nil, nil
	}
	cwnp.Spec = firewallv1.PolicySpec{
		Egress: newEgresses,
	}
	return &cwnp, nil
}
