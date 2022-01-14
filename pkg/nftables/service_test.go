package nftables

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestServiceRules(t *testing.T) {
	type want struct {
		ingress   nftablesRules
		ingressAL nftablesRules
	}

	tests := []struct {
		name  string
		input corev1.Service
		want  want
	}{
		{
			name: "standard service type loadbalancer with restricted source IP range",
			input: corev1.Service{
				ObjectMeta: v1.ObjectMeta{
					Namespace: "test",
					Name:      "svc",
				},
				Spec: corev1.ServiceSpec{
					Type: corev1.ServiceTypeLoadBalancer,
					Ports: []corev1.ServicePort{
						{
							Port:       443,
							TargetPort: *port(30443),
							Protocol:   corev1.ProtocolTCP,
						},
					},
					LoadBalancerSourceRanges: []string{"185.0.0.0/16", "185.1.0.0/16"},
				},
				Status: corev1.ServiceStatus{
					LoadBalancer: corev1.LoadBalancerStatus{
						Ingress: []corev1.LoadBalancerIngress{
							{
								IP: "185.0.0.1",
							},
						},
					},
				},
			},
			want: want{
				ingress: nftablesRules{
					`ip saddr { 185.0.0.0/16, 185.1.0.0/16 } ip daddr { 185.0.0.1 } tcp dport { 443 } counter accept comment "accept traffic for k8s service test/svc"`,
				},
				ingressAL: nftablesRules{
					`ip saddr { 185.0.0.0/16, 185.1.0.0/16 } ip daddr { 185.0.0.1 } tcp dport { 443 } counter log prefix "nftables-firewall-accept: " accept comment "accept traffic for k8s service test/svc"`,
				},
			},
		},
		{
			name: "service type nodeport is a noop",
			input: corev1.Service{
				Spec: corev1.ServiceSpec{
					Type: corev1.ServiceTypeNodePort,
					Ports: []corev1.ServicePort{
						{
							Port:       443,
							TargetPort: *port(30443),
							Protocol:   corev1.ProtocolTCP,
						},
					},
				},
			},
			want: want{nil, nil},
		},
		{
			name: "service type clusterip is a noop",
			input: corev1.Service{
				Spec: corev1.ServiceSpec{
					Type: corev1.ServiceTypeClusterIP,
					Ports: []corev1.ServicePort{
						{
							Port:       443,
							TargetPort: *port(30443),
							Protocol:   corev1.ProtocolTCP,
						},
					},
				},
			},
			want: want{nil, nil},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ingress := serviceRules(tt.input, false)
			if !cmp.Equal(ingress, tt.want.ingress) {
				t.Errorf("serviceRules() diff: %v", cmp.Diff(ingress, tt.want.ingress))
			}
			ingressAL := serviceRules(tt.input, true)
			if !cmp.Equal(ingressAL, tt.want.ingressAL) {
				t.Errorf("serviceRules() diff: %v", cmp.Diff(ingressAL, tt.want.ingressAL))
			}
		})
	}
}
