package nftables

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/metal-stack/firewall-controller/v2/pkg/helper"
	"go4.org/netipx"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func helpMustParseIPSet(ips []string) *netipx.IPSet {
	res, _ := helper.BuildNetworksIPSet(ips)
	return res
}

func TestServiceRules(t *testing.T) {
	type want struct {
		ingress   nftablesRules
		ingressAL nftablesRules
	}

	tests := []struct {
		name    string
		input   corev1.Service
		allowed *netipx.IPSet
		want    want
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
					`ip saddr { 185.0.0.0/16, 185.1.0.0/16 } ip daddr { 185.0.0.1 } tcp dport { 443 } log prefix "nftables-firewall-accepted: " limit rate 10/second` + "\n" + `ip saddr { 185.0.0.0/16, 185.1.0.0/16 } ip daddr { 185.0.0.1 } tcp dport { 443 } counter accept comment "accept traffic for k8s service test/svc"`,
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
		{
			name:    "standard service type loadbalancer with a non matching allowed IP set",
			allowed: helpMustParseIPSet([]string{"182.0.0.0/8"}),
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
					`ip saddr { 185.0.0.0/16, 185.1.0.0/16 } tcp dport { 443 } counter accept comment "accept traffic for k8s service test/svc"`,
				},
				ingressAL: nftablesRules{
					`ip saddr { 185.0.0.0/16, 185.1.0.0/16 } tcp dport { 443 } log prefix "nftables-firewall-accepted: " limit rate 10/second` + "\n" + `ip saddr { 185.0.0.0/16, 185.1.0.0/16 } tcp dport { 443 } counter accept comment "accept traffic for k8s service test/svc"`,
				},
			},
		},
		{
			name:    "standard service type loadbalancer with restricted source IP range, allow loadbalancer and status-ingress IP",
			allowed: helpMustParseIPSet([]string{"185.0.1.0/30"}),
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
					LoadBalancerIP: "185.0.1.2",
				},
				Status: corev1.ServiceStatus{
					LoadBalancer: corev1.LoadBalancerStatus{
						Ingress: []corev1.LoadBalancerIngress{
							{
								IP: "185.0.1.1",
							},
						},
					},
				},
			},
			want: want{
				ingress: nftablesRules{
					`ip daddr { 185.0.1.2, 185.0.1.1 } tcp dport { 443 } counter accept comment "accept traffic for k8s service test/svc"`,
				},
				ingressAL: nftablesRules{
					`ip daddr { 185.0.1.2, 185.0.1.1 } tcp dport { 443 } log prefix "nftables-firewall-accepted: " limit rate 10/second` + "\n" + `ip daddr { 185.0.1.2, 185.0.1.1 } tcp dport { 443 } counter accept comment "accept traffic for k8s service test/svc"`,
				},
			},
		},
		{
			name:    "standard service type loadbalancer with restricted source IP range, filter out loadbalancer-IP",
			allowed: helpMustParseIPSet([]string{"185.0.1.0/31"}),
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
					LoadBalancerIP: "185.0.1.2",
				},
				Status: corev1.ServiceStatus{
					LoadBalancer: corev1.LoadBalancerStatus{
						Ingress: []corev1.LoadBalancerIngress{
							{
								IP: "185.0.1.1",
							},
						},
					},
				},
			},
			want: want{
				ingress: nftablesRules{
					`ip daddr { 185.0.1.1 } tcp dport { 443 } counter accept comment "accept traffic for k8s service test/svc"`,
				},
				ingressAL: nftablesRules{
					`ip daddr { 185.0.1.1 } tcp dport { 443 } log prefix "nftables-firewall-accepted: " limit rate 10/second` + "\n" + `ip daddr { 185.0.1.1 } tcp dport { 443 } counter accept comment "accept traffic for k8s service test/svc"`,
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ingress := serviceRules(tt.input, tt.allowed, false, nil)
			if !cmp.Equal(ingress, tt.want.ingress) {
				t.Errorf("serviceRules() diff: %v", cmp.Diff(ingress, tt.want.ingress))
			}
			ingressAL := serviceRules(tt.input, tt.allowed, true, nil)
			if !cmp.Equal(ingressAL, tt.want.ingressAL) {
				t.Errorf("serviceRules() diff: %v", cmp.Diff(ingressAL, tt.want.ingressAL))
			}
		})
	}
}
