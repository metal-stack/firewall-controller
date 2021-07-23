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

//nolint
package controllers

import (
	"fmt"

	"github.com/golang/mock/gomock"

	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
	"github.com/metal-stack/firewall-controller/pkg/nftables/mocks"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var _ = Describe("Reconcile CWNP resources", func() {
	type CWNPTestCase struct {
		objects              []runtime.Object
		policySpecsChecksums map[string][16]byte
		mockFunc             func(*mocks.MockFQDNCache)
		reconcile            bool
	}

	testFunc := func(tc CWNPTestCase) {
		ctrl := gomock.NewController(GinkgoT())
		defer ctrl.Finish()

		firewall := mocks.NewMockFirewallInterface(ctrl)
		fqdnCache := mocks.NewMockFQDNCache(ctrl)

		r := newCWNPReconciler(createTestFirewallFunc(firewall), fqdnCache, tc.objects, tc.policySpecsChecksums)
		req := reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      firewallName,
				Namespace: firewallv1.ClusterwideNetworkPolicyNamespace,
			},
		}

		if tc.reconcile {
			firewall.EXPECT().Reconcile().Return(nil)
		}
		if tc.mockFunc != nil {
			tc.mockFunc(fqdnCache)
		}

		_, err := r.Reconcile(req)
		Expect(err).ToNot(HaveOccurred())
	}

	DescribeTable("Policies update", testFunc,
		Entry("Should reconcile when new CWNP resource added", CWNPTestCase{
			objects: []runtime.Object{
				newFirewall(),
				newCWNP("test", []firewallv1.EgressRule{
					{
						ToFQDNs: []firewallv1.FQDNSelector{
							{
								MatchName: "test.com",
							},
						},
					},
				}),
			},
			reconcile: true,
		}),
		Entry("Shouldn't update when resource not updated", CWNPTestCase{
			objects: []runtime.Object{
				newFirewall(),
				newCWNP("test", []firewallv1.EgressRule{
					{
						ToFQDNs: []firewallv1.FQDNSelector{
							{
								MatchName: "test.com",
								Sets: []firewallv1.IPSet{
									{
										SetName: "test",
									},
									{
										SetName: "test2",
									},
								},
							},
						},
					},
				}),
			},
			policySpecsChecksums: map[string][16]byte{
				getPolicySpecKey("test"): getCWNPChecksum("test", []firewallv1.EgressRule{
					{
						ToFQDNs: []firewallv1.FQDNSelector{
							{
								MatchName: "test.com",
								Sets: []firewallv1.IPSet{
									{
										SetName: "test",
									},
									{
										SetName: "test2",
									},
								},
							},
						},
					},
				}),
			},
			mockFunc: func(cache *mocks.MockFQDNCache) {
				cache.EXPECT().GetSetsForFQDN(gomock.Any(), false).Return([]firewallv1.IPSet{
					{
						SetName: "test2",
					},
					{
						SetName: "test",
					},
				})
			},
		}),
		Entry("Should reconcile when updated", CWNPTestCase{
			objects: []runtime.Object{
				newFirewall(),
				newCWNP("test", []firewallv1.EgressRule{
					{
						ToFQDNs: []firewallv1.FQDNSelector{
							{
								MatchName: "test.com",
							},
						},
					},
				}),
			},
			policySpecsChecksums: map[string][16]byte{
				getPolicySpecKey("test"): getCWNPChecksum("test", []firewallv1.EgressRule{
					{
						ToFQDNs: []firewallv1.FQDNSelector{
							{
								MatchName: "test2.com",
							},
						},
					},
				}),
			},
			reconcile: true,
		}),
		Entry("Should reconcile when FQDN cache updated", CWNPTestCase{
			objects: []runtime.Object{
				newFirewall(),
				newCWNP("test", []firewallv1.EgressRule{
					{
						ToFQDNs: []firewallv1.FQDNSelector{
							{
								MatchName: "test.com",
							},
						},
					},
				}),
			},
			policySpecsChecksums: map[string][16]byte{
				getPolicySpecKey("test"): getCWNPChecksum("test", []firewallv1.EgressRule{
					{
						ToFQDNs: []firewallv1.FQDNSelector{
							{
								MatchName: "test.com",
							},
						},
					},
				}),
			},
			mockFunc: func(cache *mocks.MockFQDNCache) {
				cache.EXPECT().GetSetsForFQDN(gomock.Any(), false).Return([]firewallv1.IPSet{{SetName: "test"}})
			},
			reconcile: true,
		}),
	)
})

func getPolicySpecKey(name string) string {
	return fmt.Sprintf("%s%c%s", firewallv1.ClusterwideNetworkPolicyNamespace, types.Separator, name)
}
