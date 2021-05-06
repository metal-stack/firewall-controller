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

package controllers

import (
	"fmt"

	"github.com/golang/mock/gomock"
	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
	"github.com/metal-stack/firewall-controller/controllers/mocks"
	nftMocks "github.com/metal-stack/firewall-controller/pkg/nftables/mocks"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var _ = Describe("Reconcile CNWP resources", func() {
	type CNWPTestCase struct {
		objects     []runtime.Object
		policySpecs map[string]firewallv1.PolicySpec
		mockFunc    func(*nftMocks.MockFQDNCache)
		reconcile   bool
	}

	testFunc := func(tc CNWPTestCase) {
		ctrl := gomock.NewController(GinkgoT())
		defer ctrl.Finish()

		firewall := mocks.NewMockFirewallInterface(ctrl)
		fqdnCache := nftMocks.NewMockFQDNCache(ctrl)

		r := newCNWPReconciler(createTestFirewallFunc(firewall), fqdnCache, tc.objects, tc.policySpecs)
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
		Entry("Should reconcile when new CNWP resource added", CNWPTestCase{
			objects: []runtime.Object{
				newFirewall(),
				newCNWP("test", []firewallv1.EgressRule{
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
		Entry("Shouldn't update when resource not updated", CNWPTestCase{
			objects: []runtime.Object{
				newFirewall(),
				newCNWP("test", []firewallv1.EgressRule{
					{
						ToFQDNs: []firewallv1.FQDNSelector{
							{
								MatchName: "test.com",
							},
						},
					},
				}),
			},
			policySpecs: map[string]firewallv1.PolicySpec{
				getPolicySpecKey("test"): newCNWP("test", []firewallv1.EgressRule{
					{
						ToFQDNs: []firewallv1.FQDNSelector{
							{
								MatchName: "test.com",
							},
						},
					},
				}).Spec,
			},
			mockFunc: func(cache *nftMocks.MockFQDNCache) {
				cache.EXPECT().GetSetsForFQDN(gomock.Any()).Return(nil)
			},
		}),
		Entry("Should reconcile when updated", CNWPTestCase{
			objects: []runtime.Object{
				newFirewall(),
				newCNWP("test", []firewallv1.EgressRule{
					{
						ToFQDNs: []firewallv1.FQDNSelector{
							{
								MatchName: "test.com",
							},
						},
					},
				}),
			},
			policySpecs: map[string]firewallv1.PolicySpec{
				getPolicySpecKey("test"): newCNWP("test", []firewallv1.EgressRule{
					{
						ToFQDNs: []firewallv1.FQDNSelector{
							{
								MatchName: "test2.com",
							},
						},
					},
				}).Spec,
			},
			reconcile: true,
		}),
		Entry("Should reconcile when FQDN cache updated", CNWPTestCase{
			objects: []runtime.Object{
				newFirewall(),
				newCNWP("test", []firewallv1.EgressRule{
					{
						ToFQDNs: []firewallv1.FQDNSelector{
							{
								MatchName: "test.com",
							},
						},
					},
				}),
			},
			policySpecs: map[string]firewallv1.PolicySpec{
				getPolicySpecKey("test"): newCNWP("test", []firewallv1.EgressRule{
					{
						ToFQDNs: []firewallv1.FQDNSelector{
							{
								MatchName: "test.com",
							},
						},
					},
				}).Spec,
			},
			mockFunc: func(cache *nftMocks.MockFQDNCache) {
				cache.EXPECT().GetSetsForFQDN(gomock.Any()).Return([]string{"test"})
			},
			reconcile: true,
		}),
	)
})

func getPolicySpecKey(name string) string {
	return fmt.Sprintf("%s%c%s", firewallv1.ClusterwideNetworkPolicyNamespace, types.Separator, name)
}
