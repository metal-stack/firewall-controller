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
	"context"

	"github.com/metal-stack/firewall-controller/controllers/mocks"

	"github.com/golang/mock/gomock"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
)

var _ = Describe("Reconcile CWNP resources", func() {
	type CWNPTestCase struct {
		objects   []runtime.Object
		reconcile bool
	}

	ctx := context.TODO()
	testFunc := func(tc CWNPTestCase) {
		ctrl := gomock.NewController(GinkgoT())
		defer ctrl.Finish()

		firewall := mocks.NewMockFirewallInterface(ctrl)
		r := newCWNPReconciler(createTestFirewallFunc(firewall), tc.objects)
		req := reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      firewallName,
				Namespace: firewallv1.ClusterwideNetworkPolicyNamespace,
			},
		}

		if tc.reconcile {
			firewall.EXPECT().Reconcile().Return(true, nil)
		}

		_, err := r.Reconcile(ctx, req)
		Expect(err).ToNot(HaveOccurred())
	}

	DescribeTable("Policies update", testFunc,
		Entry("Should reconcile when new CWNP resource", CWNPTestCase{
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
	)
})
