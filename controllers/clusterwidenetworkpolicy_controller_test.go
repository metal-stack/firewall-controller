// nolint
package controllers

// import (
// 	"context"

// 	"github.com/metal-stack/firewall-controller/controllers/mocks"

// 	"github.com/golang/mock/gomock"

// 	. "github.com/onsi/ginkgo"
// 	. "github.com/onsi/ginkgo/extensions/table"
// 	. "github.com/onsi/gomega"
// 	"k8s.io/apimachinery/pkg/runtime"
// 	"k8s.io/apimachinery/pkg/types"
// 	"sigs.k8s.io/controller-runtime/pkg/reconcile"

// 	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
// )

// var _ = Describe("Reconcile CWNP resources", func() {
// 	type CWNPTestCase struct {
// 		objects   []runtime.Object
// 		reconcile bool
// 	}

// 	ctx := context.TODO()
// 	testFunc := func(tc CWNPTestCase) {
// 		ctrl := gomock.NewController(GinkgoT())
// 		defer ctrl.Finish()

// 		firewall := mocks.NewMockFirewallInterface(ctrl)
// 		r := newCWNPReconciler(createTestFirewallFunc(firewall), tc.objects)
// 		req := reconcile.Request{
// 			NamespacedName: types.NamespacedName{
// 				Name:      "firewall",
// 				Namespace: firewallv1.ClusterwideNetworkPolicyNamespace,
// 			},
// 		}

// 		if tc.reconcile {
// 			firewall.EXPECT().Reconcile().Return(true, nil)
// 		}

// 		_, err := r.Reconcile(ctx, req)
// 		Expect(err).ToNot(HaveOccurred())
// 	}

// 	DescribeTable("Policies update", testFunc,
// 		Entry("Should reconcile when new CWNP resource", CWNPTestCase{
// 			objects: []runtime.Object{
// 				newFirewall(),
// 				newCWNP("test", []firewallv1.EgressRule{
// 					{
// 						ToFQDNs: []firewallv1.FQDNSelector{
// 							{
// 								MatchName: "test.com",
// 							},
// 						},
// 					},
// 				}),
// 			},
// 			reconcile: true,
// 		}),
// 	)
// })
