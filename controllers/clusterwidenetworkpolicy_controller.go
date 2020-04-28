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
	"context"
	"fmt"

	"github.com/go-logr/logr"
	firewallv1 "github.com/metal-stack/firewall-builder/api/v1"
	"github.com/metal-stack/firewall-builder/pkg/nftables"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"sigs.k8s.io/controller-runtime/pkg/source"
)

// ClusterwideNetworkPolicyReconciler reconciles a ClusterwideNetworkPolicy object
type ClusterwideNetworkPolicyReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

const firewallNamespace = "firewall"

// +kubebuilder:rbac:groups=firewall.metal-stack.io,resources=clusterwidenetworkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=firewall.metal-stack.io,resources=clusterwidenetworkpolicies/status,verbs=get;update;patch

func (r *ClusterwideNetworkPolicyReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("ClusterWideNetworkPolicy", req.NamespacedName)
	if req.Namespace != firewallNamespace {
		var clusterNP firewallv1.ClusterwideNetworkPolicy
		if err := r.Get(ctx, req.NamespacedName, &clusterNP); err != nil {
			return ctrl.Result{}, err
		}
		clusterNP.Status.Message = fmt.Sprintf("cluster wide network policies must be defined in namespace %s otherwise they won't take effect", firewallNamespace)
		if err := r.Update(ctx, &clusterNP); err != nil {
			log.Error(err, "unable to update ClusterWideNetworkPolicy", "namespacedname", req.NamespacedName)
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	var clusterNPs firewallv1.ClusterwideNetworkPolicyList
	if err := r.List(ctx, &clusterNPs, client.InNamespace(req.Namespace)); err != nil {
		log.Error(err, "")
	}

	var services v1.ServiceList
	if err := r.List(ctx, &services); err != nil {
		log.Error(err, "")
	}

	fwr := &nftables.FirewallResources{
		NetworkPolicyList: &clusterNPs,
		ServiceList:       &services,
	}
	rules := fwr.AssembleRules()
	log.Info("assembled", "rules", rules)
	f, _ := rules.Render()
	log.Info("nftables", "file", f)

	return ctrl.Result{}, nil
}

func (r *ClusterwideNetworkPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&firewallv1.ClusterwideNetworkPolicy{}).
		Watches(&source.Kind{Type: &corev1.Service{}}, newEnqueueReconcilationHandler(firewallNamespace, "trigger-reconcilation-for-service")).
		Complete(r)
}
