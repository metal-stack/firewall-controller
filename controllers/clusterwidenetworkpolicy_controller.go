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
	"time"

	"github.com/go-logr/logr"
	firewallv1 "github.com/metal-stack/firewall-builder/api/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ClusterwideNetworkPolicyReconciler reconciles a ClusterwideNetworkPolicy object
type ClusterwideNetworkPolicyReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

const clusterwideNPNamespace = "firewall"

// +kubebuilder:rbac:groups=firewall.metal-stack.io,resources=clusterwidenetworkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=firewall.metal-stack.io,resources=clusterwidenetworkpolicies/status,verbs=get;update;patch

func (r *ClusterwideNetworkPolicyReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("ClusterwideNetworkPolicy", req.NamespacedName)

	requeue := ctrl.Result{
		Requeue:      true,
		RequeueAfter: 30 * time.Second,
	}

	// if network policy does not belong to the namespace where clusterwide network policies are stored:
	// update status with error message
	if req.Namespace != clusterwideNPNamespace {
		var clusterNP firewallv1.ClusterwideNetworkPolicy
		if err := r.Get(ctx, req.NamespacedName, &clusterNP); err != nil {
			return requeue, err
		}
		clusterNP.Status.Message = fmt.Sprintf("cluster wide network policies must be defined in namespace %s otherwise they won't take effect", clusterwideNPNamespace)
		if err := r.Update(ctx, &clusterNP); err != nil {
			log.Error(err, "unable to update ClusterwideNetworkPolicy", "namespacedname", req.NamespacedName)
			return requeue, nil
		}
		return ctrl.Result{}, nil
	}

	return ctrl.Result{}, nil
}

func (r *ClusterwideNetworkPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&firewallv1.ClusterwideNetworkPolicy{}).
		Complete(r)
}
