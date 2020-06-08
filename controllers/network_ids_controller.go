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
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
)

// NetworkIDSReconciler reconciles a NetworkIDS object
type NetworkIDSReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

const (
	networkIDSReconcileInterval = time.Second * 10
)

// Reconcile NetworkIDS
// +kubebuilder:rbac:groups=metal-stack.io,resources=NetworkIDSs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=metal-stack.io,resources=NetworkIDSs/status,verbs=get;update;patch
func (r *NetworkIDSReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("NetworkIDS", req.NamespacedName)
	interval := networkIDSReconcileInterval

	var ids firewallv1.NetworkIDS
	if err := r.Get(ctx, req.NamespacedName, &ids); err != nil {
		// we'll ignore not-found errors, since they can't be fixed by an immediate
		// requeue (we'll need to wait for a new notification), and we can get them
		// on deleted requests.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	spec := ids.Spec
	requeue := ctrl.Result{
		RequeueAfter: interval,
	}

	if !spec.Enabled {
		log.Info("NetworkIDS is disabled")
		return requeue, nil
	}

	log.Info("reconcile NetworkIDS")

	// FIXME if enabled configure to forward to a user specified Target

	ids.Status.Updated.Time = time.Now()
	if err := r.Status().Update(ctx, &ids); err != nil {
		log.Error(err, "unable to update NetworkIDS")
		return ctrl.Result{}, err
	}
	log.Info("ids stats updated")
	return requeue, nil
}

// SetupWithManager create a new controller to reconcile NetworkIDS
func (r *NetworkIDSReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&firewallv1.NetworkIDS{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}
