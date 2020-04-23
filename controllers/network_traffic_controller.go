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

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	firewallv1 "github.com/metal-stack/firewall-builder/api/v1"
)

// NetworkTrafficReconciler reconciles a NetworkTraffic object
type NetworkTrafficReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=firewall.metal-stack.io,resources=networktraffics,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=firewall.metal-stack.io,resources=networktraffics/status,verbs=get;update;patch

func (r *NetworkTrafficReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	_ = context.Background()
	_ = r.Log.WithValues("network", req.NamespacedName)

	ctx := context.Background()

	var networkTraffic firewallv1.NetworkTraffic
	if err := r.Get(ctx, req.NamespacedName, &networkTraffic); err != nil {
		r.Log.Error(err, "unable to get networkTraffic")
		return ctrl.Result{}, err
	}

	// TODO implement here
	if networkTraffic.Spec.Enabled {
		r.Log.Info("networkTraffic is enabled")
	} else {
		r.Log.Info("networkTraffic is disabled")
	}

	return ctrl.Result{}, nil
}

func (r *NetworkTrafficReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&firewallv1.NetworkTraffic{}).
		Complete(r)
}
