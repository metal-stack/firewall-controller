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

	firewallv1 "github.com/metal-stack/firewall-builder/api/v1"
	"github.com/metal-stack/firewall-builder/pkg/suricata"
)

// NetworkIDSReconciler reconciles a NetworkIDS object
type NetworkIDSReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// Reconcile NetworkIDS
// +kubebuilder:rbac:groups=firewall.metal-stack.io,resources=NetworkIDSs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=firewall.metal-stack.io,resources=NetworkIDSs/status,verbs=get;update;patch
func (r *NetworkIDSReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("NetworkIDS", req.NamespacedName)

	var NetworkIDS firewallv1.NetworkIDS
	if err := r.Get(ctx, req.NamespacedName, &NetworkIDS); err != nil {
		log.Error(err, "unable to get NetworkIDS")
		return ctrl.Result{RequeueAfter: 10 * time.Second}, err
	}
	spec := NetworkIDS.Spec
	interval, err := time.ParseDuration(spec.Interval)
	if err != nil {
		interval = time.Minute
	}

	if spec.Enabled {
		log.Info("NetworkIDS is enabled", "interval", interval)
		s := suricata.New(spec.StatsLog)
		ss, err := s.Stats()
		if err != nil {
			return ctrl.Result{}, err
		}
		NetworkIDS.Status.IDSStatistic.Items = ss
		NetworkIDS.Status.Updated.Time = time.Now()
		if err := r.Update(ctx, &NetworkIDS); err != nil {
			log.Error(err, "unable to update NetworkIDS")
			return ctrl.Result{}, err
		}
		log.Info("ids stats updated")
		return ctrl.Result{RequeueAfter: interval}, nil
	}
	log.Info("NetworkIDS is disabled")
	return ctrl.Result{}, nil
}

// SetupWithManager create a new controller to reconcile NetworkIDS
func (r *NetworkIDSReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&firewallv1.NetworkIDS{}).
		Complete(r)
}
