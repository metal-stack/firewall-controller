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
	firewall "github.com/metal-stack/firewall-builder/pkg/firewall"
)

// FirewallReconciler reconciles a Firewall object
type FirewallReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=firewall.metal-stack.io,resources=firewalls,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=firewall.metal-stack.io,resources=firewalls/status,verbs=get;update;patch

func (r *FirewallReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("firewall", req.NamespacedName)

	var f firewallv1.Firewall
	if err := r.Get(ctx, req.NamespacedName, &f); err != nil {
		log.Error(err, "unable to get firewall")
		return ctrl.Result{}, err
	}
	spec := f.Spec
	interval := time.Second * 30
	if spec.Interval > 0 {
		interval = spec.Interval * time.Second
	}

	res := ctrl.Result{
		Requeue:      true,
		RequeueAfter: interval,
	}
	if !spec.Enabled {
		log.Info("firewall is disabled")
		return res, nil
	}

	c := firewall.NewCollector(&r.Log, spec.NftablesExportURL)
	ruleStats, err := c.Collect()
	if err != nil {
		return res, err
	}
	f.Status.FirewallStats = firewallv1.FirewallStats{
		RuleStats: ruleStats,
	}
	f.Status.Updated.Time = time.Now()

	log.Info("status", "s", f.Status.FirewallStats.RuleStats)
	if err := r.Update(ctx, &f); err != nil {
		log.Error(err, "unable to update firewall")
		return res, err
	}
	log.Info("firewall stats updated")

	return res, nil
}

func (r *FirewallReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&firewallv1.Firewall{}).
		Complete(r)
}
