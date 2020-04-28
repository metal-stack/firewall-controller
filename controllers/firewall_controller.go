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
	"github.com/prometheus/common/log"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/source"

	firewallv1 "github.com/metal-stack/firewall-builder/api/v1"
	firewall "github.com/metal-stack/firewall-builder/pkg/firewall"
	"github.com/metal-stack/firewall-builder/pkg/nftables"
)

// FirewallReconciler reconciles a Firewall object
type FirewallReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

const (
	firewallReconcileInterval = time.Second * 30
	firewallNamespace         = "firewall"
	firewallName              = "firewall"
)

// +kubebuilder:rbac:groups=firewall.metal-stack.io,resources=firewalls,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=firewall.metal-stack.io,resources=firewalls/status,verbs=get;update;patch

func (r *FirewallReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("firewall", req.NamespacedName)
	interval := firewallReconcileInterval
	requeue := ctrl.Result{
		Requeue:      true,
		RequeueAfter: interval,
	}

	var f firewallv1.Firewall
	if err := r.Get(ctx, req.NamespacedName, &f); err != nil {
		return requeue, err
	}

	if err := r.validateFirewall(ctx, f); err != nil {
		// don't requeue invalid firewall objects
		return ctrl.Result{}, err
	}

	i, err := time.ParseDuration(f.Spec.Interval)
	if err != nil {
		interval = i
	}

	requeue = ctrl.Result{
		Requeue:      true,
		RequeueAfter: interval,
	}
	if !f.Spec.Enabled {
		return requeue, nil
	}

	log.Info("reconciling nftables rules")
	if err = r.reconcileRules(ctx, f); err != nil {
		return requeue, err
	}

	log.Info("updating status field for firewall object")
	if err = r.updateStatus(ctx, f); err != nil {
		return requeue, err
	}

	log.Info("reconciled firewall")
	return requeue, nil
}

// validateFirewall validates a firewall object:
// it must be a singularity in a fixed namespace
// and for the triggered reconcilation requests
func (r *FirewallReconciler) validateFirewall(ctx context.Context, f firewallv1.Firewall) error {
	if f.Namespace != firewallNamespace {
		f.Status.Message = fmt.Sprintf("firewall must be defined in namespace %s otherwise they won't take effect", firewallNamespace)
		if err := r.Update(ctx, &f); err != nil {
			return fmt.Errorf("unable to update firewall, namespace: %s, name: %s, err: %w", f.Namespace, f.Name, err)
		}
	}

	if f.Name != firewallName {
		f.Status.Message = fmt.Sprintf("there must be only one object of kind firewall in the namespace %s with name %s", firewallNamespace, firewallName)
		if err := r.Update(ctx, &f); err != nil {
			return fmt.Errorf("unable to update firewall, namespace: %s, name: %s, err: %w", f.Namespace, f.Name, err)
		}
	}

	return nil
}

// reconcileRules reconciles the nftable rules for this firewall
func (r *FirewallReconciler) reconcileRules(ctx context.Context, f firewallv1.Firewall) error {
	var clusterNPs firewallv1.ClusterwideNetworkPolicyList
	if err := r.List(ctx, &clusterNPs, client.InNamespace(f.Namespace)); err != nil {
		return err
	}

	var services v1.ServiceList
	if err := r.List(ctx, &services); err != nil {
		return err
	}

	nftablesFirewall := nftables.NewFirewall(&clusterNPs, &services, f.Spec.Ipv4RuleFile, f.Spec.DryRun)
	log.Info("loaded firewall rules", "ingress", nftablesFirewall.Ingress, "egress", nftablesFirewall.Egress)

	if err := nftablesFirewall.Reconcile(); err != nil {
		return err
	}

	return nil
}

// updateStatus updates the status field for this firewall
func (r *FirewallReconciler) updateStatus(ctx context.Context, f firewallv1.Firewall) error {
	c := firewall.NewCollector(&r.Log, f.Spec.NftablesExportURL)

	ruleStats, err := c.Collect()
	if err != nil {
		return err
	}

	f.Status.FirewallStats = firewallv1.FirewallStats{
		RuleStats: ruleStats,
	}
	f.Status.Updated.Time = time.Now()

	if err := r.Update(ctx, &f); err != nil {
		return fmt.Errorf("unable to update firewall, err: %w", err)
	}
	return nil
}

func (r *FirewallReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&firewallv1.Firewall{}).
		Watches(&source.Kind{Type: &firewallv1.ClusterwideNetworkPolicy{}}, newEnqueueReconcilationHandler(firewallNamespace, firewallName)).
		Watches(&source.Kind{Type: &corev1.Service{}}, newEnqueueReconcilationHandler(firewallNamespace, firewallName)).
		Complete(r)
}
