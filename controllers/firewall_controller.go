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
	"path/filepath"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	firewallv1 "github.com/metal-stack/firewall-builder/api/v1"
	"github.com/metal-stack/firewall-builder/pkg/nftables"
	"github.com/metal-stack/firewall-builder/pkg/trafficcontrol"
)

// FirewallReconciler reconciles a Firewall object
type FirewallReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

const (
	firewallReconcileInterval = time.Second * 10
	firewallNamespace         = "firewall"
	firewallName              = "firewall"
)

// Reconcile reconciles a firewall by:
// - reading ClusterwideNetworkPolicies and Services of type Loadbalancer
// - rendering nftables rules
// - updating the firewall object with nftable rule statistics grouped by action
// +kubebuilder:rbac:groups=firewall.metal-stack.io,resources=firewalls,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=firewall.metal-stack.io,resources=firewalls/status,verbs=get;update;patch
func (r *FirewallReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("firewall", req.NamespacedName)
	interval := firewallReconcileInterval
	requeue := ctrl.Result{
		RequeueAfter: interval,
	}

	var f firewallv1.Firewall
	if err := r.Get(ctx, req.NamespacedName, &f); err != nil {
		// we'll ignore not-found errors, since they can't be fixed by an immediate
		// requeue (we'll need to wait for a new notification), and we can get them
		// on deleted requests.
		return ctrl.Result{}, client.IgnoreNotFound(err)
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
		RequeueAfter: interval,
	}
	if !f.Spec.Enabled {
		log.Info("reconciling firewall is disabled")
		return requeue, nil
	}

	log.Info("reconciling nftables rules")
	if err = r.reconcileRules(ctx, f, log); err != nil {
		return requeue, err
	}

	log.Info("reconciling traffic control rules")
	if err = r.reconcileTrafficControl(ctx, f, log); err != nil {
		return requeue, err
	}

	log.Info("updating status field")
	if err = r.updateStatus(ctx, f, log); err != nil {
		return requeue, err
	}

	log.Info("reconciled firewall")
	return requeue, err
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
func (r *FirewallReconciler) reconcileRules(ctx context.Context, f firewallv1.Firewall, log logr.Logger) error {
	var clusterNPs firewallv1.ClusterwideNetworkPolicyList
	if err := r.List(ctx, &clusterNPs, client.InNamespace(f.Namespace)); err != nil {
		return err
	}

	var services v1.ServiceList
	if err := r.List(ctx, &services); err != nil {
		return err
	}

	nftablesFirewall := nftables.NewFirewall(&clusterNPs, &services, f.Spec.Ipv4RuleFile, f.Spec.DryRun)
	log.Info("loaded rules", "ingress", len(nftablesFirewall.Ingress), "egress", len(nftablesFirewall.Egress))

	if err := nftablesFirewall.Reconcile(); err != nil {
		return err
	}

	return nil
}
func (r *FirewallReconciler) reconcileTrafficControl(ctx context.Context, f firewallv1.Firewall, log logr.Logger) error {
	tc, err := trafficcontrol.New()
	if err != nil {
		return err
	}

	tcSpec := f.Spec.TrafficControl
	for _, t := range tcSpec.Rules {
		match, err := filepath.Match(tcSpec.Interfaces, t.Interface)
		if err != nil {
			return err
		}
		if !match {
			log.Info("skipping interface because it does not match the allowed interfaces pattern in the traffic control spec", "iface", t.Interface, "pattern", tcSpec.Interfaces)
			continue
		}

		log.Info("reconcile rate for", "iface", t.Interface, "rate", t.Rate)
		if f.Spec.DryRun {
			continue
		}

		hasRate, err := tc.HasRateLimit(t.Interface, t.Rate)
		if err != nil {
			return err
		}

		if hasRate {
			continue
		}

		err = tc.Clear(t.Interface)
		if err != nil {
			return err
		}

		err = tc.AddRateLimit(t.Interface, t.Rate)
		if err != nil {
			return err
		}
	}
	return nil
}

// updateStatus updates the status field for this firewall
func (r *FirewallReconciler) updateStatus(ctx context.Context, f firewallv1.Firewall, log logr.Logger) error {
	spec := f.Spec
	c := nftables.NewCollector(&log, spec.NftablesExportURL)

	ruleStats, err := c.Collect()
	if err != nil {
		return err
	}

	tc, err := trafficcontrol.New()
	if err != nil {
		return err
	}

	tcStats := firewallv1.TrafficControlStatsByIface{}
	tcSpec := spec.TrafficControl
	for _, t := range tcSpec.Rules {
		match, err := filepath.Match(tcSpec.Interfaces, t.Interface)
		if err != nil {
			return err
		}
		if !match {
			continue
		}
		s, err := tc.ShowTbfRule(t.Interface)
		if err != nil {
			log.Info("could not get tc rule stats", "err", err)
			continue
		}
		tcStats[t.Interface] = firewallv1.TrafficControlStats{
			Bytes:      s.Bytes,
			Packets:    s.Packets,
			Drops:      s.Drops,
			Overlimits: s.Overlimits,
			Requeues:   s.Requeues,
			Backlog:    s.Backlog,
			Qlen:       s.Qlen,
		}
	}

	f.Status.FirewallStats = firewallv1.FirewallStats{
		RuleStats:           ruleStats,
		TrafficControlStats: tcStats,
	}
	f.Status.Updated.Time = time.Now()

	if err := r.Status().Update(ctx, &f); err != nil {
		return fmt.Errorf("unable to update firewall status, err: %w", err)
	}
	return nil
}

func (r *FirewallReconciler) SetupWithManager(mgr ctrl.Manager) error {
	mapToFirewallReconcilation := handler.ToRequestsFunc(
		func(a handler.MapObject) []reconcile.Request {
			return []reconcile.Request{
				{NamespacedName: types.NamespacedName{
					Name:      firewallName,
					Namespace: firewallNamespace,
				}},
			}
		})
	triggerFirewallReconcilation := &handler.EnqueueRequestsFromMapFunc{
		ToRequests: mapToFirewallReconcilation,
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&firewallv1.Firewall{}).
		// don't trigger a reconcilation for status updates
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Watches(&source.Kind{Type: &firewallv1.ClusterwideNetworkPolicy{}}, triggerFirewallReconcilation).
		Watches(&source.Kind{Type: &corev1.Service{}}, triggerFirewallReconcilation).
		Complete(r)
}
