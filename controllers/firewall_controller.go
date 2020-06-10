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
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/hashicorp/go-multierror"

	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
	"github.com/metal-stack/firewall-controller/pkg/collector"
	"github.com/metal-stack/firewall-controller/pkg/nftables"
	"github.com/metal-stack/firewall-controller/pkg/suricata"
	networking "k8s.io/api/networking/v1"
)

// FirewallReconciler reconciles a Firewall object
type FirewallReconciler struct {
	client.Client
	Log      logr.Logger
	Scheme   *runtime.Scheme
	recorder record.EventRecorder
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
// +kubebuilder:rbac:groups=metal-stack.io,resources=firewalls,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=metal-stack.io,resources=firewalls/status,verbs=get;update;patch
func (r *FirewallReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("firewall", req.NamespacedName)
	interval := firewallReconcileInterval

	var f firewallv1.Firewall
	if err := r.Get(ctx, req.NamespacedName, &f); err != nil {
		// we'll ignore not-found errors, since they can't be fixed by an immediate
		// requeue (we'll need to wait for a new notification), and we can get them
		// on deleted requests.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if err := r.validateFirewall(ctx, f); err != nil {
		r.recorder.Event(&f, "Warning", "Unapplicable", err.Error())
		// don't requeue invalid firewall objects
		return ctrl.Result{}, err
	}

	i, err := time.ParseDuration(f.Spec.Interval)
	if err != nil {
		interval = i
	}

	requeue := ctrl.Result{
		RequeueAfter: interval,
	}

	var errors *multierror.Error
	log.Info("migrating old global network policies to kind ClusterwideNetworkPolicy")
	if err = r.migrateToClusterwideNetworkPolicy(ctx, f, log); err != nil {
		errors = multierror.Append(errors, err)
	}

	log.Info("reconciling nftables rules")
	if err = r.reconcileRules(ctx, f, log); err != nil {
		errors = multierror.Append(errors, err)
	}

	log.Info("updating status field")
	if err = r.updateStatus(ctx, f, log); err != nil {
		errors = multierror.Append(errors, err)
	}
	r.recorder.Event(&f, "Normal", "Reconciled", "nftables rules and statistics")

	if errors.ErrorOrNil() != nil {
		return requeue, errors
	}
	log.Info("reconciled firewall")
	return requeue, nil
}

// validateFirewall validates a firewall object:
// it must be a singularity in a fixed namespace
// and for the triggered reconcilation requests
func (r *FirewallReconciler) validateFirewall(ctx context.Context, f firewallv1.Firewall) error {
	if f.Namespace != firewallNamespace {
		return fmt.Errorf("firewall must be defined in namespace %s otherwise it won't take effect", firewallNamespace)
	}

	if f.Name != firewallName {
		return fmt.Errorf("firewall object is a singularity - it must have the name %s", firewallName)
	}

	return nil
}

// migrateToClusterwideNetworkPolicy migrates old network policy objects to the new kind ClusterwideNetworkPolicy
func (r *FirewallReconciler) migrateToClusterwideNetworkPolicy(ctx context.Context, f firewallv1.Firewall, log logr.Logger) error {
	npsToIgnore := []string{"egress-allow-http", "egress-allow-https", "egress-allow-any", "egress-allow-dns", "egress-allow-ntp"}

	var nps networking.NetworkPolicyList
	if err := r.Client.List(ctx, &nps); err != nil {
		return err
	}

	n := 0
	for _, np := range nps.Items {
		s := np.Spec
		if len(s.PodSelector.MatchExpressions) != 0 || len(s.PodSelector.MatchLabels) != 0 {
			continue
		}

		// is one of the old network policy objects like egress-allow-http that are replaced by cluster wide ones installed by gepm
		if contains(npsToIgnore, np.Name) {
			continue
		}

		cwnp, err := convert(np)
		if err != nil {
			return fmt.Errorf("could not migrate network policy to a cluster-wide np: %w", err)
		}

		if cwnp == nil {
			// nothing to do here because network policy translates to an empty cwnp
			continue
		}

		var current firewallv1.ClusterwideNetworkPolicy
		err = r.Get(ctx, types.NamespacedName{Name: cwnp.Name, Namespace: firewallNamespace}, &current)

		// cwnp already exists: don't try to merge or update - just ignore
		if err == nil {
			continue
		}

		if errors.IsNotFound(err) {
			err = r.Client.Create(ctx, cwnp)
		}

		if err != nil {
			return fmt.Errorf("could not migrate to cluster-wide network policy: %w", err)
		}
		n++
	}

	log.Info("migrated network policies to cluster-wide network policies", "n", n)

	return nil
}

func contains(l []string, e string) bool {
	for _, elem := range l {
		if elem == e {
			return true
		}
	}
	return false
}

// converts a network-policy object that was used before in a cluster-wide manner to the new CRD
func convert(np networking.NetworkPolicy) (*firewallv1.ClusterwideNetworkPolicy, error) {
	cwnp := firewallv1.ClusterwideNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      np.Name,
			Namespace: firewallNamespace,
		},
	}
	newEgresses := []firewallv1.EgressRule{}
	for _, egress := range np.Spec.Egress {
		newTos := []networking.IPBlock{}
		for _, to := range egress.To {
			if to.NamespaceSelector != nil {
				return nil, fmt.Errorf("np %v contains a namespace selector and is not applicable for a conversion to a cluster-wide network policy", np.ObjectMeta)
			}
			if to.PodSelector != nil {
				return nil, fmt.Errorf("np %v contains a pod selector and is not applicable for a conversion to a cluster-wide network policy", np.ObjectMeta)
			}
			if to.IPBlock == nil {
				continue
			}
			newTos = append(newTos, *to.IPBlock)
		}
		if len(newTos) == 0 {
			continue
		}
		newEgresses = append(newEgresses, firewallv1.EgressRule{
			Ports: egress.Ports,
			To:    newTos,
		})
	}
	if len(newEgresses) == 0 {
		return nil, nil
	}
	cwnp.Spec = firewallv1.PolicySpec{
		Egress: newEgresses,
	}
	return &cwnp, nil
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

	nftablesFirewall := nftables.NewFirewall(&clusterNPs, &services, f.Spec)
	log.Info("loaded rules", "ingress", len(nftablesFirewall.Ingress), "egress", len(nftablesFirewall.Egress))

	if err := nftablesFirewall.Reconcile(); err != nil {
		return err
	}

	return nil
}

// updateStatus updates the status field for this firewall
func (r *FirewallReconciler) updateStatus(ctx context.Context, f firewallv1.Firewall, log logr.Logger) error {
	c := collector.NewNFTablesCollector(&r.Log)
	ruleStats := c.CollectRuleStats()

	f.Status.FirewallStats = firewallv1.FirewallStats{
		RuleStats: ruleStats,
	}
	deviceStats, err := c.CollectDeviceStats()
	if err != nil {
		return err
	}
	f.Status.FirewallStats.DeviceStats = deviceStats

	s := suricata.New()
	ss, err := s.InterfaceStats()
	if err != nil {
		return err
	}
	idsStats := firewallv1.IDSStatsByDevice{}
	for iface, stat := range *ss {
		idsStats[iface] = firewallv1.InterfaceStat{
			Drop:             stat.Drop,
			InvalidChecksums: stat.InvalidChecksums,
			Packets:          stat.Pkts,
		}
	}
	f.Status.FirewallStats.IDSStats = idsStats

	f.Status.Updated.Time = time.Now()

	if err := r.Status().Update(ctx, &f); err != nil {
		return fmt.Errorf("unable to update firewall status, err: %w", err)
	}
	return nil
}

// SetupWithManager configures this controller to watch for the CRDs in a specific namespace
func (r *FirewallReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.recorder = mgr.GetEventRecorderFor("FirewallController")
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
		Watches(&source.Kind{Type: &networking.NetworkPolicy{}}, triggerFirewallReconcilation).
		Watches(&source.Kind{Type: &corev1.Service{}}, triggerFirewallReconcilation).
		Complete(r)
}
