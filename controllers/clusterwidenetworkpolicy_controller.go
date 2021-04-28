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
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
	"github.com/metal-stack/firewall-controller/pkg/dns"
	"github.com/metal-stack/firewall-controller/pkg/nftables"
)

// ClusterwideNetworkPolicyReconciler reconciles a ClusterwideNetworkPolicy object
// +kubebuilder:rbac:groups=metal-stack.io,resources=events,verbs=create;patch
type ClusterwideNetworkPolicyReconciler struct {
	client.Client
	Log      logr.Logger
	Scheme   *runtime.Scheme
	Cache    *dns.DNSCache
	recorder record.EventRecorder
}

// Reconcile ClusterwideNetworkPolicy and creates nftables rules accordingly
// +kubebuilder:rbac:groups=metal-stack.io,resources=clusterwidenetworkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=metal-stack.io,resources=clusterwidenetworkpolicies/status,verbs=get;update;patch
func (r *ClusterwideNetworkPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("cwnp", req.Name)

	var clusterNP firewallv1.ClusterwideNetworkPolicy
	if err := r.Get(ctx, req.NamespacedName, &clusterNP); err != nil {
		return done, client.IgnoreNotFound(err)
	}

	// if network policy does not belong to the namespace where clusterwide network policies are stored:
	// update status with error message
	if req.Namespace != firewallv1.ClusterwideNetworkPolicyNamespace {
		r.recorder.Event(
			&clusterNP,
			corev1.EventTypeWarning,
			"Unapplicable",
			fmt.Sprintf("cluster wide network policies must be defined in namespace %s otherwise they won't take effect", firewallv1.ClusterwideNetworkPolicyNamespace),
		)
		return done, nil
	}

	err := clusterNP.Spec.Validate()
	if err != nil {
		r.recorder.Event(
			&clusterNP,
			corev1.EventTypeWarning,
			"Unapplicable",
			fmt.Sprintf("cluster wide network policy is not valid: %v", err),
		)
		return done, nil
	}

	// Get Firewall resource
	var f firewallv1.Firewall
	namespacedName := types.NamespacedName{
		Name:      firewallName,
		Namespace: firewallv1.ClusterwideNetworkPolicyNamespace,
	}
	if err := r.Get(ctx, namespacedName, &f); err != nil {
		if apierrors.IsNotFound(err) {
			defaultFw := nftables.NewDefaultFirewall()
			log.Info("flushing k8s firewall rules")
			err := defaultFw.Flush()
			if err == nil {
				return done, nil
			}
			return firewallRequeue, err
		}

		return done, client.IgnoreNotFound(err)
	}

	if err := r.reconcileRules(ctx, f, log); err != nil {
		return firewallRequeue, err
	}

	return done, nil
}

func (r *ClusterwideNetworkPolicyReconciler) reconcileRules(
	ctx context.Context,
	firewall firewallv1.Firewall,
	log logr.Logger,
) error {
	var clusterNPs firewallv1.ClusterwideNetworkPolicyList
	if err := r.List(ctx, &clusterNPs, client.InNamespace(firewallv1.ClusterwideNetworkPolicyNamespace)); err != nil {
		return err
	}

	var services corev1.ServiceList
	if err := r.List(ctx, &services); err != nil {
		return err
	}

	nftablesFirewall := nftables.NewFirewall(&clusterNPs, &services, firewall.Spec, log)
	if err := nftablesFirewall.Reconcile(); err != nil {
		return err
	}

	return nil
}

// SetupWithManager configures this controller to watch for ClusterwideNetworkPolicy CRD
func (r *ClusterwideNetworkPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.recorder = mgr.GetEventRecorderFor("FirewallController")
	return ctrl.NewControllerManagedBy(mgr).
		For(&firewallv1.ClusterwideNetworkPolicy{}).
		Complete(r)
}
