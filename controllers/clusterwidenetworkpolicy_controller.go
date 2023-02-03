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

	"github.com/metal-stack/firewall-controller/pkg/dns"

	"github.com/go-logr/logr"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/util/workqueue"

	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	firewallv2 "github.com/metal-stack/firewall-controller-manager/api/v2"
	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
)

// ClusterwideNetworkPolicyReconciler reconciles a ClusterwideNetworkPolicy object
// +kubebuilder:rbac:groups=metal-stack.io,resources=events,verbs=create;patch
type ClusterwideNetworkPolicyReconciler struct {
	SeedClient  client.Client
	ShootClient client.Client

	FirewallName  string
	SeedNamespace string

	Log logr.Logger

	CreateFirewall CreateFirewall

	Interval time.Duration
	DnsProxy *dns.DNSProxy
	SkipDNS  bool
}

// SetupWithManager configures this controller to run in schedule
func (r *ClusterwideNetworkPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Interval == 0 {
		r.Interval = reconcilationInterval
	}

	scheduleChan := make(chan event.GenericEvent)
	if err := mgr.Add(r.getReconciliationTicker(scheduleChan)); err != nil {
		return fmt.Errorf("failed to add runnable to manager: %w", err)
	}

	firewallTrigger := handler.Funcs{
		CreateFunc: func(_ event.CreateEvent, rli workqueue.RateLimitingInterface) {
			rli.Add(reconcile.Request{NamespacedName: types.NamespacedName{Name: r.FirewallName, Namespace: r.SeedNamespace}})
		},
		UpdateFunc: func(_ event.UpdateEvent, rli workqueue.RateLimitingInterface) {
			rli.Add(reconcile.Request{NamespacedName: types.NamespacedName{Name: r.FirewallName, Namespace: r.SeedNamespace}})
		},
		DeleteFunc: func(_ event.DeleteEvent, rli workqueue.RateLimitingInterface) {
			rli.Add(reconcile.Request{NamespacedName: types.NamespacedName{Name: r.FirewallName, Namespace: r.SeedNamespace}})
		},
		GenericFunc: func(_ event.GenericEvent, rli workqueue.RateLimitingInterface) {
			rli.Add(reconcile.Request{NamespacedName: types.NamespacedName{Name: r.FirewallName, Namespace: r.SeedNamespace}})
		},
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&firewallv1.ClusterwideNetworkPolicy{}).
		Watches(&source.Channel{Source: scheduleChan}, firewallTrigger).
		Watches(&source.Kind{Type: &corev1.Service{}}, firewallTrigger).
		Complete(r)
}

// Reconcile ClusterwideNetworkPolicy and creates nftables rules accordingly
// +kubebuilder:rbac:groups=metal-stack.io,resources=clusterwidenetworkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=metal-stack.io,resources=clusterwidenetworkpolicies/status,verbs=get;update;patch
func (r *ClusterwideNetworkPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("cwnp", req.Name)

	var cwnps firewallv1.ClusterwideNetworkPolicyList
	if err := r.ShootClient.List(ctx, &cwnps, client.InNamespace(firewallv1.ClusterwideNetworkPolicyNamespace)); err != nil {
		return done, err
	}

	return r.reconcileRules(ctx, log, cwnps)
}

func (r *ClusterwideNetworkPolicyReconciler) reconcileRules(ctx context.Context, log logr.Logger, cwnps firewallv1.ClusterwideNetworkPolicyList) (ctrl.Result, error) {
	var f firewallv2.Firewall
	nn := types.NamespacedName{
		Name:      r.FirewallName,
		Namespace: r.SeedNamespace,
	}
	if err := r.SeedClient.Get(ctx, nn, &f); err != nil {
		return done, client.IgnoreNotFound(err)
	}

	// Set CWNP requeue interval
	if interval, err := time.ParseDuration(f.Spec.Interval); err == nil {
		r.Interval = interval
	} else {
		return done, fmt.Errorf("failed to parse Interval field: %w", err)
	}

	var services corev1.ServiceList
	if err := r.ShootClient.List(ctx, &services); err != nil {
		return done, err
	}
	nftablesFirewall := r.CreateFirewall(f, &cwnps, &services, r.DnsProxy, log)
	if err := r.manageDNSProxy(ctx, log, f, cwnps, nftablesFirewall); err != nil {
		return done, err
	}
	updated, err := nftablesFirewall.Reconcile()
	if err != nil {
		return done, err
	}

	if updated {
		for _, i := range cwnps.Items {
			o := i
			if err := r.ShootClient.Status().Update(ctx, &o); err != nil {
				return done, fmt.Errorf("failed to updated CWNP status: %w", err)
			}
		}
	}

	return done, nil
}

// manageDNSProxy start DNS proxy if toFQDN rules are present
// if rules were deleted it will stop running DNS proxy
func (r *ClusterwideNetworkPolicyReconciler) manageDNSProxy(
	ctx context.Context, log logr.Logger, f firewallv2.Firewall, cwnps firewallv1.ClusterwideNetworkPolicyList, nftablesFirewall FirewallInterface,
) (err error) {
	// Skipping is needed for testing
	if r.SkipDNS {
		return nil
	}

	enableDNS := len(cwnps.GetFQDNs()) > 0

	if err := nftablesFirewall.ReconcileNetconfTables(); err != nil {
		return fmt.Errorf("failed to reconcile nftables for DNS proxy: %w", err)
	}

	if enableDNS && r.DnsProxy == nil {
		log.Info("DNS Proxy is initialized")
		if r.DnsProxy, err = dns.NewDNSProxy(f.Spec.DNSPort, ctrl.Log.WithName("DNS proxy")); err != nil {
			return fmt.Errorf("failed to init DNS proxy: %w", err)
		}
		go r.DnsProxy.Run(ctx)
	} else if !enableDNS && r.DnsProxy != nil {
		log.Info("DNS Proxy is stopped")
		r.DnsProxy.Stop()
		r.DnsProxy = nil
	}

	// If proxy is ON, update DNS address(if it's set in spec)
	if r.DnsProxy != nil && f.Spec.DNSServerAddress != "" {
		if err = r.DnsProxy.UpdateDNSServerAddr(f.Spec.DNSServerAddress); err != nil {
			return fmt.Errorf("failed to update DNS server address: %w", err)
		}
	}

	return nil
}

// IMPORTANT!
// We shouldn't implement reconciliation loop by assigning RequeueAfter in result like it's done in Firewall controller.
// Here's the case when it would go bad:
//
//	DNS Proxy is ON and Firewall machine is rebooted.
//
// There will be at least 2 problems:
//  1. When it's rebooted, metal-networker will generate basic nftables config and apply it.
//     In basic config there's now DNAT rules required for DNS Proxy.
//  2. DNS Proxy is started by CWNP controller, and it will not be started until some CWNP resource is created/updated/deleted.
func (r *ClusterwideNetworkPolicyReconciler) getReconciliationTicker(scheduleChan chan<- event.GenericEvent) manager.RunnableFunc {
	return func(ctx context.Context) error {
		e := event.GenericEvent{}
		ticker := time.NewTicker(r.Interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				scheduleChan <- e
			case <-ctx.Done():
				return nil
			}
		}
	}
}
