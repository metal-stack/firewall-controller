package controllers

import (
	"context"
	"fmt"
	"time"

	"go4.org/netipx"

	"github.com/metal-stack/firewall-controller/v2/pkg/dns"
	"github.com/metal-stack/firewall-controller/v2/pkg/helper"
	"github.com/metal-stack/firewall-controller/v2/pkg/nftables"

	"github.com/go-logr/logr"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/source"

	firewallv2 "github.com/metal-stack/firewall-controller-manager/api/v2"
	firewallv1 "github.com/metal-stack/firewall-controller/v2/api/v1"
)

// ClusterwideNetworkPolicyReconciler reconciles a ClusterwideNetworkPolicy object
// +kubebuilder:rbac:groups=metal-stack.io,resources=events,verbs=create;patch
type ClusterwideNetworkPolicyReconciler struct {
	SeedClient  client.Client
	ShootClient client.Client

	FirewallName  string
	SeedNamespace string

	Log      logr.Logger
	Recorder record.EventRecorder

	Interval time.Duration
	DnsProxy *dns.DNSProxy
	SkipDNS  bool
}

// SetupWithManager configures this controller to run in schedule
func (r *ClusterwideNetworkPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Interval == 0 {
		r.Interval = reconciliationInterval
	}

	scheduleChan := make(chan event.GenericEvent)
	if err := mgr.Add(r.getReconciliationTicker(scheduleChan)); err != nil {
		return fmt.Errorf("failed to add runnable to manager: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&firewallv1.ClusterwideNetworkPolicy{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&corev1.Service{}, &handler.EnqueueRequestForObject{}).
		WatchesRawSource(&source.Channel{Source: scheduleChan}, &handler.EnqueueRequestForObject{}).
		Complete(r)
}

// Reconcile ClusterwideNetworkPolicy and creates nftables rules accordingly.
// - services of type load balancer
//
// +kubebuilder:rbac:groups=metal-stack.io,resources=clusterwidenetworkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=metal-stack.io,resources=clusterwidenetworkpolicies/status,verbs=get;update;patch

func (r *ClusterwideNetworkPolicyReconciler) Reconcile(ctx context.Context, _ ctrl.Request) (ctrl.Result, error) {
	var cwnps firewallv1.ClusterwideNetworkPolicyList
	if err := r.ShootClient.List(ctx, &cwnps, client.InNamespace(firewallv1.ClusterwideNetworkPolicyNamespace)); err != nil {
		return ctrl.Result{}, err
	}

	f := &firewallv2.Firewall{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.FirewallName,
			Namespace: r.SeedNamespace,
		},
	}
	if err := r.SeedClient.Get(ctx, client.ObjectKeyFromObject(f), f); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Set CWNP requeue interval
	if interval, err := time.ParseDuration(f.Spec.Interval); err == nil {
		r.Interval = interval
	} else {
		return ctrl.Result{}, fmt.Errorf("failed to parse Interval field: %w", err)
	}

	var services corev1.ServiceList
	if err := r.ShootClient.List(ctx, &services); err != nil {
		return ctrl.Result{}, err
	}

	validCwnps, err := r.allowedCWNPs(ctx, cwnps.Items, f.Spec.AllowedNetworks)
	if err != nil {
		return ctrl.Result{}, err
	}
	cwnps.Items = validCwnps

	nftablesFirewall := nftables.NewFirewall(f, &cwnps, &services, r.DnsProxy, r.Log, r.Recorder)
	if err := r.manageDNSProxy(ctx, f, cwnps, nftablesFirewall); err != nil {
		return ctrl.Result{}, err
	}
	updated, err := nftablesFirewall.Reconcile()
	if err != nil {
		return ctrl.Result{}, err
	}

	if updated {
		for _, i := range cwnps.Items {
			o := i
			if err := r.updateCWNPState(ctx, o, firewallv1.PolicyDeploymentStateDeployed, ""); err != nil {
				return ctrl.Result{}, err
			}
		}
	}

	return ctrl.Result{}, nil
}

// manageDNSProxy start DNS proxy if toFQDN rules are present
// if rules were deleted it will stop running DNS proxy
func (r *ClusterwideNetworkPolicyReconciler) manageDNSProxy(
	ctx context.Context, f *firewallv2.Firewall, cwnps firewallv1.ClusterwideNetworkPolicyList, nftablesFirewall *nftables.Firewall,
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
		r.Log.Info("DNS Proxy is initialized")
		if r.DnsProxy, err = dns.NewDNSProxy(f.Spec.DNSServerAddress, f.Spec.DNSPort, r.ShootClient, ctrl.Log.WithName("DNS proxy")); err != nil {
			return fmt.Errorf("failed to init DNS proxy: %w", err)
		}
		go r.DnsProxy.Run(ctx)
	} else if !enableDNS && r.DnsProxy != nil {
		r.Log.Info("DNS Proxy is stopped")
		r.DnsProxy.Stop()
		r.DnsProxy = nil
	}

	// If proxy is ON, update DNS address(if it's set in spec)
	if r.DnsProxy != nil && f.Spec.DNSServerAddress != "" {
		port := uint(53)
		if f.Spec.DNSPort != nil {
			port = *f.Spec.DNSPort
		}
		addr := fmt.Sprintf("%s:%d", f.Spec.DNSServerAddress, port)
		if err = r.DnsProxy.UpdateDNSServerAddr(addr); err != nil {
			return fmt.Errorf("failed to update DNS server address: %w", err)
		}
	}

	return nil
}

// TODO: the interval can change over the lifetime of a firewall resource
// in case the interval has changed nothing happens at the moment
// we need to implement the recreation of the ticker
//
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
		e := event.GenericEvent{Object: &firewallv1.ClusterwideNetworkPolicy{}}
		ticker := time.NewTicker(r.Interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				r.Log.Info("requesting cwnp reconcile due to reconciliation ticker event")
				scheduleChan <- e
			case <-ctx.Done():
				return nil
			}
		}
	}
}

func (r *ClusterwideNetworkPolicyReconciler) allowedCWNPs(ctx context.Context, cwnps []firewallv1.ClusterwideNetworkPolicy, allowedNetworks firewallv2.AllowedNetworks) ([]firewallv1.ClusterwideNetworkPolicy, error) {
	if len(allowedNetworks.Egress) == 0 && len(allowedNetworks.Ingress) == 0 {
		return cwnps, nil
	}

	validCWNPs := make([]firewallv1.ClusterwideNetworkPolicy, 0, len(cwnps))

	egressSet, err := helper.BuildNetworksIPSet(allowedNetworks.Egress)
	if err != nil {
		return nil, err
	}

	ingressSet, err := helper.BuildNetworksIPSet(allowedNetworks.Ingress)
	if err != nil {
		return nil, err
	}

	for _, cwnp := range cwnps {
		oke, err := r.validateCWNPEgressTargetPrefix(cwnp, egressSet)
		if err != nil {
			return nil, err
		}
		oki, err := r.validateCWNPIngressTargetPrefix(cwnp, ingressSet)
		if err != nil {
			return nil, err
		}

		if !oki || !oke {
			// at least one of ingress and/or egress is not in the allowed network set
			if err := r.updateCWNPState(ctx, cwnp, firewallv1.PolicyDeploymentStateIgnored, "ingress/egress does not match allowed networks"); err != nil {
				return nil, err
			}
			continue
		}

		validCWNPs = append(validCWNPs, cwnp)
	}

	return validCWNPs, nil
}

func (r *ClusterwideNetworkPolicyReconciler) updateCWNPState(ctx context.Context, cwnp firewallv1.ClusterwideNetworkPolicy, state firewallv1.PolicyDeploymentState, msg string) error {
	cwnp.Status.Message = msg
	cwnp.Status.State = state

	if err := r.ShootClient.Status().Update(ctx, &cwnp); err != nil {
		return fmt.Errorf("failed to update status of CWNP %q to %q: %w", cwnp.Name, state, err)
	}
	return nil
}

func (r *ClusterwideNetworkPolicyReconciler) validateCWNPEgressTargetPrefix(cwnp firewallv1.ClusterwideNetworkPolicy, ipSet *netipx.IPSet) (bool, error) {
	for _, egress := range cwnp.Spec.Egress {
		for _, to := range egress.To {
			if ok, err := helper.ValidateCIDR(&cwnp, to.CIDR, ipSet, r.Recorder); !ok {
				return false, err
			}
		}
	}
	return true, nil
}

func (r *ClusterwideNetworkPolicyReconciler) validateCWNPIngressTargetPrefix(cwnp firewallv1.ClusterwideNetworkPolicy, ipSet *netipx.IPSet) (bool, error) {
	for _, ingress := range cwnp.Spec.Ingress {
		for _, from := range ingress.From {
			if ok, err := helper.ValidateCIDR(&cwnp, from.CIDR, ipSet, r.Recorder); !ok {
				return false, err
			}
		}
	}
	return true, nil
}
