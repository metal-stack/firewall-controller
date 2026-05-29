package controllers

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/go-logr/logr"
	firewallv2 "github.com/metal-stack/firewall-controller-manager/api/v2"
	v2 "github.com/metal-stack/firewall-controller-manager/api/v2"
	"github.com/metal-stack/firewall-controller/v2/pkg/updater"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const firewallControllerService = "firewall-controller.service"

var (
	systemdServiceRestartWhitelist = []string{
		"droptailer.service",
		"firewall-controller.service",
		"nftables-exporter.service",
		"node-exporter.service",
		"tailscaled.service",
	}
)

type FirewallMonitorAnnotationController struct {
	ShootClient   client.Client
	SeedClient    client.Client
	FirewallName  string
	SeedNamespace string
	Log           logr.Logger
}

func (r *FirewallMonitorAnnotationController) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&firewallv2.FirewallMonitor{},
			builder.WithPredicates(
				predicate.AnnotationChangedPredicate{},
			),
		).
		WithEventFilter(predicate.Funcs{
			DeleteFunc: func(de event.DeleteEvent) bool {
				return false
			},
		}).
		WithEventFilter(predicate.NewPredicateFuncs(func(object client.Object) bool {
			return object.GetNamespace() == v2.FirewallShootNamespace && object.GetName() == r.FirewallName
		})).
		Named("FirewallMonitorAnnotationController").
		Complete(r)
}

func (r *FirewallMonitorAnnotationController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var (
		fw = &firewallv2.Firewall{
			ObjectMeta: metav1.ObjectMeta{
				Name:      r.FirewallName,
				Namespace: r.SeedNamespace,
			},
		}
		fwmon = &firewallv2.FirewallMonitor{}
	)

	if err := r.ShootClient.Get(ctx, req.NamespacedName, fwmon); err != nil {
		if apierrors.IsNotFound(err) {
			r.Log.V(1).Info("object is gone, stop reconciling")
			return reconcile.Result{}, nil
		}

		return reconcile.Result{}, fmt.Errorf("error retrieving object: %w", err)
	}

	if err := r.SeedClient.Get(ctx, client.ObjectKeyFromObject(fw), fw); err != nil {
		if apierrors.IsNotFound(err) {
			r.Log.V(1).Info("object is gone, stop reconciling")
			return reconcile.Result{}, nil
		}

		return reconcile.Result{}, fmt.Errorf("error retrieving object: %w", err)
	}

	services, ok := fwmon.Annotations[firewallv2.FirewallRestartSystemdServicesAnnotation]
	if !ok {
		return reconcile.Result{}, nil
	}

	var (
		restartFirewallController bool
		whitelist                 = systemdServiceRestartWhitelist
	)

	if overwrite, ok := fw.GetAnnotations()[v2.FirewallRestartSystemdServicesWhitelistAnnotation]; ok {
		whitelist = strings.Split(overwrite, ",")
	}

	for serviceName := range strings.SplitSeq(services, ",") {
		if !strings.HasSuffix(serviceName, ".service") {
			serviceName = serviceName + ".service"
		}

		if !slices.Contains(whitelist, serviceName) {
			r.Log.Info("skipping service restart because not in whitelist", "service-name", serviceName)
			continue
		}

		// If the firewall-controller itself should be restarted, we have to first remove the annotation from the node.
		// Otherwise, the annotation is never removed and it restarts itself indefinitely.
		if serviceName == firewallControllerService {
			restartFirewallController = true
			continue
		}

		r.Log.Info("restart service", "service-name", serviceName)
		if err := updater.Restart(ctx, serviceName); err != nil {
			r.Log.Error(err, "error restarting service", "service-name", serviceName)
		}
	}

	r.Log.Info("Removing annotation from firewall monitor", "annotation", firewallv2.FirewallRestartSystemdServicesAnnotation)

	patch := client.MergeFrom(fwmon.DeepCopy())
	delete(fwmon.Annotations, firewallv2.FirewallRestartSystemdServicesAnnotation)
	if err := r.ShootClient.Patch(ctx, fwmon, patch); err != nil {
		return reconcile.Result{}, err
	}

	if restartFirewallController {
		r.Log.Info("restart firewall-controller")
		if err := updater.Restart(ctx, firewallControllerService); err != nil {
			r.Log.Error(err, "error restarting firewall-controller")
		}
	}

	return ctrl.Result{}, nil
}
