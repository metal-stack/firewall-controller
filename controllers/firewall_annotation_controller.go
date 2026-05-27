package controllers

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	firewallv2 "github.com/metal-stack/firewall-controller-manager/api/v2"
	firewallv1 "github.com/metal-stack/firewall-controller/v2/api/v1"
	"github.com/metal-stack/firewall-controller/v2/pkg/updater"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type FirewallAnnotationController struct {
	SeedClient   client.Client
	FirewallName string
	Namespace    string
	Log          logr.Logger
}

func (r *FirewallAnnotationController) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&firewallv2.Firewall{},
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
			return object.GetNamespace() == r.Namespace && object.GetName() == r.FirewallName
		})).
		Named("FirewallAnnotationController").
		Complete(r)
}

func (r *FirewallAnnotationController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	fw := &firewallv2.Firewall{}

	if err := r.SeedClient.Get(ctx, req.NamespacedName, fw); err != nil {
		if apierrors.IsNotFound(err) {
			r.Log.V(1).Info("object is gone, stop reconciling")
			return reconcile.Result{}, nil
		}

		return reconcile.Result{}, fmt.Errorf("error retrieving object: %w", err)
	}

	services, ok := fw.Annotations[firewallv1.AnnotationRestartSystemdServices]
	if !ok {
		return reconcile.Result{}, nil
	}

	var (
		restartFirewallController bool
	)

	for serviceName := range strings.SplitSeq(services, ",") {
		if !strings.HasSuffix(serviceName, ".service") {
			serviceName = serviceName + ".service"
		}
		// If the firewall-controller itself should be restarted, we have to first remove the annotation from the node.
		// Otherwise, the annotation is never removed and it restarts itself indefinitely.
		if serviceName == "firewall-controller.service" {
			restartFirewallController = true
			continue
		}

		r.Log.Info("restart service", "service-name", serviceName)
		if err := updater.Restart(ctx, serviceName); err != nil {
			r.Log.Error(err, "error restarting service", "service-name", serviceName)
		}
	}

	r.Log.Info("Removing annotation from firewall", "annotation", firewallv1.AnnotationRestartSystemdServices)
	patch := client.MergeFrom(fw.DeepCopy())
	delete(fw.Annotations, firewallv1.AnnotationRestartSystemdServices)
	if err := r.SeedClient.Patch(ctx, fw, patch); err != nil {
		return reconcile.Result{}, err
	}

	if restartFirewallController {
		r.Log.Info("restart firewall-controller")
		if err := updater.Restart(ctx, "firewall-controller.service"); err != nil {
			r.Log.Error(err, "error restarting firewall-controller")
		}
	}

	return ctrl.Result{}, nil
}
