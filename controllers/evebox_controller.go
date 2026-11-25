package controllers

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	"github.com/txn2/txeh"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	firewallv1 "github.com/metal-stack/firewall-controller/v2/api/v1"
	"github.com/metal-stack/firewall-controller/v2/pkg/systemd"
)

const (
	// eveboxHostname is the hostname under which the evebox server in the shoot is reachable from the firewall.
	// the evebox server url in the firewall spec is expected to reference this hostname.
	eveboxHostname     = "evebox"
	eveboxAppLabel     = "evebox"
	eveboxAgentService = "evebox.service"
)

// EveboxReconciler keeps a hosts entry pointing to the pod ip of the evebox server running in the shoot
// such that the evebox agent on the firewall can reach it under a stable name.
type EveboxReconciler struct {
	ShootClient client.Client
	Log         logr.Logger
	Hosts       *txeh.Hosts

	oldPodIP string
}

// SetupWithManager configures this controller with required defaults
func (r *EveboxReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Hosts == nil {
		return fmt.Errorf("hosts editor must be specified")
	}

	eveboxPredicate := predicate.NewPredicateFuncs(func(obj client.Object) bool {
		if obj.GetNamespace() != firewallv1.ClusterwideNetworkPolicyNamespace {
			return false
		}

		return obj.GetLabels()["app"] == eveboxAppLabel
	})

	return ctrl.NewControllerManagedBy(mgr).
		Named("evebox").
		For(&corev1.Pod{}, builder.WithPredicates(eveboxPredicate)).
		Complete(r)
}

// Reconcile updates the evebox hosts entry with the evebox server pod ip and restarts the evebox agent on change.
func (r *EveboxReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	pod := &corev1.Pod{}
	if err := r.ShootClient.Get(ctx, req.NamespacedName, pod); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		return ctrl.Result{}, fmt.Errorf("error retrieving evebox pod: %w", err)
	}

	if !pod.GetDeletionTimestamp().IsZero() {
		r.Log.Info("evebox pod is being deleted")
		return ctrl.Result{}, nil
	}

	podIP := pod.Status.PodIP
	if podIP == "" || podIP == r.oldPodIP {
		return ctrl.Result{}, nil
	}

	r.Log.Info("evebox pod ip changed, updating hosts file", "old", r.oldPodIP, "new", podIP)

	r.Hosts.RemoveHost(eveboxHostname)
	r.Hosts.AddHost(podIP, eveboxHostname)
	if err := r.Hosts.Save(); err != nil {
		return ctrl.Result{}, fmt.Errorf("could not write evebox hosts entry: %w", err)
	}

	r.oldPodIP = podIP

	// only restart the agent when it is enabled, the agent is deployed by the firewall reconciler
	enabled, err := systemd.AnyUnitFileEnabled(ctx, eveboxAgentService)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to check if evebox agent is enabled: %w", err)
	}

	if enabled {
		if err := systemd.Restart(ctx, eveboxAgentService); err != nil {
			return ctrl.Result{}, fmt.Errorf("unable to restart evebox agent: %w", err)
		}
	}

	r.Log.Info("evebox hosts entry successfully reconciled")

	return ctrl.Result{}, nil
}
