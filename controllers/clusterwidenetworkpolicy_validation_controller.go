package controllers

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/go-logr/logr"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	firewallv1 "github.com/metal-stack/firewall-controller/v2/api/v1"
)

// ClusterwideNetworkPolicyValidationReconciler validates a ClusterwideNetworkPolicy object
// +kubebuilder:rbac:groups=metal-stack.io,resources=events,verbs=create;patch
type ClusterwideNetworkPolicyValidationReconciler struct {
	ShootClient client.Client
	Log         logr.Logger
	Recorder    record.EventRecorder
}

// Validates ClusterwideNetworkPolicy object
// +kubebuilder:rbac:groups=metal-stack.io,resources=clusterwidenetworkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=metal-stack.io,resources=clusterwidenetworkpolicies/status,verbs=get;update;patch
func (r *ClusterwideNetworkPolicyValidationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var clusterNP firewallv1.ClusterwideNetworkPolicy
	if err := r.ShootClient.Get(ctx, req.NamespacedName, &clusterNP); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// if network policy does not belong to the namespace where clusterwide network policies are stored:
	// update status with error message
	if req.Namespace != firewallv1.ClusterwideNetworkPolicyNamespace {
		r.Recorder.Event(
			&clusterNP,
			corev1.EventTypeWarning,
			"Unapplicable",
			fmt.Sprintf("cluster wide network policies must be defined in namespace %s otherwise they won't take effect", firewallv1.ClusterwideNetworkPolicyNamespace),
		)
		return ctrl.Result{}, nil
	}

	err := clusterNP.Spec.Validate()
	if err != nil {
		r.Recorder.Event(
			&clusterNP,
			corev1.EventTypeWarning,
			"Unapplicable",
			fmt.Sprintf("cluster wide network policy is not valid: %v", err),
		)
		return ctrl.Result{}, nil
	}

	return ctrl.Result{}, nil
}

// SetupWithManager configures this controller to watch for ClusterwideNetworkPolicy CRD
func (r *ClusterwideNetworkPolicyValidationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&firewallv1.ClusterwideNetworkPolicy{}).
		Complete(r)
}
