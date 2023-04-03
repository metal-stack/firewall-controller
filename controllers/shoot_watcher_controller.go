package controllers

import (
	"context"

	"github.com/go-logr/logr"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// ShootWatcherController watches service resources in the shoot cluster and
// notifies the firewall controller when a service was created, modified or deleted.
type ShootWatcherController struct {
	Log logr.Logger

	trigger chan event.GenericEvent
}

func (r *ShootWatcherController) SetupWithManager(mgr ctrl.Manager) error {
	r.trigger = make(chan event.GenericEvent)

	return ctrl.NewControllerManagedBy(mgr).
		Watches(&source.Kind{Type: &corev1.Service{}}, handler.Funcs{
			CreateFunc: func(ce event.CreateEvent, rli workqueue.RateLimitingInterface) {
				r.Log.Info("requesting firewall reconcile due to service creation in shoot cluster")
				r.trigger <- event.GenericEvent{}
			},
			UpdateFunc: func(ue event.UpdateEvent, rli workqueue.RateLimitingInterface) {
				r.Log.Info("requesting firewall reconcile due to service update in shoot cluster")
				r.trigger <- event.GenericEvent{}
			},
			DeleteFunc: func(de event.DeleteEvent, rli workqueue.RateLimitingInterface) {
				r.Log.Info("requesting firewall reconcile due to service deletion in shoot cluster")
				r.trigger <- event.GenericEvent{}
			},
		}).
		Complete(r)
}

func (r *ShootWatcherController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return ctrl.Result{}, nil
}

func (r *ShootWatcherController) GetSource() source.Source {
	return &source.Channel{Source: r.trigger}
}

func (r *ShootWatcherController) GetEventHandler(firewallName, firewallNamespace string) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(o client.Object) []reconcile.Request {
		r.Log.Info("firewall reconcile requested from external controller")
		return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: firewallName, Namespace: firewallNamespace}}}
	})
}
