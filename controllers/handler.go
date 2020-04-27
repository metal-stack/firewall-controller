package controllers

import (
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type enqueueReconcilationHandler struct {
	request reconcile.Request
}

func newEnqueueReconcilationHandler(namespace, name string) enqueueReconcilationHandler {
	return enqueueReconcilationHandler{
		request: reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      name,
				Namespace: firewallNamespace,
			},
		},
	}
}

func (h enqueueReconcilationHandler) Create(e event.CreateEvent, w workqueue.RateLimitingInterface) {
	w.Add(h.request)
}

func (h enqueueReconcilationHandler) Update(e event.UpdateEvent, w workqueue.RateLimitingInterface) {
	w.Add(h.request)
}

func (h enqueueReconcilationHandler) Delete(e event.DeleteEvent, w workqueue.RateLimitingInterface) {
	w.Add(h.request)
}

func (h enqueueReconcilationHandler) Generic(e event.GenericEvent, w workqueue.RateLimitingInterface) {
	w.Add(h.request)
}
