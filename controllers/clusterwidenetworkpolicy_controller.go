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
	"crypto/md5" //nolint:gosec
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	"github.com/go-logr/logr"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
	"github.com/metal-stack/firewall-controller/pkg/nftables"
)

const (
	rulesReconcileInterval = 30 * time.Second
)

// ClusterwideNetworkPolicyReconciler reconciles a ClusterwideNetworkPolicy object
// +kubebuilder:rbac:groups=metal-stack.io,resources=events,verbs=create;patch
type ClusterwideNetworkPolicyReconciler struct {
	client.Client
	Log                  logr.Logger
	Scheme               *runtime.Scheme
	Cache                nftables.FQDNCache
	CreateFirewall       CreateFirewall
	policySpecsChecksums map[string][16]byte
}

// Reconcile ClusterwideNetworkPolicy and creates nftables rules accordingly
// +kubebuilder:rbac:groups=metal-stack.io,resources=clusterwidenetworkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=metal-stack.io,resources=clusterwidenetworkpolicies/status,verbs=get;update;patch
func (r *ClusterwideNetworkPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("cwnp", req.Name)

	var cwnps firewallv1.ClusterwideNetworkPolicyList
	if err := r.List(ctx, &cwnps, client.InNamespace(firewallv1.ClusterwideNetworkPolicyNamespace)); err != nil {
		return done, err
	}

	// Check if new sets added or CWNP specs updated
	changed, err := r.isSpecsChanged(cwnps)
	if err != nil {
		return done, err
	}
	if changed || r.nftableSetsAdded(cwnps) {
		return r.reconcileRules(ctx, log, cwnps)
	}

	return done, nil
}

func (r *ClusterwideNetworkPolicyReconciler) reconcileRules(ctx context.Context, log logr.Logger, cwnps firewallv1.ClusterwideNetworkPolicyList) (ctrl.Result, error) {
	var f firewallv1.Firewall
	nn := types.NamespacedName{
		Name:      firewallName,
		Namespace: firewallv1.ClusterwideNetworkPolicyNamespace,
	}
	if err := r.Get(ctx, nn, &f); err != nil {
		if apierrors.IsNotFound(err) {
			return done, err
		}

		return done, client.IgnoreNotFound(err)
	}

	var services corev1.ServiceList
	if err := r.List(ctx, &services); err != nil {
		return done, err
	}
	nftablesFirewall := r.CreateFirewall(&cwnps, &services, f.Spec, r.Cache, log)
	if err := nftablesFirewall.Reconcile(); err != nil {
		return done, err
	}

	for _, i := range cwnps.Items {
		o := i
		if err := r.Update(ctx, &o); err != nil {
			return done, err
		}

		j, err := json.Marshal(o.Spec)
		if err != nil {
			return done, fmt.Errorf("failed to parse updated '%s' CWNP spec: %w", o.Name, err)
		}
		currentSum := md5.Sum(j) //nolint:gosec

		onn := types.NamespacedName{
			Name:      o.Name,
			Namespace: o.Namespace,
		}
		r.policySpecsChecksums[onn.String()] = currentSum
	}

	return done, nil
}

func (r *ClusterwideNetworkPolicyReconciler) isSpecsChanged(cwnps firewallv1.ClusterwideNetworkPolicyList) (bool, error) {
	if r.policySpecsChecksums == nil {
		r.policySpecsChecksums = make(map[string][16]byte)
	}

	for _, cwnp := range cwnps.Items {
		nn := types.NamespacedName{
			Name:      cwnp.Name,
			Namespace: cwnp.Namespace,
		}
		oldSum, exists := r.policySpecsChecksums[nn.String()]
		if !exists {
			return true, nil
		}

		j, err := json.Marshal(cwnp.Spec)
		if err != nil {
			return false, fmt.Errorf("failed to parse '%s' CWNP spec: %w", cwnp.Name, err)
		}

		currentSum := md5.Sum(j) //nolint:gosec
		if exists && !reflect.DeepEqual(oldSum, currentSum) {
			return true, nil
		}
	}

	return false, nil
}

func (r *ClusterwideNetworkPolicyReconciler) nftableSetsAdded(cwnps firewallv1.ClusterwideNetworkPolicyList) bool {
	// Aggregate all sets
	for _, cwnp := range cwnps.Items {
		for _, e := range cwnp.Spec.Egress {
			if len(e.To) > 0 {
				continue
			}

			for _, fqdn := range e.ToFQDNs {
				unique := map[string]bool{}
				sets := r.Cache.GetSetsForFQDN(fqdn, false)
				for _, s := range sets {
					unique[s.SetName] = false
				}

				for _, s := range fqdn.Sets {
					if _, ok := unique[s.SetName]; !ok {
						return true
					}

					unique[s.SetName] = true
				}

				for _, old := range unique {
					if !old {
						return true
					}
				}
			}
		}
	}

	return false
}

// SetupWithManager configures this controller to run in schedule
func (r *ClusterwideNetworkPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	scheduleChan := make(chan event.GenericEvent)
	if err := mgr.Add(manager.RunnableFunc(func(c <-chan struct{}) error {
		e := event.GenericEvent{}
		ticker := time.NewTicker(rulesReconcileInterval)

		for range ticker.C {
			scheduleChan <- e
		}
		return nil
	})); err != nil {
		return fmt.Errorf("failed to add runnable to manager: %w", err)
	}

	firewallHandler := &handler.EnqueueRequestsFromMapFunc{
		ToRequests: handler.ToRequestsFunc(
			func(a handler.MapObject) []reconcile.Request {
				return []reconcile.Request{
					{
						NamespacedName: types.NamespacedName{
							Name:      firewallName,
							Namespace: firewallv1.ClusterwideNetworkPolicyNamespace,
						},
					},
				}
			},
		),
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&firewallv1.ClusterwideNetworkPolicy{}).
		Watches(&source.Channel{Source: scheduleChan}, firewallHandler).
		Complete(r)
}
