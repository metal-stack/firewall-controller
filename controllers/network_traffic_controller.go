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
	"path/filepath"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
	"github.com/metal-stack/firewall-controller/pkg/collector"
)

// NetworkTrafficReconciler reconciles a NetworkTraffic object
type NetworkTrafficReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

const (
	networkTrafficReconcileInterval = time.Second * 10
)

// Reconcile NetworkTraffic
// +kubebuilder:rbac:groups=metal-stack.io,resources=networktraffics,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=metal-stack.io,resources=networktraffics/status,verbs=get;update;patch
func (r *NetworkTrafficReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("networktraffic", req.NamespacedName)
	interval := networkTrafficReconcileInterval

	var traffic firewallv1.NetworkTraffic
	if err := r.Get(ctx, req.NamespacedName, &traffic); err != nil {
		// we'll ignore not-found errors, since they can't be fixed by an immediate
		// requeue (we'll need to wait for a new notification), and we can get them
		// on deleted requests.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	spec := traffic.Spec
	i, err := time.ParseDuration(spec.Interval)
	if err != nil {
		interval = i
	}
	requeue := ctrl.Result{
		RequeueAfter: interval,
	}

	if !spec.Enabled {
		log.Info("NetworkTraffic is disabled")
	}

	c := collector.NewNFTablesCollector(&r.Log)
	ds, err := c.Collect()
	if err != nil {
		return requeue, err
	}

	deviceStatistics := []firewallv1.DeviceStatistic{}
	for name, v := range *ds {
		match, err := filepath.Match(spec.Interfaces, name)
		if err != nil {
			return requeue, err
		}
		if !match {
			continue
		}
		deviceStatistic := firewallv1.DeviceStatistic{
			DeviceName: name,
		}
		in, ok := v["in"]
		if ok {
			deviceStatistic.InBytes = in
		}
		out, ok := v["out"]
		if ok {
			deviceStatistic.OutBytes = out
		}
		total, ok := v["total"]
		if ok {
			deviceStatistic.TotalBytes = total
		}
		log.Info("deviceStatistic:%v", deviceStatistic)
		deviceStatistics = append(deviceStatistics, deviceStatistic)
	}
	traffic.Status.DeviceStatistics.Items = deviceStatistics
	traffic.Status.Updated.Time = time.Now()
	if err := r.Status().Update(ctx, &traffic); err != nil {
		log.Error(err, "unable to update NetworkTraffic")
		return requeue, err
	}
	log.Info("NetworkTraffic updated")
	return requeue, nil
}

// SetupWithManager create a new controller to reconcile NetworkTraffic
func (r *NetworkTrafficReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&firewallv1.NetworkTraffic{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}
