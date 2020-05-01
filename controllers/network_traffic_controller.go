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

	firewallv1 "github.com/metal-stack/firewall-builder/api/v1"
	"github.com/metal-stack/firewall-builder/pkg/collector"
)

// NetworkTrafficReconciler reconciles a NetworkTraffic object
type NetworkTrafficReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// Reconcile NetworkTraffic
// +kubebuilder:rbac:groups=metal-stack.io,resources=networktraffics,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=metal-stack.io,resources=networktraffics/status,verbs=get;update;patch
func (r *NetworkTrafficReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("networktraffic", req.NamespacedName)

	var networkTraffic firewallv1.NetworkTraffic
	if err := r.Get(ctx, req.NamespacedName, &networkTraffic); err != nil {
		log.Error(err, "unable to get networkTraffic")
		return ctrl.Result{}, err
	}
	spec := networkTraffic.Spec
	interval, err := time.ParseDuration(spec.Interval)
	if err != nil {
		interval = time.Minute
	}

	if spec.Enabled {
		log.Info("networkTraffic is enabled", "interval", interval)
		c := collector.NewCollector(&r.Log, spec.NodeExportURL)
		ds, err := c.Collect()
		if err != nil {
			return ctrl.Result{}, err
		}
		deviceStatistics := []firewallv1.DeviceStatistic{}
		for name, v := range *ds {
			match, err := filepath.Match(spec.Interfaces, name)
			if err != nil {
				return ctrl.Result{}, err
			}
			if !match {
				continue
			}
			deviceStatistic := firewallv1.DeviceStatistic{
				DeviceName: name,
				InBytes:    v["in"],
				OutBytes:   v["out"],
			}
			deviceStatistics = append(deviceStatistics, deviceStatistic)
		}
		networkTraffic.Status.DeviceStatistics.Items = deviceStatistics
		networkTraffic.Status.Updated.Time = time.Now()
		if err := r.Update(ctx, &networkTraffic); err != nil {
			log.Error(err, "unable to update networkTraffic")
			return ctrl.Result{}, err
		}
		log.Info("traffic updated")
		time.Sleep(interval)
		return ctrl.Result{}, nil
	}
	log.Info("networkTraffic is disabled")
	return ctrl.Result{}, nil
}

// SetupWithManager create a new controller to reconcile NetworkTraffic
func (r *NetworkTrafficReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&firewallv1.NetworkTraffic{}).
		Complete(r)
}
