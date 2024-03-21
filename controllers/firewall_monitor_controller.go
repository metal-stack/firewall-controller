package controllers

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	firewallv2 "github.com/metal-stack/firewall-controller-manager/api/v2"
	firewallv1 "github.com/metal-stack/firewall-controller/v2/api/v1"
	"github.com/metal-stack/firewall-controller/v2/pkg/collector"
	"github.com/metal-stack/firewall-controller/v2/pkg/suricata"
	"github.com/metal-stack/v"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// FirewallMonitorReconciler reconciles a firewall monitor object
type FirewallMonitorReconciler struct {
	ShootClient client.Client

	Recorder record.EventRecorder
	Log      logr.Logger

	FirewallName string
	Namespace    string

	IDSEnabled bool
	Interval   time.Duration

	seedUpdated metav1.Time
}

func (r *FirewallMonitorReconciler) SeedUpdated() {
	r.seedUpdated = metav1.NewTime(time.Now())
}

// SetupWithManager configures this controller to watch for the CRDs in a specific namespace
func (r *FirewallMonitorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Interval == 0 {
		r.Interval = reconcilationInterval
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&firewallv2.FirewallMonitor{}).
		WithEventFilter(predicate.Funcs{
			UpdateFunc: func(ce event.UpdateEvent) bool {
				return false
			},
			DeleteFunc: func(de event.DeleteEvent) bool {
				return false
			},
		}).
		Complete(r)
}

// Reconcile updates the firewall monitor.
func (r *FirewallMonitorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	c := collector.NewNFTablesCollector(&r.Log)
	ruleStats := c.CollectRuleStats()

	deviceStats, err := c.CollectDeviceStats()
	if err != nil {
		return ctrl.Result{}, err
	}

	idsStats := firewallv2.IDSStatsByDevice{}
	if r.IDSEnabled {
		s := suricata.New()
		ss, err := s.InterfaceStats(ctx)
		if err != nil {
			return ctrl.Result{}, err
		}
		for iface, stat := range *ss {
			idsStats[iface] = firewallv2.InterfaceStat{
				Drop:             stat.Drop,
				InvalidChecksums: stat.InvalidChecksums,
				Packets:          stat.Pkts,
			}
		}
	}

	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		mon := &firewallv2.FirewallMonitor{
			ObjectMeta: metav1.ObjectMeta{
				Name:      r.FirewallName,
				Namespace: firewallv1.ClusterwideNetworkPolicyNamespace,
			},
		}

		if err := r.ShootClient.Get(ctx, client.ObjectKeyFromObject(mon), mon); err != nil {
			if apierrors.IsNotFound(err) {
				r.Log.Info("resource no longer exists")
				return nil
			}

			return fmt.Errorf("error retrieving resource: %w", err)
		}

		if !mon.GetDeletionTimestamp().IsZero() {
			return nil
		}

		now := time.Now()

		mon.ControllerStatus = &firewallv2.ControllerStatus{
			Message: fmt.Sprintf("updated firewall monitor resource at %s", now.String()),
			FirewallStats: &firewallv2.FirewallStats{
				RuleStats:   ruleStats,
				DeviceStats: deviceStats,
				IDSStats:    idsStats,
			},
			ControllerVersion:       v.Version,
			NftablesExporterVersion: "", // TODO
			Updated:                 metav1.NewTime(now),
			Distance:                0,
			DistanceSupported:       false,
		}

		if !r.seedUpdated.IsZero() {
			mon.ControllerStatus.SeedUpdated = r.seedUpdated
		}

		err := r.ShootClient.Update(ctx, mon)
		if err != nil {
			return err
		}

		r.Log.Info(fmt.Sprintf("firewall monitor successfully updated, requeuing in %s", r.Interval.String()), "name", mon.Name, "namespace", mon.Namespace)

		return nil
	})
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to update firewall monitor status, err: %w", err)
	}

	return ctrl.Result{
		// TODO: the interval can change over the lifetime of a firewall resource
		// in case the interval has changed nothing happens at the moment
		RequeueAfter: r.Interval,
	}, nil
}
