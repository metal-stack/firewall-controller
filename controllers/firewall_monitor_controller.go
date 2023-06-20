package controllers

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/go-logr/logr"
	firewallv2 "github.com/metal-stack/firewall-controller-manager/api/v2"
	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
	"github.com/metal-stack/firewall-controller/pkg/collector"
	"github.com/metal-stack/firewall-controller/pkg/suricata"
	"github.com/metal-stack/v"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	configlatest "k8s.io/client-go/tools/clientcmd/api/latest"
	configv1 "k8s.io/client-go/tools/clientcmd/api/v1"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

var (
	scheme = runtime.NewScheme()
)

func init() {
	_ = clientgoscheme.AddToScheme(scheme)

	_ = firewallv1.AddToScheme(scheme)
	_ = firewallv2.AddToScheme(scheme)

	_ = apiextensions.AddToScheme(scheme)
	// +kubebuilder:scaffold:scheme
}

// FirewallMonitorReconciler reconciles a firewall monitor object
type FirewallMonitorReconciler struct {
	ShootClient client.Client

	Recorder record.EventRecorder
	Log      logr.Logger

	FirewallName  string
	Namespace     string
	SeedNamespace string

	SeedKubeconfigPath string

	IDSEnabled bool
	Interval   time.Duration
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
	mon := &firewallv2.FirewallMonitor{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.FirewallName,
			Namespace: firewallv1.ClusterwideNetworkPolicyNamespace,
		},
	}

	if err := r.ShootClient.Get(ctx, client.ObjectKeyFromObject(mon), mon); err != nil {
		if apierrors.IsNotFound(err) {
			r.Log.Info("resource no longer exists")
			return ctrl.Result{}, nil
		}

		return ctrl.Result{}, fmt.Errorf("error retrieving resource: %w", err)
	}

	if !mon.GetDeletionTimestamp().IsZero() {
		return ctrl.Result{}, nil
	}

	if err := r.checkSeedEndpoint(ctx, mon); err != nil {
		return ctrl.Result{}, err
	}

	c := collector.NewNFTablesCollector(&r.Log)
	ruleStats := c.CollectRuleStats()

	if mon.ControllerStatus == nil {
		mon.ControllerStatus = &firewallv2.ControllerStatus{}
	}

	mon.ControllerStatus.FirewallStats = &firewallv2.FirewallStats{
		RuleStats: ruleStats,
	}
	deviceStats, err := c.CollectDeviceStats()
	if err != nil {
		return ctrl.Result{}, err
	}
	mon.ControllerStatus.FirewallStats.DeviceStats = deviceStats

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
	mon.ControllerStatus.FirewallStats.IDSStats = idsStats

	mon.ControllerStatus.ControllerVersion = v.Version
	mon.ControllerStatus.Updated.Time = time.Now()

	if err := r.ShootClient.Update(ctx, mon); err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to update firewall monitor status, err: %w", err)
	}

	r.Log.Info(fmt.Sprintf("firewall monitor successfully updated, requeuing in %s", r.Interval.String()), "name", mon.Name, "namespace", mon.Namespace)

	return ctrl.Result{
		// TODO: the interval can change over the lifetime of a firewall resource
		// in case the interval has changed nothing happens at the moment
		RequeueAfter: r.Interval,
	}, nil
}

func (r *FirewallMonitorReconciler) checkSeedEndpoint(ctx context.Context, mon *firewallv2.FirewallMonitor) error {
	seedURL, ok := mon.Annotations[firewallv2.FirewallSeedURLAnnotation]
	if !ok {
		return nil
	}

	rawKubeconfig, err := os.ReadFile(r.SeedKubeconfigPath)
	if err != nil {
		return fmt.Errorf("unable to read kubeconfig: %w", err)
	}

	seedConfig, err := clientcmd.RESTConfigFromKubeConfig(rawKubeconfig)
	if err != nil {
		return fmt.Errorf("unable to create rest config from seed kubeconfig: %w", err)
	}

	if seedConfig.APIPath == seedURL {
		return nil
	}

	seed, err := client.New(seedConfig, client.Options{
		Scheme: scheme,
	})
	if err != nil {
		return fmt.Errorf("unable to create seed client from seed kubeconfig: %w", err)
	}

	f := &firewallv2.Firewall{
		ObjectMeta: metav1.ObjectMeta{
			Name:      mon.Name,
			Namespace: r.SeedNamespace,
		},
	}
	err = seed.Get(ctx, client.ObjectKeyFromObject(f), f)
	if err == nil {
		return nil
	}

	r.Log.Info("seed api url is not contained in seed kubeconfig and seed client seems not to work", "error", err)

	kubeconfig := &configv1.Config{}
	err = runtime.DecodeInto(configlatest.Codec, rawKubeconfig, kubeconfig)
	if err != nil {
		return fmt.Errorf("unable to decode kubeconfig seed kubeconfig: %w", err)
	}

	for _, cluster := range kubeconfig.Clusters {
		cluster := cluster
		cluster.Cluster.Server = seedURL
	}

	updatedKubeconfig, err := runtime.Encode(configlatest.Codec, kubeconfig)
	if err != nil {
		return fmt.Errorf("unable to encode kubeconfig: %w", err)
	}

	updatedConfig, err := clientcmd.RESTConfigFromKubeConfig(updatedKubeconfig)
	if err != nil {
		return fmt.Errorf("unable to create rest config from bytes: %w", err)
	}

	newSeedClient, err := client.New(updatedConfig, client.Options{
		Scheme: scheme,
	})
	if err != nil {
		return fmt.Errorf("unable to create seed client from updated seed kubeconfig: %w", err)
	}

	err = newSeedClient.Get(ctx, client.ObjectKeyFromObject(f), f)
	if err != nil {
		return fmt.Errorf("seed client seems broken but seed client with changed api server url also does not appear to work")
	}

	err = os.WriteFile(r.SeedKubeconfigPath, updatedKubeconfig, 0600)
	if err != nil {
		return fmt.Errorf("unable to write kubeconfig to destination: %w", err)
	}

	r.Log.Info("successfully updating seed client url, restarting controller")

	os.Exit(0)

	return nil

}
