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
	"fmt"
	"reflect"
	"time"

	"github.com/metal-stack/v"

	"github.com/go-logr/logr"
	"github.com/hashicorp/go-multierror"
	mn "github.com/metal-stack/metal-lib/pkg/net"
	corev1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	firewallv2 "github.com/metal-stack/firewall-controller-manager/api/v2"
	"github.com/metal-stack/firewall-controller-manager/controllers"
	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
	"github.com/metal-stack/firewall-controller/pkg/collector"
	"github.com/metal-stack/firewall-controller/pkg/network"
	"github.com/metal-stack/firewall-controller/pkg/nftables"
	"github.com/metal-stack/firewall-controller/pkg/suricata"
)

// FirewallReconciler reconciles a Firewall object
type FirewallReconciler struct {
	SeedClient  client.Client
	ShootClient client.Client

	Recorder  record.EventRecorder
	Log       logr.Logger
	Scheme    *runtime.Scheme
	EnableIDS bool

	FirewallName string
	Namespace    string
}

const (
	reconcilationInterval = 10 * time.Second

	nftablesExporterService   = "node-exporter"
	nftablesExporterNamedPort = "nodeexporter"
	nftablesExporterPort      = 9100
	nodeExporterService       = "nftables-exporter"
	nodeExporterNamedPort     = "nftexporter"
	nodeExporterPort          = 9630
	exporterLabelKey          = "app"
)

var (
	done            = ctrl.Result{}
	firewallRequeue = ctrl.Result{
		RequeueAfter: reconcilationInterval,
	}
)

// SetupWithManager configures this controller to watch for the CRDs in a specific namespace
func (r *FirewallReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&firewallv2.Firewall{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})). // don't trigger a reconcilation for status updates
		WithEventFilter(predicate.NewPredicateFuncs(controllers.SkipOtherNamespace(r.Namespace))).
		WithEventFilter(firewallv2.SkipReconcileAnnotationRemoval()).
		Complete(r)
}

// Reconcile reconciles a firewall by:
// - reading Services of type Loadbalancer
// - rendering nftables rules
// - updating the firewall object with nftable rule statistics grouped by action
// +kubebuilder:rbac:groups=metal-stack.io,resources=firewalls,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=metal-stack.io,resources=firewalls/status,verbs=get;update;patch
func (r *FirewallReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if req.Namespace != r.Namespace || req.Name != r.FirewallName {
		return ctrl.Result{}, nil
	}

	log := r.Log.WithValues("firewall", req.NamespacedName)
	requeue := firewallRequeue

	var f firewallv2.Firewall
	if err := r.SeedClient.Get(ctx, req.NamespacedName, &f); err != nil {
		if errors.IsNotFound(err) {
			defaultFw := nftables.NewDefaultFirewall()
			log.Info("flushing k8s firewall rules")
			err := defaultFw.Flush()
			if err == nil {
				return done, nil
			}
			return requeue, err
		}

		return done, client.IgnoreNotFound(err)
	}

	log.Info("reconciling firewall-controller")

	recordFirewallEvent := func(eventtype, reason, message string) {
		// we want to have this event in the shoot cluster and not in the seed
		// the seed namespace does not exist in the shoot, so we need to alter it to the shoot's namespace
		copy := f.DeepCopy()
		copy.Namespace = firewallv1.ClusterwideNetworkPolicyNamespace
		r.Recorder.Event(copy, eventtype, reason, message)
	}

	// TODO: put back in
	// err := updater.UpdateToSpecVersion(f, log, r.recorder)
	// if err != nil {
	// 	r.recorder.Eventf(&f, corev1.EventTypeWarning, "Self-Reconcilation", "failed with error: %v", err)
	// 	return requeue, err
	// }

	// Update reconcilation interval
	if i, err := time.ParseDuration(f.Spec.Interval); err == nil {
		requeue.RequeueAfter = i
	}

	log.Info("reconciling network settings")

	var errors *multierror.Error
	changed, err := network.ReconcileNetwork(f)
	if changed && err == nil {
		recordFirewallEvent(corev1.EventTypeNormal, "Network settings", "reconcilation succeeded (frr.conf)")
	} else if changed && err != nil {
		recordFirewallEvent(corev1.EventTypeWarning, "Network settings", fmt.Sprintf("reconcilation failed (frr.conf): %v", err))
	}
	if err != nil {
		errors = multierror.Append(errors, err)
	}

	log.Info("reconciling firewall services")
	if err = r.reconcileFirewallServices(ctx, f); err != nil {
		errors = multierror.Append(errors, err)
	}

	log.Info("updating status field")
	if err = r.updateStatus(ctx, f); err != nil {
		errors = multierror.Append(errors, err)
	}

	if errors.ErrorOrNil() != nil {
		recordFirewallEvent(corev1.EventTypeWarning, "Error", multierror.Flatten(errors).Error())
		return requeue, errors
	}

	recordFirewallEvent(corev1.EventTypeNormal, "Reconciled", "nftables rules and statistics successfully")
	log.Info("reconciled firewall")

	return requeue, nil
}

// converts a network-policy object that was used before in a cluster-wide manner to the new CRD
func convert(np networking.NetworkPolicy) (*firewallv1.ClusterwideNetworkPolicy, error) {
	cwnp := firewallv1.ClusterwideNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      np.Name,
			Namespace: firewallv1.ClusterwideNetworkPolicyNamespace,
		},
	}
	newEgresses := []firewallv1.EgressRule{}
	for _, egress := range np.Spec.Egress {
		newTos := []networking.IPBlock{}
		for _, to := range egress.To {
			if to.NamespaceSelector != nil {
				return nil, fmt.Errorf("np %v contains a namespace selector and is not applicable for a conversion to a cluster-wide network policy", np.ObjectMeta)
			}
			if to.PodSelector != nil {
				return nil, fmt.Errorf("np %v contains a pod selector and is not applicable for a conversion to a cluster-wide network policy", np.ObjectMeta)
			}
			if to.IPBlock == nil {
				continue
			}
			newTos = append(newTos, *to.IPBlock)
		}
		if len(newTos) == 0 {
			continue
		}
		newEgresses = append(newEgresses, firewallv1.EgressRule{
			Ports: egress.Ports,
			To:    newTos,
		})
	}
	if len(newEgresses) == 0 {
		return nil, nil
	}
	cwnp.Spec = firewallv1.PolicySpec{
		Egress: newEgresses,
	}
	return &cwnp, nil
}

type firewallService struct {
	name      string
	port      int32
	namedPort string
}

// reconcileFirewallServices reconciles the services and endpoints exposed by the firewall
func (r *FirewallReconciler) reconcileFirewallServices(ctx context.Context, f firewallv2.Firewall) error {
	services := []firewallService{
		{
			name:      nodeExporterService,
			port:      nodeExporterPort,
			namedPort: nodeExporterNamedPort,
		},
		{
			name:      nftablesExporterService,
			port:      nftablesExporterPort,
			namedPort: nftablesExporterNamedPort,
		},
	}

	var errors *multierror.Error
	for _, s := range services {
		err := r.reconcileFirewallService(ctx, s, f)
		if err != nil {
			errors = multierror.Append(errors, err)
		}
	}
	return errors.ErrorOrNil()
}

// reconcileFirewallService reconciles a single service that is to be exposed at the firewall.
func (r *FirewallReconciler) reconcileFirewallService(ctx context.Context, s firewallService, f firewallv2.Firewall) error {
	nn := types.NamespacedName{Name: s.name, Namespace: firewallv1.ClusterwideNetworkPolicyNamespace}
	meta := metav1.ObjectMeta{
		Name:      s.name,
		Namespace: firewallv1.ClusterwideNetworkPolicyNamespace,
		Labels:    map[string]string{exporterLabelKey: s.name},
	}

	var currentSvc corev1.Service
	err := r.ShootClient.Get(ctx, nn, &currentSvc)

	if err != nil && !errors.IsNotFound(err) {
		return err
	}

	svc := corev1.Service{
		ObjectMeta: meta,
		Spec: corev1.ServiceSpec{
			Type:      corev1.ServiceTypeClusterIP,
			ClusterIP: "None", // needed for headless services!
			Ports: []corev1.ServicePort{
				{
					Protocol:   corev1.ProtocolTCP,
					Port:       s.port,
					TargetPort: intstr.FromString(s.namedPort),
				},
			},
		},
	}

	if errors.IsNotFound(err) {
		err = r.ShootClient.Create(ctx, &svc)
		if err != nil {
			return err
		}
	}

	if !reflect.DeepEqual(currentSvc.Spec, svc.Spec) || currentSvc.ObjectMeta.Labels == nil || !reflect.DeepEqual(currentSvc.ObjectMeta.Labels, svc.ObjectMeta.Labels) {
		currentSvc.Spec = svc.Spec
		currentSvc.ObjectMeta.Labels = svc.ObjectMeta.Labels
		err = r.ShootClient.Update(ctx, &currentSvc)
		if err != nil {
			return err
		}
	}

	var privateNet *firewallv2.FirewallNetwork
	for _, n := range f.Status.FirewallNetworks {
		n := n
		if n.NetworkType == nil {
			continue
		}

		switch *n.NetworkType {
		case mn.PrivatePrimaryUnshared:
			privateNet = &n
		case mn.PrivatePrimaryShared:
			privateNet = &n
		}
	}

	if privateNet == nil {
		return fmt.Errorf("firewall networks contain no private network")
	}

	if len(privateNet.IPs) < 1 {
		return fmt.Errorf("private firewall network contains no ip")
	}

	endpoints := corev1.Endpoints{
		ObjectMeta: meta,
		Subsets: []corev1.EndpointSubset{
			{
				Addresses: []corev1.EndpointAddress{
					{
						IP: privateNet.IPs[0],
					},
				},
				Ports: []corev1.EndpointPort{
					{
						Name:     s.namedPort,
						Port:     s.port,
						Protocol: corev1.ProtocolTCP,
					},
				},
			},
		},
	}

	var currentEndpoints corev1.Endpoints
	err = r.ShootClient.Get(ctx, nn, &currentEndpoints)
	if err != nil && !errors.IsNotFound(err) {
		return err
	}

	if errors.IsNotFound(err) {
		err = r.ShootClient.Create(ctx, &endpoints)
		if err != nil {
			return err
		}
		return nil
	}

	if !reflect.DeepEqual(currentEndpoints.Subsets, endpoints.Subsets) {
		currentEndpoints.Subsets = endpoints.Subsets
		return r.ShootClient.Update(ctx, &currentEndpoints)
	}

	return nil
}

// updateStatus updates the status field for this firewall
func (r *FirewallReconciler) updateStatus(ctx context.Context, f firewallv2.Firewall) error {
	mon := &firewallv2.FirewallMonitor{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.FirewallName,
			Namespace: firewallv1.ClusterwideNetworkPolicyNamespace,
		},
	}
	if err := r.ShootClient.Get(ctx, client.ObjectKeyFromObject(mon), mon); err != nil {
		r.Log.Error(err, "no firewall monitor found, cannot update")
		return err
	}

	if f.Spec.DryRun {
		mon.ControllerStatus.FirewallStats = &firewallv2.FirewallStats{
			RuleStats:   firewallv2.RuleStatsByAction{},
			DeviceStats: firewallv2.DeviceStatsByDevice{},
			IDSStats:    firewallv2.IDSStatsByDevice{},
		}
		f.Status.ControllerStatus.Updated.Time = time.Now()
		if err := r.ShootClient.Update(ctx, &f); err != nil {
			return fmt.Errorf("unable to update firewall monitor status, err: %w", err)
		}
		return nil
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
		return err
	}
	mon.ControllerStatus.FirewallStats.DeviceStats = deviceStats

	idsStats := firewallv2.IDSStatsByDevice{}
	if r.EnableIDS { // checks the CLI-flag
		s := suricata.New()
		ss, err := s.InterfaceStats(ctx)
		if err != nil {
			return err
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
		return fmt.Errorf("unable to update firewall monitor status, err: %w", err)
	}
	return nil
}
