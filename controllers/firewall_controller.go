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
	"crypto/rsa"
	"fmt"
	"reflect"
	"time"

	"github.com/metal-stack/v"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/hashicorp/go-multierror"

	mn "github.com/metal-stack/metal-lib/pkg/net"
	networking "k8s.io/api/networking/v1"

	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
	"github.com/metal-stack/firewall-controller/pkg/collector"
	"github.com/metal-stack/firewall-controller/pkg/network"
	"github.com/metal-stack/firewall-controller/pkg/nftables"
	"github.com/metal-stack/firewall-controller/pkg/suricata"
	"github.com/metal-stack/firewall-controller/pkg/updater"
)

// FirewallReconciler reconciles a Firewall object
type FirewallReconciler struct {
	client.Client
	recorder             record.EventRecorder
	Log                  logr.Logger
	Scheme               *runtime.Scheme
	EnableIDS            bool
	EnableSignatureCheck bool
	CAPubKey             *rsa.PublicKey
	DNSProxy             DNSProxy
}

const (
	firewallReconcileInterval = time.Second * 10
	firewallName              = "firewall"

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
		RequeueAfter: firewallReconcileInterval,
	}
)

// Reconcile reconciles a firewall by:
// - reading Services of type Loadbalancer
// - rendering nftables rules
// - updating the firewall object with nftable rule statistics grouped by action
// +kubebuilder:rbac:groups=metal-stack.io,resources=firewalls,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=metal-stack.io,resources=firewalls/status,verbs=get;update;patch
func (r *FirewallReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("firewall", req.NamespacedName)
	requeue := firewallRequeue

	var f firewallv1.Firewall
	if err := r.Get(ctx, req.NamespacedName, &f); err != nil {
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

	if err := r.validateFirewall(f); err != nil {
		r.recorder.Event(&f, corev1.EventTypeWarning, "Unapplicable", err.Error())
		// don't requeue invalid firewall objects
		return done, err
	}

	log.Info("reconciling firewall-controller")
	err := updater.UpdateToSpecVersion(f, log, r.recorder)
	if err != nil {
		r.recorder.Eventf(&f, corev1.EventTypeWarning, "Self-Reconcilation", "failed with error: %v", err)
		return requeue, err
	}

	i, err := time.ParseDuration(f.Spec.Interval)
	if err == nil {
		requeue.RequeueAfter = i
	}

	var errors *multierror.Error
	log.Info("reconciling network settings")
	changed, err := network.ReconcileNetwork(f, log)
	if changed && err == nil {
		r.recorder.Event(&f, corev1.EventTypeNormal, "Network settings", "reconcilation succeeded (frr.conf)")
	} else if changed && err != nil {
		r.recorder.Event(&f, corev1.EventTypeWarning, "Network settings", fmt.Sprintf("reconcilation failed (frr.conf): %v", err))
	}

	if err != nil {
		errors = multierror.Append(errors, err)
	}

	log.Info("reconciling firewall services")
	if err = r.reconcileFirewallServices(ctx, f); err != nil {
		errors = multierror.Append(errors, err)
	}

	// If proxy is ON, update DNS address(if it's set in spec)
	if r.DNSProxy != nil && f.Spec.Data.DNSServerAddress != "" {
		r.DNSProxy.UpdateDNSAddr(f.Spec.Data.DNSServerAddress)
	}

	log.Info("updating status field")
	if err = r.updateStatus(ctx, f); err != nil {
		errors = multierror.Append(errors, err)
	}

	if errors.ErrorOrNil() != nil {
		r.recorder.Event(&f, corev1.EventTypeWarning, "Error", multierror.Flatten(errors).Error())
		return requeue, errors
	}

	r.recorder.Event(&f, corev1.EventTypeNormal, "Reconciled", "nftables rules and statistics successfully")
	log.Info("reconciled firewall")
	return requeue, nil
}

// validateFirewall validates a firewall object:
// - it must be a singularity in a fixed namespace
// - and for the triggered reconcilation request
// - the signature is valid (when signature checking is enabled)
func (r *FirewallReconciler) validateFirewall(f firewallv1.Firewall) error {
	if f.Namespace != firewallv1.ClusterwideNetworkPolicyNamespace {
		return fmt.Errorf("firewall must be defined in namespace %s otherwise it won't take effect", firewallv1.ClusterwideNetworkPolicyNamespace)
	}

	if f.Name != firewallName {
		return fmt.Errorf("firewall object is a singularity - it must have the name %s", firewallName)
	}

	if !r.EnableSignatureCheck {
		return nil
	}

	ok, err := f.Spec.Data.Verify(r.CAPubKey, f.Spec.Signature)
	if err != nil {
		return fmt.Errorf("firewall spec could not be verified with signature: %w", err)
	}

	if !ok {
		return fmt.Errorf("firewall object was tampered; could not verify the values given in the firewall spec")
	}

	return nil
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
func (r *FirewallReconciler) reconcileFirewallServices(ctx context.Context, f firewallv1.Firewall) error {
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
func (r *FirewallReconciler) reconcileFirewallService(ctx context.Context, s firewallService, f firewallv1.Firewall) error {
	nn := types.NamespacedName{Name: s.name, Namespace: firewallv1.ClusterwideNetworkPolicyNamespace}
	meta := metav1.ObjectMeta{
		Name:      s.name,
		Namespace: firewallv1.ClusterwideNetworkPolicyNamespace,
		Labels:    map[string]string{exporterLabelKey: s.name},
	}

	var currentSvc corev1.Service
	err := r.Get(ctx, nn, &currentSvc)

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
		err = r.Create(ctx, &svc)
		if err != nil {
			return err
		}
	}

	if !reflect.DeepEqual(currentSvc.Spec, svc.Spec) || currentSvc.ObjectMeta.Labels == nil || !reflect.DeepEqual(currentSvc.ObjectMeta.Labels, svc.ObjectMeta.Labels) {
		currentSvc.Spec = svc.Spec
		currentSvc.ObjectMeta.Labels = svc.ObjectMeta.Labels
		err = r.Update(ctx, &currentSvc)
		if err != nil {
			return err
		}
	}

	var privateNet *firewallv1.FirewallNetwork
	for _, n := range f.Spec.FirewallNetworks {
		n := n
		if n.Networktype == nil {
			continue
		}

		switch *n.Networktype {
		case mn.PrivatePrimaryUnshared:
			privateNet = &n
		case mn.PrivatePrimaryShared:
			privateNet = &n
		}
	}

	if privateNet == nil {
		return fmt.Errorf("firewall networks contain no private network")
	}

	if len(privateNet.Ips) < 1 {
		return fmt.Errorf("private firewall network contains no ip")
	}

	endpoints := corev1.Endpoints{
		ObjectMeta: meta,
		Subsets: []corev1.EndpointSubset{
			{
				Addresses: []corev1.EndpointAddress{
					{
						IP: privateNet.Ips[0],
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
	err = r.Get(ctx, nn, &currentEndpoints)
	if err != nil && !errors.IsNotFound(err) {
		return err
	}

	if errors.IsNotFound(err) {
		err = r.Create(ctx, &endpoints)
		if err != nil {
			return err
		}
		return nil
	}

	if !reflect.DeepEqual(currentEndpoints.Subsets, endpoints.Subsets) {
		currentEndpoints.Subsets = endpoints.Subsets
		return r.Update(ctx, &currentEndpoints)
	}

	return nil
}

// updateStatus updates the status field for this firewall
func (r *FirewallReconciler) updateStatus(ctx context.Context, f firewallv1.Firewall) error {
	if f.Spec.DryRun {
		f.Status.FirewallStats = firewallv1.FirewallStats{
			RuleStats:   firewallv1.RuleStatsByAction{},
			DeviceStats: firewallv1.DeviceStatsByDevice{},
			IDSStats:    firewallv1.IDSStatsByDevice{},
		}
		f.Status.Updated.Time = time.Now()
		if err := r.Status().Update(ctx, &f); err != nil {
			return fmt.Errorf("unable to update firewall status, err: %w", err)
		}
		return nil
	}

	c := collector.NewNFTablesCollector(&r.Log)
	ruleStats := c.CollectRuleStats()

	f.Status.FirewallStats = firewallv1.FirewallStats{
		RuleStats: ruleStats,
	}
	deviceStats, err := c.CollectDeviceStats()
	if err != nil {
		return err
	}
	f.Status.FirewallStats.DeviceStats = deviceStats

	idsStats := firewallv1.IDSStatsByDevice{}
	if r.EnableIDS { // checks the CLI-flag
		s := suricata.New()
		ss, err := s.InterfaceStats(ctx)
		if err != nil {
			return err
		}
		for iface, stat := range *ss {
			idsStats[iface] = firewallv1.InterfaceStat{
				Drop:             stat.Drop,
				InvalidChecksums: stat.InvalidChecksums,
				Packets:          stat.Pkts,
			}
		}
	}
	f.Status.FirewallStats.IDSStats = idsStats

	f.Status.ControllerVersion = v.Version
	f.Status.Updated.Time = time.Now()

	if err := r.Status().Update(ctx, &f); err != nil {
		return fmt.Errorf("unable to update firewall status, err: %w", err)
	}
	return nil
}

// SetupWithManager configures this controller to watch for the CRDs in a specific namespace
func (r *FirewallReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.recorder = mgr.GetEventRecorderFor("FirewallController")
	triggerFirewallReconcilation := handler.EnqueueRequestsFromMapFunc(func(a client.Object) []reconcile.Request {
		return []reconcile.Request{
			{NamespacedName: types.NamespacedName{
				Name:      firewallName,
				Namespace: firewallv1.ClusterwideNetworkPolicyNamespace,
			}},
		}
	})
	namespacePredicate := predicate.NewPredicateFuncs(func(obj client.Object) bool {
		return obj.GetNamespace() == namespace
	})
	return ctrl.NewControllerManagedBy(mgr).
		For(&firewallv1.Firewall{}, builder.WithPredicates(namespacePredicate)).
		// don't trigger a reconcilation for status updates
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Watches(&source.Kind{Type: &corev1.Service{}}, triggerFirewallReconcilation).
		Complete(r)
}
