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
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/hashicorp/go-multierror"

	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
	"github.com/metal-stack/firewall-controller/pkg/collector"
	"github.com/metal-stack/firewall-controller/pkg/nftables"
	"github.com/metal-stack/firewall-controller/pkg/suricata"
	"github.com/metal-stack/metal-lib/pkg/sign"
	networking "k8s.io/api/networking/v1"
)

// FirewallReconciler reconciles a Firewall object
type FirewallReconciler struct {
	client.Client
	recorder             record.EventRecorder
	Log                  logr.Logger
	Scheme               *runtime.Scheme
	ServiceIP            string
	EnableIDS            bool
	EnableSignatureCheck bool
	CAPubKey             *rsa.PublicKey
}

const (
	firewallReconcileInterval = time.Second * 10
	firewallNamespace         = "firewall"
	firewallName              = "firewall"

	nftablesExporterService   = "node-exporter"
	nftablesExporterNamedPort = "nodeexporter"
	nftablesExporterPort      = 9100
	nodeExporterService       = "nftables-exporter"
	nodeExporterNamedPort     = "nftexporter"
	nodeExporterPort          = 9630
	exporterLabelKey          = "app"
)

var done = ctrl.Result{}

// Reconcile reconciles a firewall by:
// - reading ClusterwideNetworkPolicies and Services of type Loadbalancer
// - rendering nftables rules
// - updating the firewall object with nftable rule statistics grouped by action
// +kubebuilder:rbac:groups=metal-stack.io,resources=firewalls,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=metal-stack.io,resources=firewalls/status,verbs=get;update;patch
func (r *FirewallReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("firewall", req.NamespacedName)
	requeue := ctrl.Result{
		RequeueAfter: firewallReconcileInterval,
	}

	var f firewallv1.Firewall
	if err := r.Get(ctx, req.NamespacedName, &f); err != nil {
		if apierrors.IsNotFound(err) {
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

	if err := r.validateFirewall(ctx, f); err != nil {
		r.recorder.Event(&f, "Warning", "Unapplicable", err.Error())
		// don't requeue invalid firewall objects
		return done, err
	}

	i, err := time.ParseDuration(f.Spec.Interval)
	if err == nil {
		requeue.RequeueAfter = i
	}

	var errors *multierror.Error
	log.Info("migrating old global network policies to kind ClusterwideNetworkPolicy")
	if err = r.migrateToClusterwideNetworkPolicy(ctx, f, log); err != nil {
		errors = multierror.Append(errors, err)
	}

	log.Info("reconciling nftables rules")
	if err = r.reconcileRules(ctx, f, log); err != nil {
		errors = multierror.Append(errors, err)
	}

	log.Info("reconciling firewall services")
	if err = r.reconcileFirewallServices(ctx, log); err != nil {
		errors = multierror.Append(errors, err)
	}

	log.Info("updating status field")
	if err = r.updateStatus(ctx, f, log); err != nil {
		errors = multierror.Append(errors, err)
	}

	if errors.ErrorOrNil() != nil {
		r.recorder.Event(&f, "Warning", "Error", multierror.Flatten(errors).Error())
		return requeue, errors
	}

	r.recorder.Event(&f, "Normal", "Reconciled", "nftables rules and statistics successfully")
	log.Info("reconciled firewall")
	return requeue, nil
}

// validateFirewall validates a firewall object:
// - it must be a singularity in a fixed namespace
// - and for the triggered reconcilation request
// - the signature is valid (when signature checking is enabled)
func (r *FirewallReconciler) validateFirewall(ctx context.Context, f firewallv1.Firewall) error {
	if f.Namespace != firewallNamespace {
		return fmt.Errorf("firewall must be defined in namespace %s otherwise it won't take effect", firewallNamespace)
	}

	if f.Name != firewallName {
		return fmt.Errorf("firewall object is a singularity - it must have the name %s", firewallName)
	}

	if !r.EnableSignatureCheck {
		return nil
	}

	dataMarshalled, err := json.Marshal(&f.Spec.Data)
	if err != nil {
		return fmt.Errorf("could not marshal firewall values to json for signature check: %w", err)
	}
	r.Log.Info("checking firewall signature for", "values", dataMarshalled)

	ok, err := sign.VerifySignature(r.CAPubKey, f.Spec.Signature, dataMarshalled)
	if err != nil {
		return fmt.Errorf("firewall spec could not be verified with signature: %w", err)
	}

	if !ok {
		return fmt.Errorf("firewall object was tampered; could not verify the values given in the firewall spec")
	}

	return nil
}

// migrateToClusterwideNetworkPolicy migrates old network policy objects to the new kind ClusterwideNetworkPolicy
func (r *FirewallReconciler) migrateToClusterwideNetworkPolicy(ctx context.Context, f firewallv1.Firewall, log logr.Logger) error {
	npsToIgnore := []string{"egress-allow-http", "egress-allow-https", "egress-allow-any", "egress-allow-dns", "egress-allow-ntp"}

	var nps networking.NetworkPolicyList
	if err := r.Client.List(ctx, &nps); err != nil {
		return err
	}

	n := 0
	for _, np := range nps.Items {
		s := np.Spec
		if len(s.PodSelector.MatchExpressions) != 0 || len(s.PodSelector.MatchLabels) != 0 {
			continue
		}

		// is one of the old network policy objects like egress-allow-http that are replaced by cluster wide ones installed by gepm
		if contains(npsToIgnore, np.Name) {
			continue
		}

		cwnp, err := convert(np)
		if err != nil {
			return fmt.Errorf("could not migrate network policy to a cluster-wide np: %w", err)
		}

		if cwnp == nil {
			// nothing to do here because network policy translates to an empty cwnp
			continue
		}

		var current firewallv1.ClusterwideNetworkPolicy
		err = r.Get(ctx, types.NamespacedName{Name: cwnp.Name, Namespace: firewallNamespace}, &current)

		// cwnp already exists: don't try to merge or update - just ignore
		if err == nil {
			continue
		}

		if errors.IsNotFound(err) {
			err = r.Client.Create(ctx, cwnp)
		}

		if err != nil {
			return fmt.Errorf("could not migrate to cluster-wide network policy: %w", err)
		}
		n++
	}

	log.Info("migrated network policies to cluster-wide network policies", "n", n)

	return nil
}

func contains(l []string, e string) bool {
	for _, elem := range l {
		if elem == e {
			return true
		}
	}
	return false
}

// converts a network-policy object that was used before in a cluster-wide manner to the new CRD
func convert(np networking.NetworkPolicy) (*firewallv1.ClusterwideNetworkPolicy, error) {
	cwnp := firewallv1.ClusterwideNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      np.Name,
			Namespace: firewallNamespace,
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

// reconcileRules reconciles the nftable rules for this firewall
func (r *FirewallReconciler) reconcileRules(ctx context.Context, f firewallv1.Firewall, log logr.Logger) error {
	var clusterNPs firewallv1.ClusterwideNetworkPolicyList
	if err := r.List(ctx, &clusterNPs, client.InNamespace(f.Namespace)); err != nil {
		return err
	}

	var services v1.ServiceList
	if err := r.List(ctx, &services); err != nil {
		return err
	}

	nftablesFirewall := nftables.NewFirewall(&clusterNPs, &services, f.Spec)
	if err := nftablesFirewall.Reconcile(); err != nil {
		return err
	}

	return nil
}

type firewallService struct {
	name      string
	port      int32
	namedPort string
}

// reconcileFirewallServices reconciles the services and endpoints exposed by the firewall
func (r *FirewallReconciler) reconcileFirewallServices(ctx context.Context, log logr.Logger) error {
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
		err := r.reconcileFirewallService(ctx, s, log)
		if err != nil {
			errors = multierror.Append(errors, err)
		}
	}
	return errors
}

// reconcileFirewallService reconciles a single service that is to be exposed at the firewall.
func (r *FirewallReconciler) reconcileFirewallService(ctx context.Context, s firewallService, log logr.Logger) error {
	nn := types.NamespacedName{Name: s.name, Namespace: firewallNamespace}
	meta := metav1.ObjectMeta{
		Name:      s.name,
		Namespace: firewallNamespace,
		Labels:    map[string]string{exporterLabelKey: s.name},
	}

	var currentSvc v1.Service
	err := r.Get(ctx, nn, &currentSvc)

	if err != nil && !errors.IsNotFound(err) {
		return err
	}

	svc := v1.Service{
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

	if !reflect.DeepEqual(currentSvc.Spec, svc.Spec) {
		currentSvc.Spec = svc.Spec
		err = r.Update(ctx, &currentSvc)
		if err != nil {
			return err
		}
	}

	endpoints := v1.Endpoints{
		ObjectMeta: meta,
		Subsets: []v1.EndpointSubset{
			{
				Addresses: []corev1.EndpointAddress{
					{
						IP: r.ServiceIP,
					},
				},
				Ports: []v1.EndpointPort{
					{
						Name:     s.namedPort,
						Port:     s.port,
						Protocol: corev1.ProtocolTCP,
					},
				},
			},
		},
	}

	var currentEndpoints v1.Endpoints
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
func (r *FirewallReconciler) updateStatus(ctx context.Context, f firewallv1.Firewall, log logr.Logger) error {
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
		ss, err := s.InterfaceStats()
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

	f.Status.Updated.Time = time.Now()

	if err := r.Status().Update(ctx, &f); err != nil {
		return fmt.Errorf("unable to update firewall status, err: %w", err)
	}
	return nil
}

// SetupWithManager configures this controller to watch for the CRDs in a specific namespace
func (r *FirewallReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.recorder = mgr.GetEventRecorderFor("FirewallController")
	mapToFirewallReconcilation := handler.ToRequestsFunc(
		func(a handler.MapObject) []reconcile.Request {
			return []reconcile.Request{
				{NamespacedName: types.NamespacedName{
					Name:      firewallName,
					Namespace: firewallNamespace,
				}},
			}
		})
	triggerFirewallReconcilation := &handler.EnqueueRequestsFromMapFunc{
		ToRequests: mapToFirewallReconcilation,
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&firewallv1.Firewall{}).
		// don't trigger a reconcilation for status updates
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Watches(&source.Kind{Type: &firewallv1.ClusterwideNetworkPolicy{}}, triggerFirewallReconcilation).
		Watches(&source.Kind{Type: &networking.NetworkPolicy{}}, triggerFirewallReconcilation).
		Watches(&source.Kind{Type: &corev1.Service{}}, triggerFirewallReconcilation).
		Complete(r)
}
