package controllers

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/go-logr/logr"
	mn "github.com/metal-stack/metal-lib/pkg/net"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
	"github.com/metal-stack/firewall-controller-manager/api/v2/helper"
	firewallv1 "github.com/metal-stack/firewall-controller/v2/api/v1"
	"github.com/metal-stack/firewall-controller/v2/pkg/network"
	"github.com/metal-stack/firewall-controller/v2/pkg/nftables"
	"github.com/metal-stack/firewall-controller/v2/pkg/updater"
)

// FirewallReconciler reconciles a Firewall object
type FirewallReconciler struct {
	SeedClient  client.Client
	ShootClient client.Client

	Recorder record.EventRecorder
	Log      logr.Logger
	Ctx      context.Context
	Scheme   *runtime.Scheme

	Updater      *updater.Updater
	TokenUpdater *helper.ShootAccessTokenUpdater

	FirewallName string
	Namespace    string

	recordFirewallEvent func(f *firewallv2.Firewall, eventtype, reason, message string)

	SeedUpdatedFunc func()

	FrrVersion *semver.Version
}

const (
	reconciliationInterval = 10 * time.Second

	nftablesExporterService   = "node-exporter"
	nftablesExporterNamedPort = "nodeexporter"
	nftablesExporterPort      = 9100
	nodeExporterService       = "nftables-exporter"
	nodeExporterNamedPort     = "nftexporter"
	nodeExporterPort          = 9630
	exporterLabelKey          = "app"
)

// SetupWithManager configures this controller to watch for the CRDs in a specific namespace
func (r *FirewallReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.recordFirewallEvent = updater.ShootRecorderNamespaceRewriter(r.Recorder)

	return ctrl.NewControllerManagedBy(mgr).
		For(&firewallv2.Firewall{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})). // don't trigger a reconciliation for status updates
		WithEventFilter(predicate.NewPredicateFuncs(func(object client.Object) bool {
			return object.GetNamespace() == r.Namespace && object.GetName() == r.FirewallName
		})).
		Complete(r)
}

// Reconcile reconciles a firewall by:
// - rendering nftables rules (changes in firewall networks)
// - exposing local services (nftables exporter and node exporter) in the shoot cluster as services
func (r *FirewallReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.Log.Info("reconciling firewall resource")

	f := &firewallv2.Firewall{}
	if err := r.SeedClient.Get(ctx, req.NamespacedName, f); err != nil {
		if apierrors.IsNotFound(err) {
			r.Log.Info("flushing k8s firewall rules")

			defaultFw := nftables.NewFirewall(&firewallv2.Firewall{}, &firewallv1.ClusterwideNetworkPolicyList{}, &corev1.ServiceList{}, nil, logr.Discard(), r.Recorder)

			flushErr := defaultFw.Flush()
			if flushErr != nil {
				r.Log.Error(flushErr, "error flushing k8s firewall rules")
				return ctrl.Result{}, flushErr
			}

			return ctrl.Result{}, nil
		}

		return ctrl.Result{}, fmt.Errorf("error retrieving resource: %w", err)
	}

	if r.Updater != nil {
		r.Log.Info("running binary updater")

		err := r.Updater.Run(ctx, f)
		if err != nil {
			return ctrl.Result{}, err
		}
	}
	if r.TokenUpdater != nil && f.Status.ShootAccess != nil {
		r.TokenUpdater.UpdateShootAccess(f.Status.ShootAccess)
	}

	r.Log.Info("reconciling network settings")

	var errs []error
	changed, err := network.ReconcileNetwork(f, r.FrrVersion)
	if changed && err == nil {
		r.recordFirewallEvent(f, corev1.EventTypeNormal, "Network settings", "reconciliation succeeded (frr.conf)")
	} else if changed && err != nil {
		r.recordFirewallEvent(f, corev1.EventTypeWarning, "Network settings", fmt.Sprintf("reconciliation failed (frr.conf): %v", err))
	}
	if err != nil {
		errs = append(errs, err)
	}

	r.Log.Info("reconciling firewall services")
	if err = r.reconcileFirewallServices(ctx, f); err != nil {
		errs = append(errs, err)
	}

	r.Log.Info("reconciling ssh keys")
	if err := r.reconcileSSHKeys(f); err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		r.recordFirewallEvent(f, corev1.EventTypeWarning, "Error", errors.Join(errs...).Error())
		return ctrl.Result{}, errors.Join(errs...)
	}

	r.recordFirewallEvent(f, corev1.EventTypeNormal, "Reconciled", "nftables rules and statistics successfully")

	r.SeedUpdatedFunc()

	r.Log.Info("successfully reconciled firewall, requeuing in 3 minutes")

	return ctrl.Result{
		RequeueAfter: 3 * time.Minute,
	}, nil
}

type firewallService struct {
	name      string
	port      int32
	namedPort string
}

// reconcileFirewallServices reconciles the services and endpoints exposed by the firewall
func (r *FirewallReconciler) reconcileFirewallServices(ctx context.Context, f *firewallv2.Firewall) error {
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

	var errs []error
	for _, s := range services {
		err := r.reconcileFirewallService(ctx, s, f)
		if err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// reconcileFirewallService reconciles a single service that is to be exposed at the firewall.
func (r *FirewallReconciler) reconcileFirewallService(ctx context.Context, s firewallService, f *firewallv2.Firewall) error {
	nn := types.NamespacedName{Name: s.name, Namespace: firewallv1.ClusterwideNetworkPolicyNamespace}
	meta := metav1.ObjectMeta{
		Name:      s.name,
		Namespace: firewallv1.ClusterwideNetworkPolicyNamespace,
		Labels:    map[string]string{exporterLabelKey: s.name},
	}

	var currentSvc corev1.Service
	err := r.ShootClient.Get(ctx, nn, &currentSvc)
	if err != nil && !apierrors.IsNotFound(err) {
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

	if apierrors.IsNotFound(err) {
		err = r.ShootClient.Create(ctx, &svc)
		if err != nil {
			return err
		}
	}

	if !reflect.DeepEqual(currentSvc.Spec, svc.Spec) || currentSvc.Labels == nil || !reflect.DeepEqual(currentSvc.Labels, svc.Labels) {
		currentSvc.Spec = svc.Spec
		currentSvc.Labels = svc.Labels
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
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}

	if apierrors.IsNotFound(err) {
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

func (r *FirewallReconciler) reconcileSSHKeys(fw *firewallv2.Firewall) error {
	const (
		authorizedKeysPath = "/home/metal/.ssh/authorized_keys"
	)

	content := strings.Join(fw.Spec.SSHPublicKeys, "\n")

	err := os.WriteFile(authorizedKeysPath, []byte(content), 0600)
	if err != nil {
		return fmt.Errorf("unable to write authorized keys file: %w", err)
	}

	return nil
}
