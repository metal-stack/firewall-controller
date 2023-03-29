package controllers

import (
	"context"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/go-logr/logr"
	v1 "github.com/metal-stack/firewall-controller/api/v1"
	"github.com/txn2/txeh"
	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	secretName              = "droptailer-client"     //nolint:gosec
	secretKeyCertificate    = "droptailer-client.crt" //nolint:gosec
	secretKeyCertificateKey = "droptailer-client.key" //nolint:gosec
	secretKeyCaCertificate  = "ca.crt"                //nolint:gosec
	defaultCertificateBase  = "/etc/droptailer-client"

	droptailerReconcileInterval = time.Second * 10
)

// DroptailerReconciler reconciles a Droptailer object
type DroptailerReconciler struct {
	client.Client
	Log       logr.Logger
	HostsFile string
	// FIXME is not filled properly
	certificateBase string
	oldPodIP        string
	hosts           *txeh.Hosts
}

// Reconcile droptailer with certificate and droptailer-server ip from pod inspection
// +kubebuilder:rbac:groups=metal-stack.io,resources=Droptailers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=metal-stack.io,resources=Droptailers/status,verbs=get;update;patch
func (r *DroptailerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("Droptailer", req.NamespacedName)
	requeue := ctrl.Result{
		RequeueAfter: droptailerReconcileInterval,
	}

	var secrets corev1.SecretList
	if err := r.List(ctx, &secrets, &client.ListOptions{Namespace: v1.ClusterwideNetworkPolicyNamespace}); err != nil {
		// we'll ignore not-found errors, since they can't be fixed by an immediate
		// requeue (we'll need to wait for a new notification), and we can get them
		// on deleted requests.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	var droptailerSecret corev1.Secret
	secretFound := false
	for _, s := range secrets.Items {
		if s.Name == secretName {
			droptailerSecret = s
			secretFound = true
			break
		}
	}
	if !secretFound {
		log.Info("droptailer-secret not found")
		return ctrl.Result{}, nil
	}

	log.Info("droptailer-secret", "name", droptailerSecret.Name)
	err := r.writeSecret(droptailerSecret)
	if err != nil {
		return requeue, err
	}

	var pods corev1.PodList
	if err := r.List(ctx, &pods, &client.ListOptions{Namespace: v1.ClusterwideNetworkPolicyNamespace}); err != nil {
		return ctrl.Result{}, fmt.Errorf("no pod running in namespace %v", v1.ClusterwideNetworkPolicyNamespace)
	}

	var droptailerPod *corev1.Pod
	for _, p := range pods.Items {
		p := p
		if strings.HasPrefix(p.Name, "droptailer") && p.Status.Phase == corev1.PodRunning {
			droptailerPod = &p
			break
		}
	}
	if droptailerPod == nil {
		return ctrl.Result{}, fmt.Errorf("droptailer server pod not found")
	}

	podIP := droptailerPod.Status.PodIP
	if podIP != "" && r.oldPodIP != podIP {
		log.Info("podIP changed, update /etc/hosts", "old", r.oldPodIP, "new", podIP)
		r.hosts.RemoveHost("droptailer")
		r.hosts.AddHost(podIP, "droptailer")
		err := r.hosts.Save()
		if err != nil {
			log.Error(err, "could not write droptailer hosts entry")
			return requeue, fmt.Errorf("could not write droptailer hosts entry:%w", err)
		}
		r.oldPodIP = podIP
	}

	return ctrl.Result{}, nil
}

func (r *DroptailerReconciler) writeSecret(secret corev1.Secret) error {
	keys := []string{secretKeyCaCertificate, secretKeyCertificate, secretKeyCertificateKey}
	certificateBase := defaultCertificateBase
	if r.certificateBase != "" {
		certificateBase = r.certificateBase
	}
	for _, k := range keys {
		v, ok := secret.Data[k]
		if !ok {
			return fmt.Errorf("could not find key in secret key:%s", k)
		}
		f := path.Join(certificateBase, k)
		err := os.WriteFile(f, v, 0600)
		if err != nil {
			return fmt.Errorf("could not write secret to certificate base folder:%w", err)
		}
	}
	return nil
}

// SetupWithManager configure this controller with required defaults
func (r *DroptailerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	hc := &txeh.HostsConfig{
		ReadFilePath:  r.HostsFile,
		WriteFilePath: r.HostsFile,
	}

	_, err := os.Stat(r.HostsFile)
	if os.IsNotExist(err) {
		empty, err := os.Create(r.HostsFile)
		if err != nil {
			return err
		}
		empty.Close()
	}

	hosts, err := txeh.NewHosts(hc)
	if err != nil {
		return fmt.Errorf("unable to create hosts editor:%w", err)
	}

	r.hosts = hosts
	certificateBase := os.Getenv("DROPTAILER_CLIENT_CERTIFICATE_BASE")

	if certificateBase == "" {
		r.certificateBase = certificateBase
	}
	namespacePredicate := predicate.NewPredicateFuncs(func(obj client.Object) bool {
		return obj.GetNamespace() == v1.ClusterwideNetworkPolicyNamespace
	})
	triggerDroptailerReconcilation := handler.EnqueueRequestsFromMapFunc(func(a client.Object) []reconcile.Request {
		return []reconcile.Request{
			{NamespacedName: types.NamespacedName{
				Name:      "trigger-reconcilation-for-droptailer",
				Namespace: v1.ClusterwideNetworkPolicyNamespace,
			}},
		}
	})

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}, builder.WithPredicates(namespacePredicate)).
		Watches(&source.Kind{Type: &corev1.Secret{}}, triggerDroptailerReconcilation).
		Complete(r)
}
