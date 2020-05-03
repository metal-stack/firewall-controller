package controllers

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"time"

	"github.com/go-logr/logr"
	"github.com/txn2/txeh"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const (
	namespace               = "firewall"
	secretName              = "droptailer-client"
	secretKeyCertificate    = "droptailer-client.crt"
	secretKeyCertificateKey = "droptailer-client.key"
	secretKeyCaCertificate  = "ca.crt"
	defaultCertificateBase  = "/etc/droptailer-client"
)

// DroptailerReconciler reconciles a Droptailer object
type DroptailerReconciler struct {
	client.Client
	Log       logr.Logger
	Scheme    *runtime.Scheme
	HostsFile string
	// FIXME is not filled properly
	certificateBase string
	oldPodIP        string
	hosts           *txeh.Hosts
}

const (
	droptailerReconcileInterval = time.Second * 10
)

// Reconcile droptailer with certificate and droptailer-server ip from pod inspection
// +kubebuilder:rbac:groups=metal-stack.io,resources=Droptailers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=metal-stack.io,resources=Droptailers/status,verbs=get;update;patch
func (r *DroptailerReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("Droptailer", req.NamespacedName)
	requeue := ctrl.Result{
		RequeueAfter: droptailerReconcileInterval,
	}
	if req.Namespace != namespace {
		return requeue, nil
	}

	var secrets corev1.SecretList
	if err := r.List(ctx, &secrets, &client.ListOptions{Namespace: namespace}); err != nil {
		// we'll ignore not-found errors, since they can't be fixed by an immediate
		// requeue (we'll need to wait for a new notification), and we can get them
		// on deleted requests.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	var droptailerSecret corev1.Secret
	secretFound := false
	for _, s := range secrets.Items {
		if s.ObjectMeta.Name == secretName {
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

	var droptailerPod corev1.Pod
	if err := r.Get(ctx, req.NamespacedName, &droptailerPod); err != nil {
		return ctrl.Result{}, fmt.Errorf("droptailer-secret not found")
	}

	podIP := droptailerPod.Status.PodIP
	if podIP != "" && r.oldPodIP != podIP {
		log.Info("podIP changed, update /etc/hosts", "old", r.oldPodIP, "new", podIP)
		r.hosts.RemoveHost("droptailer")
		r.hosts.AddHost(podIP, "droptailer")
		err := r.hosts.Save()
		if err != nil {
			log.Error(err, "could not write droptailer hosts entry")
			return requeue, fmt.Errorf("could not write droptailer hosts entry:%v", err)
		}
		r.oldPodIP = podIP
	}

	return ctrl.Result{}, nil
}

func (r *DroptailerReconciler) writeSecret(secret corev1.Secret) error {
	keys := []string{secretKeyCaCertificate, secretKeyCertificate, secretKeyCertificateKey}
	for _, k := range keys {
		v, ok := secret.Data[k]
		if !ok {
			return fmt.Errorf("could not find key in secret key:%s", k)
		}
		f := path.Join(r.certificateBase, k)
		err := ioutil.WriteFile(f, v, 0640)
		if err != nil {
			return fmt.Errorf("could not write secret to certificate base folder:%v", err)
		}
	}
	return nil
}

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
	} else {
		return err
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

	genericPredicate := predicate.Funcs{
		GenericFunc: func(e event.GenericEvent) bool {
			if e.Meta.GetNamespace() == namespace {
				return true
			}
			return false
		},
	}

	mapToDroptailerReconcilation := handler.ToRequestsFunc(
		func(a handler.MapObject) []reconcile.Request {
			return []reconcile.Request{
				{NamespacedName: types.NamespacedName{
					Name:      "trigger-reconcilation-for-droptailer",
					Namespace: namespace,
				}},
			}
		})
	triggerDroptailerReconcilation := &handler.EnqueueRequestsFromMapFunc{
		ToRequests: mapToDroptailerReconcilation,
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}, builder.WithPredicates(genericPredicate)).
		Watches(&source.Kind{Type: &corev1.Secret{}}, triggerDroptailerReconcilation).
		Complete(r)
}
