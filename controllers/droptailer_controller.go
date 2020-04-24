package controllers

import (
	"context"
	"fmt"
	"io/ioutil"
	"path"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
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
	Log             logr.Logger
	Scheme          *runtime.Scheme
	certificateBase string
}

// +kubebuilder:rbac:groups=firewall.metal-stack.io,resources=Droptailers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=firewall.metal-stack.io,resources=Droptailers/status,verbs=get;update;patch

func (r *DroptailerReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("Droptailer", req.NamespacedName)

	var secrets corev1.SecretList
	if err := r.List(ctx, &secrets, &client.ListOptions{Namespace: namespace}); err != nil {
		log.Error(err, "unable to get droptailer secrets")
		return ctrl.Result{}, err
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
		return ctrl.Result{}, fmt.Errorf("droptailer-secret not found")
	}
	err := r.writeSecret(droptailerSecret)
	if err != nil {
		return ctrl.Result{}, err
	}
	log.Info("droptailer-secret", "name", droptailerSecret.Name)
	// var droptailerPod corev1.Pod
	// if err := r.Get(ctx, req.NamespacedName, &droptailerPod); err != nil {
	// 	if !apierrors.IsNotFound(err) {
	// 		log.Error(err, "unable to get droptailer pod")
	// 		return ctrl.Result{}, err
	// 	}
	// }

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
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}).
		Owns(&corev1.Pod{}).
		Complete(r)
}
