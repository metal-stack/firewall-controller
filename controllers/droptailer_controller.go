package controllers

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strconv"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/go-logr/logr"
	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
	"github.com/txn2/txeh"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	secretName              = "droptailer-client" //nolint:gosec
	secretKeyCertificate    = "tls.crt"           //nolint:gosec
	secretKeyCertificateKey = "tls.key"           //nolint:gosec
	secretKeyCaCertificate  = "ca.crt"            //nolint:gosec
	defaultCertificateBase  = "/etc/droptailer-client"
)

// DroptailerReconciler reconciles a Droptailer object
type DroptailerReconciler struct {
	ShootClient client.Client

	Log logr.Logger

	HostsFile string

	// FIXME is not filled properly
	certificateBase string
	oldPodIP        string
	hosts           *txeh.Hosts
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

	droptailerPredicate := predicate.NewPredicateFuncs(func(obj client.Object) bool {
		if obj.GetNamespace() != firewallv1.ClusterwideNetworkPolicyNamespace {
			return false
		}

		return obj.GetLabels()["app"] == "droptailer"
	})

	droptailerSecretPredicate := predicate.NewPredicateFuncs(func(obj client.Object) bool {
		if obj.GetNamespace() != firewallv1.ClusterwideNetworkPolicyNamespace {
			return false
		}

		return obj.GetName() == secretName
	})

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}, builder.WithPredicates(droptailerPredicate)).
		Watches(&source.Kind{Type: &corev1.Secret{}}, handler.EnqueueRequestsFromMapFunc(func(_ client.Object) []reconcile.Request {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			pods := &corev1.PodList{}
			if err := r.ShootClient.List(ctx, pods, client.InNamespace(firewallv1.ClusterwideNetworkPolicyNamespace), client.HasLabels{
				"app=droptailer",
			}); err != nil {
				return nil
			}

			if len(pods.Items) != 1 {
				return nil
			}

			pod := pods.Items[0]

			if !pod.GetDeletionTimestamp().IsZero() {
				return nil
			}

			r.Log.Info("triggering reconcile because droptailer secret was changed and droptailer pod is present")

			return []reconcile.Request{ctrl.Request{NamespacedName: types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}}}
		}), builder.WithPredicates(droptailerSecretPredicate)).
		Complete(r)
}

// Reconcile droptailer with certificate and droptailer-server ip from pod inspection
// +kubebuilder:rbac:groups=metal-stack.io,resources=Droptailers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=metal-stack.io,resources=Droptailers/status,verbs=get;update;patch
func (r *DroptailerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	pod := &corev1.Pod{}
	if err := r.ShootClient.Get(ctx, req.NamespacedName, pod); err != nil {
		if apierrors.IsNotFound(err) {
			r.Log.Info("resource no longer exists")
			return ctrl.Result{}, nil
		}

		return ctrl.Result{}, fmt.Errorf("error retrieving resource: %w", err)
	}

	if !pod.GetDeletionTimestamp().IsZero() {
		r.Log.Info("droptailer pod is being deleted")
		return ctrl.Result{}, nil
	}

	secret, err := getLatestSecret(ctx, r.ShootClient, firewallv1.ClusterwideNetworkPolicyNamespace, secretName)
	if err != nil {
		return ctrl.Result{}, err
	}
	err = r.writeSecret(secret)
	if err != nil {
		return ctrl.Result{}, err
	}

	// ugly migration code to for secretsmanager-secrets, remove when there is no firewall-image older than 2023-05 in use
	err = r.removeAndLinkCert(defaultCertificateBase, "droptailer-client.crt", secretKeyCertificate)
	if err != nil {
		return ctrl.Result{}, err
	}
	err = r.removeAndLinkCert(defaultCertificateBase, "droptailer-client.key", secretKeyCertificateKey)
	if err != nil {
		return ctrl.Result{}, err
	}

	podIP := pod.Status.PodIP
	if podIP != "" && r.oldPodIP != podIP {
		r.Log.Info("podIP changed, update /etc/hosts", "old", r.oldPodIP, "new", podIP)
		r.hosts.RemoveHost("droptailer")
		r.hosts.AddHost(podIP, "droptailer")
		err := r.hosts.Save()
		if err != nil {
			r.Log.Error(err, "could not write droptailer hosts entry")
			return ctrl.Result{}, fmt.Errorf("could not write droptailer hosts entry:%w", err)
		}
		r.oldPodIP = podIP
	}

	err = exec.Command("systemctl", "restart", "droptailer.service").Run()
	if err != nil {
		return ctrl.Result{}, err
	}

	r.Log.Info("droptailer successfully reconciled")

	return ctrl.Result{}, nil
}

func (r *DroptailerReconciler) removeAndLinkCert(base, old, new string) error {
	newFilename := path.Join(base, new)
	_, err := os.Stat(newFilename)
	if os.IsNotExist(err) {
		// new file does not exist, nothing to do
		return nil
	}
	if err != nil {
		return err
	}
	oldFilename := path.Join(base, old)
	if err := os.Remove(oldFilename); err != nil {
		r.Log.Info("could not remove", "file", oldFilename)
	}
	if err := os.Symlink(newFilename, oldFilename); err != nil {
		return err
	}
	return nil
}

func (r *DroptailerReconciler) writeSecret(secret *corev1.Secret) error {
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

func getLatestSecret(ctx context.Context, c client.Client, namespace string, name string) (*corev1.Secret, error) {
	secretList := &corev1.SecretList{}
	if err := c.List(ctx, secretList, client.InNamespace(namespace), client.MatchingLabels{
		"name":       name,
		"managed-by": "secrets-manager",
	}); err != nil {
		return nil, err
	}

	return getLatestIssuedSecret(secretList.Items)
}

// getLatestIssuedSecret returns the secret with the "issued-at-time" label that represents the latest point in time
func getLatestIssuedSecret(secrets []corev1.Secret) (*corev1.Secret, error) {
	if len(secrets) == 0 {
		return nil, fmt.Errorf("no secret found")
	}

	var newestSecret *corev1.Secret
	var currentIssuedAtTime time.Time
	for i := 0; i < len(secrets); i++ {
		// if some of the secrets have no "issued-at-time" label
		// we have a problem since this is the source of truth
		issuedAt, ok := secrets[i].Labels["issued-at-time"]
		if !ok {
			// there are some old secrets from ancient gardener versions which have to be skipped... (e.g. ssh-keypair.old)
			continue
		}

		issuedAtUnix, err := strconv.ParseInt(issuedAt, 10, 64)
		if err != nil {
			return nil, err
		}

		issuedAtTime := time.Unix(issuedAtUnix, 0).UTC()
		if newestSecret == nil || issuedAtTime.After(currentIssuedAtTime) {
			newestSecret = &secrets[i]
			currentIssuedAtTime = issuedAtTime
		}
	}

	if newestSecret == nil {
		return nil, fmt.Errorf("no secret found")
	}

	return newestSecret, nil
}
