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

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"github.com/metal-stack/v"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	corev1 "k8s.io/api/core/v1"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/discovery"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	firewallv2 "github.com/metal-stack/firewall-controller-manager/api/v2"
	v2 "github.com/metal-stack/firewall-controller-manager/api/v2"
	"github.com/metal-stack/firewall-controller-manager/api/v2/helper"
	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
	"github.com/metal-stack/firewall-controller/controllers"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	_ = clientgoscheme.AddToScheme(scheme)

	_ = firewallv1.AddToScheme(scheme)
	_ = firewallv2.AddToScheme(scheme)

	_ = apiextensions.AddToScheme(scheme)
	// +kubebuilder:scaffold:scheme
}

func main() {
	var (
		logLevel             string
		isVersion            bool
		metricsAddr          string
		enableLeaderElection bool
		enableIDS            bool
		enableSignatureCheck bool
		hostsFile            string
		firewallName         string
	)
	flag.StringVar(&logLevel, "log-level", "info", "the log level of the controller")
	flag.BoolVar(&isVersion, "v", false, "Show firewall-controller version")
	flag.StringVar(&metricsAddr, "metrics-addr", ":8080", "The address the metric endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "enable-leader-election", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&enableIDS, "enable-IDS", true, "Set this to false to exclude IDS.")
	flag.StringVar(&hostsFile, "hosts-file", "/etc/hosts", "The hosts file to manipulate for the droptailer.")
	flag.BoolVar(&enableSignatureCheck, "enable-signature-check", true, "Set this to false to ignore signature checking.")
	flag.StringVar(&firewallName, "firewall-name", "", "the name of the firewall resource in the seed cluster to reconcile (defaults to hostname)")

	flag.Parse()

	if isVersion {
		fmt.Println(v.V.String())
		return
	}

	l, err := newZapLogger(logLevel)
	if err != nil {
		setupLog.Error(err, "unable to parse log level")
		os.Exit(1)
	}

	if firewallName == "" {
		firewallName, err = os.Hostname()
		if err != nil {
			l.Fatalw("unable to default firewall name flag to hostname")
		}
	}

	ctrl.SetLogger(zapr.NewLogger(l.Desugar()))

	seedConfig := ctrl.GetConfigOrDie()
	mgr, err := ctrl.NewManager(seedConfig, ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: metricsAddr,
		Port:               9443,
		LeaderElection:     enableLeaderElection,
		LeaderElectionID:   "25f95f9f.metal-stack.io",
	})
	if err != nil {
		setupLog.Error(err, "unable to start firewall-controller manager")
		os.Exit(1)
	}

	ctx := ctrl.SetupSignalHandler()

	// FIXME better at the end and not in a go func
	go func() {
		setupLog.Info("starting firewall-controller", "version", v.V)
		if err := mgr.Start(ctx); err != nil {
			setupLog.Error(err, "problem running firewall-controller")
			panic(err)
		}
	}()

	if started := mgr.GetCache().WaitForCacheSync(ctx); !started {
		panic("not all started")
	}

	err = seedClientCheck(ctx, setupLog, seedConfig, mgr.GetClient(), firewallName)
	if err != nil {
		setupLog.Error(err, "not possible to connect to seed")
		os.Exit(1)
	}

	shootClient, firewallNamespace, err := newShootClientWithCheck(ctx, setupLog, mgr.GetClient(), firewallName)
	if err != nil {
		setupLog.Error(err, "unable to construct shoot client")
		os.Exit(1)
	}

	// Droptailer Reconciler
	if err = (&controllers.DroptailerReconciler{
		Client:    shootClient,
		Log:       ctrl.Log.WithName("controllers").WithName("Droptailer"),
		Scheme:    mgr.GetScheme(),
		HostsFile: hostsFile,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Droptailer")
		os.Exit(1)
	}

	// ClusterwideNetworkPolicy Reconciler
	if err = controllers.NewClusterwideNetworkPolicyReconciler(mgr).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ClusterwideNetworkPolicy")
		os.Exit(1)
	}

	if err = (&controllers.ClusterwideNetworkPolicyValidationReconciler{
		Client: shootClient,
		Log:    ctrl.Log.WithName("controllers").WithName("ClusterwideNetworkPolicyValidation"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ClusterwideNetworkPolicyValidation")
		os.Exit(1)
	}

	// Firewall Reconciler
	if err = (&controllers.FirewallReconciler{
		SeedClient:   mgr.GetClient(),
		ShootClient:  shootClient,
		Log:          ctrl.Log.WithName("controllers").WithName("Firewall"),
		Scheme:       mgr.GetScheme(),
		EnableIDS:    enableIDS,
		Namespace:    firewallNamespace,
		FirewallName: firewallName,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Firewall")
		os.Exit(1)
	}
	// +kubebuilder:scaffold:builder

	<-ctx.Done()
}

func seedClientCheck(ctx context.Context, log logr.Logger, config *rest.Config, c client.Client, firewallName string) error {
	discoveryClient := discovery.NewDiscoveryClientForConfigOrDie(config)

	resources, err := discoveryClient.ServerResourcesForGroupVersion(firewallv2.GroupVersion.String())
	if err != nil {
		return err
	}

	found := false
	for _, r := range resources.APIResources {
		if r.Kind == "Firewall" {
			found = true
			break
		}
	}
	if found {
		return nil
	}

	log.Info("client cannot find firewall v2 resource on server side, assuming that this firewall was provisioned with shoot client in the past")

	migrationSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "firewall-controller-migration-secret",
			Namespace: v2.FirewallShootNamespace,
		},
	}
	err = c.Get(ctx, client.ObjectKeyFromObject(migrationSecret), migrationSecret)
	if err != nil {
		return fmt.Errorf("no migration secret found, cannot run with shoot client")
	}

	log.Info("found migration secret, attempting to exchange kubeconfig from original provisioning process")

	kubeconfig := migrationSecret.Data["kubeconfig"]

	seedConfig, err := clientcmd.RESTConfigFromKubeConfig(kubeconfig)
	if err != nil {
		return fmt.Errorf("unable to create rest config from migration secret: %w", err)
	}

	seed, err := client.New(seedConfig, client.Options{
		Scheme: scheme,
	})
	if err != nil {
		return fmt.Errorf("unable to create seed client from migration secret: %w", err)
	}

	_, _, err = newShootClientWithCheck(ctx, log, seed, firewallName)
	if err != nil {
		return fmt.Errorf("unable to startup with seed client from migration secret: %w", err)
	}

	log.Info("possible to start up with client from migration secret, exchanging original kubeconfig")

	path := os.Getenv("KUBECONFIG")
	if path == "" {
		return fmt.Errorf("KUBECONFIG environment variable is not set, aborting")
	}

	err = os.WriteFile(path, kubeconfig, 0600)
	if err != nil {
		return fmt.Errorf("unable to write kubeconfig to destination: %w", err)
	}

	log.Info("exchanged kubeconfig, restarting controller")
	os.Exit(0)

	return nil
}

func newShootClientWithCheck(ctx context.Context, log logr.Logger, seed client.Client, firewallName string) (client.Client, string, error) {
	// TODO: maybe there is another way to get the seed namespace...
	seedNamespace, _, _ := strings.Cut(firewallName, "-firewall-")

	fwList := &firewallv2.FirewallList{}
	err := seed.List(ctx, fwList, &client.ListOptions{
		Namespace: seedNamespace,
	})
	if err != nil {
		return nil, "", fmt.Errorf("unable to list firewalls: %w", err)
	}

	var fws []firewallv2.Firewall
	for _, fw := range fwList.Items {
		if fw.Name == firewallName {
			fws = append(fws, fw)
		}
	}
	if len(fws) != 1 {
		return nil, "", fmt.Errorf("found no single firewall resource for firewall: %s", firewallName)
	}

	var (
		fw                = fws[0]
		firewallNamespace = fw.Namespace
		shootAccess       = fw.Status.ShootAccess
	)

	if shootAccess == nil {
		return nil, "", fmt.Errorf("shoot access status field is empty")
	}

	shootConfig, err := helper.NewShootConfig(ctx, seed, shootAccess)
	if err != nil {
		return nil, "", fmt.Errorf("unable to get shoot config: %w", err)
	}

	shootClient, err := client.New(shootConfig, client.Options{Scheme: scheme})
	if err != nil {
		return nil, "", fmt.Errorf("unable to create shoot client: %w", err)
	}

	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				fw := &firewallv2.Firewall{
					ObjectMeta: metav1.ObjectMeta{
						Name:      firewallName,
						Namespace: firewallNamespace,
					},
				}
				err = seed.Get(ctx, client.ObjectKeyFromObject(fw), fw)
				if err != nil {
					log.Error(err, "unable to get firewall resource, retrying in five minutes")
					continue
				}

				// TODO: implement ssh key rotation

				if fw.Status.ShootAccess != nil && (fw.Status.ShootAccess.APIServerURL != shootAccess.APIServerURL ||
					fw.Status.ShootAccess.GenericKubeconfigSecretName != shootAccess.GenericKubeconfigSecretName ||
					fw.Status.ShootAccess.TokenSecretName != shootAccess.TokenSecretName) {
					log.Info("shoot access has changed, restarting controller")
					ctx.Done()
					return
				}

				log.Info("shoot access has not changed, checking again in five minutes")
			case <-ctx.Done():
				return
			}
		}
	}()

	return shootClient, firewallNamespace, nil
}

func newZapLogger(levelString string) (*zap.SugaredLogger, error) {
	level, err := zap.ParseAtomicLevel(levelString)
	if err != nil {
		return nil, fmt.Errorf("unable to parse log level: %w", err)
	}

	cfg := zap.NewProductionConfig()
	cfg.Level = level
	cfg.EncoderConfig.TimeKey = "timestamp"
	cfg.EncoderConfig.EncodeTime = zapcore.RFC3339TimeEncoder

	l, err := cfg.Build()
	if err != nil {
		return nil, fmt.Errorf("can't initialize zap logger: %w", err)
	}

	return l.Sugar(), nil
}
