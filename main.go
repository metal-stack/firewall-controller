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
	controllerclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"

	firewallv2 "github.com/metal-stack/firewall-controller-manager/api/v2"
	v2 "github.com/metal-stack/firewall-controller-manager/api/v2"
	"github.com/metal-stack/firewall-controller-manager/api/v2/helper"
	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
	"github.com/metal-stack/firewall-controller/controllers"
	// +kubebuilder:scaffold:imports
)

var (
	setupLog = ctrl.Log.WithName("setup")
	scheme   = runtime.NewScheme()
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
		enableIDS            bool
		enableSignatureCheck bool
		hostsFile            string
		firewallName         string
	)

	flag.StringVar(&logLevel, "log-level", "info", "the log level of the controller")
	flag.BoolVar(&isVersion, "v", false, "Show firewall-controller version")
	flag.StringVar(&metricsAddr, "metrics-addr", ":8080", "The address the metric endpoint binds to.")
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
	ctrl.SetLogger(zapr.NewLogger(l.Desugar()))

	if firewallName == "" {
		firewallName, err = os.Hostname()
		if err != nil {
			l.Fatalw("unable to default firewall name flag to hostname", "error", err)
		}
	}

	var (
		ctx        = ctrl.SetupSignalHandler()
		seedConfig = ctrl.GetConfigOrDie()
	)

	client, err := controllerclient.New(seedConfig, controllerclient.Options{
		Scheme: scheme,
	})
	if err != nil {
		l.Fatalw("unable to create seed client", "error", err)
	}

	err = seedClientCheck(ctx, setupLog, seedConfig, client, firewallName, ctx)
	if err != nil {
		l.Fatalw("not possible to connect to seed", "error", err)
	}

	shootConfig, shootClient, firewallNamespace, err := newShootClientWithCheck(ctx, setupLog, client, firewallName, ctx)
	if err != nil {
		l.Fatalw("unable to construct shoot client", "error", err)
	}

	seedMgr, err := ctrl.NewManager(seedConfig, ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: metricsAddr,
		Port:               9443,
		Namespace:          firewallNamespace,
		LeaderElection:     false, // leader election does not make sense for this controller, it's always single managed by systemd
	})
	if err != nil {
		l.Fatalw("unable to create seed manager", "error", err)
	}

	shootMgr, err := ctrl.NewManager(shootConfig, ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: "0",
		LeaderElection:     false,
		Namespace:          v2.FirewallShootNamespace,
	})
	if err != nil {
		l.Fatalw("unable to create shoot manager", "error", err)
	}

	externalTrigger := make(chan event.GenericEvent)

	// Firewall Reconciler
	if err = (&controllers.FirewallReconciler{
		SeedClient:               seedMgr.GetClient(),
		ShootClient:              shootClient,
		Log:                      ctrl.Log.WithName("controllers").WithName("Firewall"),
		Scheme:                   scheme,
		EnableIDS:                enableIDS,
		Namespace:                firewallNamespace,
		FirewallName:             firewallName,
		Recorder:                 shootMgr.GetEventRecorderFor("FirewallController"),
		ExternalReconcileTrigger: externalTrigger,
	}).SetupWithManager(seedMgr); err != nil {
		l.Fatalw("unable to create firewall controller", "error", err)
	}

	// Droptailer Reconciler
	if err = (&controllers.DroptailerReconciler{
		Client:    shootMgr.GetClient(),
		Log:       ctrl.Log.WithName("controllers").WithName("Droptailer"),
		HostsFile: hostsFile,
	}).SetupWithManager(shootMgr); err != nil {
		l.Fatalw("unable to create droptailer controller", "error", err)
	}

	// ClusterwideNetworkPolicy Reconciler
	if err = (&controllers.ClusterwideNetworkPolicyReconciler{
		SeedClient:              seedMgr.GetClient(),
		ShootClient:             shootMgr.GetClient(),
		Log:                     ctrl.Log.WithName("controllers").WithName("ClusterwideNetworkPolicy"),
		FirewallName:            firewallName,
		SeedNamespace:           firewallNamespace,
		ExternalFirewallTrigger: externalTrigger,
	}).SetupWithManager(shootMgr); err != nil {
		l.Fatalw("unable to create clusterwidenetworkpolicy controller", "error", err)
	}

	if err = (&controllers.ClusterwideNetworkPolicyValidationReconciler{
		ShootClient: shootMgr.GetClient(),
		Log:         ctrl.Log.WithName("controllers").WithName("ClusterwideNetworkPolicyValidation"),
		Recorder:    shootMgr.GetEventRecorderFor("FirewallController"),
	}).SetupWithManager(shootMgr); err != nil {
		l.Fatalw("unable to create clusterwidenetworkpolicyvalidation controller", "error", err)
	}

	// +kubebuilder:scaffold:builder

	setupLog.Info("starting firewall-controller", "version", v.V)

	go func() {
		l.Infow("starting shoot controller", "version", v.V)
		if err := shootMgr.Start(ctx); err != nil {
			l.Fatalw("problem running shoot controller", "error", err)
		}
	}()

	if err := seedMgr.Start(ctx); err != nil {
		l.Errorw("problem running seed controller", "error", err)
		panic(err)
	}
}

func seedClientCheck(ctx context.Context, log logr.Logger, config *rest.Config, c client.Client, firewallName string, stop context.Context) error {
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
		log.Info("found firewall v2 resource on server side")
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

	_, _, _, err = newShootClientWithCheck(ctx, log, seed, firewallName, stop)
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

	return nil // not reachable, but satisfies the compiler
}

func newShootClientWithCheck(ctx context.Context, log logr.Logger, seed client.Client, firewallName string, stop context.Context) (*rest.Config, client.Client, string, error) {
	// TODO: maybe there is another way to get the seed namespace...
	seedNamespace, _, _ := strings.Cut(firewallName, "-firewall-")

	fwList := &firewallv2.FirewallList{}
	err := seed.List(ctx, fwList, &client.ListOptions{
		Namespace: seedNamespace,
	})
	if err != nil {
		return nil, nil, "", fmt.Errorf("unable to list firewalls: %w", err)
	}

	var fws []firewallv2.Firewall
	for _, fw := range fwList.Items {
		if fw.Name == firewallName {
			fws = append(fws, fw)
		}
	}
	if len(fws) != 1 {
		return nil, nil, "", fmt.Errorf("found no single firewall resource for firewall: %s", firewallName)
	}

	log.Info("found firewall resource to be responsible for", "firewall-name", firewallName, "namespace", seedNamespace)

	var (
		fw          = fws[0]
		shootAccess = fw.Status.ShootAccess
	)

	if shootAccess == nil {
		return nil, nil, "", fmt.Errorf("shoot access status field is empty")
	}

	expiresAt, shootConfig, err := helper.NewShootConfig(ctx, seed, shootAccess)
	if err != nil {
		return nil, nil, "", fmt.Errorf("unable to get shoot config: %w", err)
	}

	helper.ShutdownOnTokenExpiration(log.WithName("token-expiration"), expiresAt, stop)

	shootClient, err := client.New(shootConfig, client.Options{Scheme: scheme})
	if err != nil {
		return nil, nil, "", fmt.Errorf("unable to create shoot client: %w", err)
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
						Namespace: shootAccess.Namespace,
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

	return shootConfig, shootClient, shootAccess.Namespace, nil
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
