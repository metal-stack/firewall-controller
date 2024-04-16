package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/metal-stack/v"

	"github.com/go-logr/logr"

	corev1 "k8s.io/api/core/v1"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/yaml"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	controllerclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	firewallv2 "github.com/metal-stack/firewall-controller-manager/api/v2"
	"github.com/metal-stack/firewall-controller-manager/api/v2/helper"

	firewallv1 "github.com/metal-stack/firewall-controller/v2/api/v1"
	"github.com/metal-stack/firewall-controller/v2/controllers"
	"github.com/metal-stack/firewall-controller/v2/pkg/sysctl"
	"github.com/metal-stack/firewall-controller/v2/pkg/updater"
	// +kubebuilder:scaffold:imports
)

const (
	seedKubeconfigPath = "/etc/firewall-controller/.seed-kubeconfig"
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
		kubeconfigPath       = os.Getenv("KUBECONFIG")
	)

	flag.StringVar(&logLevel, "log-level", "info", "the log level of the controller")
	flag.BoolVar(&isVersion, "v", false, "Show firewall-controller version")
	flag.StringVar(&metricsAddr, "metrics-addr", ":8080", "The address the metric endpoint binds to.")
	flag.BoolVar(&enableIDS, "enable-IDS", true, "Set this to false to exclude IDS.")
	flag.StringVar(&hostsFile, "hosts-file", "/etc/hosts", "The hosts file to manipulate for the droptailer.")
	flag.BoolVar(&enableSignatureCheck, "enable-signature-check", true, "Set this to false to ignore signature checking.")
	flag.StringVar(&firewallName, "firewall-name", "", "the name of the firewall resource in the seed cluster to reconcile (defaults to hostname)")

	if _, err := os.Stat(seedKubeconfigPath); err == nil || os.IsExist(err) {
		// controller-runtime registered this flag already, so we can use it
		err = flag.Set("kubeconfig", seedKubeconfigPath)
		if err != nil {
			setupLog.Error(err, "unable to set seed kubeconfig path")
			os.Exit(1)
		}
		kubeconfigPath = seedKubeconfigPath
	}

	flag.Parse()

	if isVersion {
		fmt.Println(v.V.String())
		return
	}

	jsonHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{})
	l := slog.New(jsonHandler)

	ctrl.SetLogger(logr.FromSlogHandler(jsonHandler))

	l.Info("using kubeconfig path", "path", kubeconfigPath)

	var (
		ctx        = ctrl.SetupSignalHandler()
		seedConfig = ctrl.GetConfigOrDie()
	)

	// FIXME validation and controller start should be refactored into own func which returns error
	// instead Fatalw or Error and panic here.
	var err error
	if firewallName == "" {
		firewallName, err = os.Hostname()
		if err != nil {
			l.Error("unable to default firewall name flag to hostname", "error", err)
			panic(err)
		}
	}

	if kubeconfigPath == "" {
		l.Error("kubeconfig path is empty, aborting")
		panic(err)
	}

	seedClient, err := controllerclient.New(seedConfig, controllerclient.Options{
		Scheme: scheme,
	})
	if err != nil {
		l.Error("unable to create seed client", "error", err)
		panic(err)
	}

	rawKubeconfig, err := os.ReadFile(kubeconfigPath)
	if err != nil {
		l.Error("unable to read kubeconfig", "path", kubeconfigPath, "error", err)
		panic(err)
	}

	seedNamespace, err := getSeedNamespace(rawKubeconfig)
	if err != nil {
		l.Error("unable to find seed namespace from kubeconfig", "error", err)
		panic(err)
	}

	fw, err := findResponsibleFirewall(ctx, seedClient, firewallName, seedNamespace)
	if err != nil {
		l.Error("unable to find firewall resource to be responsible for", "error", err)
		panic(err)
	}

	l.Info("found firewall resource to be responsible for", "firewall-name", firewallName, "namespace", seedNamespace)

	shootAccessHelper := helper.NewShootAccessHelper(seedClient, fw.Status.ShootAccess)
	if err != nil {
		l.Error("unable to construct shoot access helper", "error", err)
		panic(err)
	}

	accessTokenUpdater, err := helper.NewShootAccessTokenUpdater(shootAccessHelper, "/etc/firewall-controller")
	if err != nil {
		l.Error("unable to create shoot access token updater", "error", err)
		panic(err)
	}

	err = accessTokenUpdater.UpdateContinuously(ctrl.Log.WithName("token-updater"), ctx)
	if err != nil {
		l.Error("unable to start token updater", "error", err)
		panic(err)
	}

	shootConfig, err := shootAccessHelper.RESTConfig(ctx)
	if err != nil {
		l.Error("unable to create shoot config", "error", err)
		panic(err)
	}

	seedMgr, err := ctrl.NewManager(seedConfig, ctrl.Options{
		Scheme: scheme,
		Metrics: server.Options{
			BindAddress: metricsAddr,
		},
		WebhookServer: webhook.NewServer(webhook.Options{
			Port: 9443,
		}),
		Cache: cache.Options{
			DefaultNamespaces: map[string]cache.Config{
				seedNamespace: cache.Config{},
			},
		},
		Client: controllerclient.Options{
			Cache: &controllerclient.CacheOptions{
				// we need to disable caches on secrets as otherwise the controller would need list access to secrets
				// see: https://github.com/kubernetes-sigs/controller-runtime/issues/550
				DisableFor: []controllerclient.Object{&corev1.Secret{}},
			},
		},
		LeaderElection: false, // leader election does not make sense for this controller, it's always single managed by systemd
	})
	if err != nil {
		l.Error("unable to create seed manager", "error", err)
		panic(err)
	}

	shootMgr, err := ctrl.NewManager(shootConfig, ctrl.Options{
		Scheme: scheme,
		Metrics: server.Options{
			BindAddress: "0",
		},
		LeaderElection: false,
	})
	if err != nil {
		l.Error("unable to create shoot manager", "error", err)
		panic(err)
	}

	shootClient, err := controllerclient.New(shootConfig, controllerclient.Options{Scheme: scheme})
	if err != nil {
		l.Error("unable to create shoot client", "error", err)
		panic(err)
	}

	updater := updater.New(ctrl.Log.WithName("updater"), shootMgr.GetEventRecorderFor("FirewallController"))

	fwmReconciler := &controllers.FirewallMonitorReconciler{
		ShootClient:  shootMgr.GetClient(),
		Log:          ctrl.Log.WithName("controllers").WithName("FirewallMonitorReconciler"),
		Recorder:     shootMgr.GetEventRecorderFor("FirewallMonitorController"),
		IDSEnabled:   enableIDS,
		FirewallName: firewallName,
		Namespace:    firewallv2.FirewallShootNamespace,
	}

	// Firewall Reconciler
	if err = (&controllers.FirewallReconciler{
		SeedClient:      seedMgr.GetClient(),
		ShootClient:     shootClient,
		Log:             ctrl.Log.WithName("controllers").WithName("Firewall"),
		Scheme:          scheme,
		Namespace:       seedNamespace,
		FirewallName:    firewallName,
		Recorder:        shootMgr.GetEventRecorderFor("FirewallController"),
		Updater:         updater,
		SeedUpdatedFunc: fwmReconciler.SeedUpdated,
		TokenUpdater:    accessTokenUpdater,
	}).SetupWithManager(seedMgr); err != nil {
		l.Error("unable to create firewall controller", "error", err)
		panic(err)
	}

	// Droptailer Reconciler
	if err = (&controllers.DroptailerReconciler{
		ShootClient: shootMgr.GetClient(),
		Log:         ctrl.Log.WithName("controllers").WithName("Droptailer"),
		HostsFile:   hostsFile,
	}).SetupWithManager(shootMgr); err != nil {
		l.Error("unable to create droptailer controller", "error", err)
		panic(err)
	}

	// ClusterwideNetworkPolicy Reconciler
	if err = (&controllers.ClusterwideNetworkPolicyReconciler{
		SeedClient:    seedMgr.GetClient(),
		ShootClient:   shootMgr.GetClient(),
		Log:           ctrl.Log.WithName("controllers").WithName("ClusterwideNetworkPolicy"),
		Recorder:      shootMgr.GetEventRecorderFor("FirewallController"),
		FirewallName:  firewallName,
		SeedNamespace: seedNamespace,
	}).SetupWithManager(shootMgr); err != nil {
		l.Error("unable to create clusterwidenetworkpolicy controller", "error", err)
		panic(err)
	}

	if err = (&controllers.ClusterwideNetworkPolicyValidationReconciler{
		ShootClient: shootMgr.GetClient(),
		Log:         ctrl.Log.WithName("controllers").WithName("ClusterwideNetworkPolicyValidation"),
		Recorder:    shootMgr.GetEventRecorderFor("FirewallController"),
	}).SetupWithManager(shootMgr); err != nil {
		l.Error("unable to create clusterwidenetworkpolicyvalidation controller", "error", err)
		panic(err)
	}

	// FirewallMonitorReconciler
	if err = (fwmReconciler).SetupWithManager(shootMgr); err != nil {
		l.Error("unable to create firewall monitor controller", "error", err)
		panic(err)
	}

	// +kubebuilder:scaffold:builder

	setupLog.Info("starting firewall-controller", "version", v.V)

	// before starting up the controllers, we update components to the specified versions
	// otherwise we can run into races where controllers start reconfiguring the firewall
	// while an update is progressing
	updaterCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	err = updater.Run(updaterCtx, fw)
	if err != nil {
		l.Error("unable to update firewall components", "error", err)
		panic(err)
	}

	go func() {
		l.Info("starting shoot controller", "version", v.V)
		if err := shootMgr.Start(ctx); err != nil {
			l.Error("problem running shoot controller", "error", err)
			panic(err)
		}
	}()

	err = sysctl.Tune(l)
	if err != nil {
		l.Error("unable to tune kernel", "error", err)
	}

	if err := seedMgr.Start(ctx); err != nil {
		l.Error("problem running seed controller", "error", err)
		panic(err)
	}
}

func findResponsibleFirewall(ctx context.Context, seed controllerclient.Client, firewallName, seedNamespace string) (*firewallv2.Firewall, error) {
	fwList := &firewallv2.FirewallList{}
	err := seed.List(ctx, fwList, &controllerclient.ListOptions{
		Namespace: seedNamespace,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to list firewalls: %w", err)
	}

	var fws []firewallv2.Firewall
	for _, fw := range fwList.Items {
		if fw.Name == firewallName {
			fws = append(fws, fw)
		}
	}
	if len(fws) != 1 {
		return nil, fmt.Errorf("found no single firewall resource for firewall: %s", firewallName)
	}

	return &fws[0], nil
}

func getSeedNamespace(rawKubeconfig []byte) (string, error) {
	type config struct {
		SeedNamespace string `json:"current-context" yaml:"current-context"`
	}

	var c *config
	err := yaml.Unmarshal(rawKubeconfig, &c)
	if err != nil {
		return "", err
	}

	if c.SeedNamespace != "" {
		return c.SeedNamespace, nil
	}

	return "", fmt.Errorf("unable to figure out seed namespace from kubeconfig")
}
