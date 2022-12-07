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
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/go-logr/zapr"
	"github.com/metal-stack/v"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	firewallv2 "github.com/metal-stack/firewall-controller-manager/api/v2"
	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
	"github.com/metal-stack/firewall-controller/controllers"
	"github.com/metal-stack/firewall-controller/controllers/crd"
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
		shootKubeconfig      string
		seedKubeconfig       string
		firewallNamespace    string
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
	flag.StringVar(&shootKubeconfig, "shoot-kubeconfig", "/etc/firewall-controller/shoot.kubeconfig", "the path to the kubeconfig to talk to the shoot")
	flag.StringVar(&seedKubeconfig, "seed-kubeconfig", "/etc/firewall-controller/seed.kubeconfig", "the path to the kubeconfig to talk to the seed")
	flag.StringVar(&firewallNamespace, "firewall-namespace", "", "the name of the namespace of the firewall resource in the seed cluster to reconcile")
	flag.StringVar(&firewallName, "firewall-name", "", "the name of the firewall resource in the seed cluster to reconcile")

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
		l.Fatalw("-firewall-name flag is required")
	}
	if firewallNamespace == "" {
		l.Fatalw("-firewall-namespace flag is required")
	}

	ctrl.SetLogger(zapr.NewLogger(l.Desugar()))

	seedConfig, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: seedKubeconfig},
		&clientcmd.ConfigOverrides{},
	).ClientConfig()
	if err != nil {
		l.Fatalw("unable create seed rest config", "error", err)
	}

	shootConfig, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: shootKubeconfig},
		&clientcmd.ConfigOverrides{},
	).ClientConfig()
	if err != nil {
		l.Fatalw("unable create shoot rest config", "error", err)
	}
	shootClient, err := client.New(shootConfig, client.Options{Scheme: scheme})
	if err != nil {
		l.Fatalw("unable create shoot client", "error", err)
	}

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

	err = crd.WaitForCRDs(seedConfig, crd.InstallOptions{ // FIXME: can we remove this?
		MaxTime:      500 * time.Millisecond,
		PollInterval: 100 * time.Millisecond,
	}, "firewall", "clusterwidenetworkpolicy")
	if err != nil {
		setupLog.Error(err, "unable to wait for created crds of firewall-controller")
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
