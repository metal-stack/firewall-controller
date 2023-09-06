package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/go-logr/zapr"
	v1 "github.com/metal-stack/firewall-controller/api/v1"
	"github.com/metal-stack/firewall-controller/api/v1/defaults"
	"github.com/metal-stack/firewall-controller/api/v1/validation"
	"github.com/metal-stack/firewall-controller/pkg/logger"
	"github.com/metal-stack/v"
	ctrl "sigs.k8s.io/controller-runtime"
)

var (
	setupLog = ctrl.Log.WithName("setup")
)

func main() {
	var (
		logLevel             string
		isVersion            bool
		metricsAddr          string
		healthAddr           string
		certDir              string
		enableLeaderElection bool
	)

	flag.StringVar(&logLevel, "log-level", "info", "The log level of the webhook")
	flag.BoolVar(&isVersion, "v", false, "Show version")
	flag.StringVar(&metricsAddr, "metrics-addr", ":2112", "the address the metric endpoint binds to")
	flag.StringVar(&healthAddr, "health-addr", ":8081", "the address the health endpoint binds to")
	flag.StringVar(&certDir, "cert-dir", "", "The directory that contains the server key and certificate for the webhook server")
	flag.BoolVar(&enableLeaderElection, "enable-leader-election", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager")

	flag.Parse()

	if isVersion {
		fmt.Println(v.V.String())
		return
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		MetricsBindAddress:     metricsAddr,
		HealthProbeBindAddress: healthAddr,
		Port:                   9443,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "firewall-controller-webhook-leader-election",
		CertDir:                certDir,
	})
	if err != nil {
		setupLog.Error(err, "unable to create manager")
		os.Exit(1)
	}

	l, err := logger.NewZapLogger(logLevel)
	if err != nil {
		setupLog.Error(err, "unable to parse log level")
		os.Exit(1)
	}
	log := zapr.NewLogger(l.Desugar())
	ctrl.SetLogger(log)

	err = ctrl.NewWebhookManagedBy(mgr).
		For(&v1.ClusterwideNetworkPolicy{}).
		WithDefaulter(defaults.NewDefaulter(log.WithName("defaulting-webhook"))).
		WithValidator(validation.NewValidator(log.WithName("validating-webhook"))).
		Complete()
	if err != nil {
		l.Fatalw("unable to create webhook", "error", err)
	}

	l.Infow("starting webhook", "version", v.V)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		l.Fatalw("problem running webhook", "error", err)
	}
}
