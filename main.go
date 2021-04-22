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
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"time"

	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/metal-stack/metal-lib/pkg/sign"
	"github.com/metal-stack/v"

	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
	"github.com/metal-stack/firewall-controller/controllers"
	"github.com/metal-stack/firewall-controller/controllers/crd"
	"github.com/metal-stack/firewall-controller/pkg/dns"
	_ "github.com/metal-stack/firewall-controller/statik"
	// +kubebuilder:scaffold:imports
)

//go:embed config/crd/bases/*.yaml
var crds embed.FS

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	_ = clientgoscheme.AddToScheme(scheme)

	_ = firewallv1.AddToScheme(scheme)

	_ = apiextensions.AddToScheme(scheme)
	// +kubebuilder:scaffold:scheme
}

func main() {
	var (
		isVersion            bool
		metricsAddr          string
		enableLeaderElection bool
		enableIDS            bool
		enableSignatureCheck bool
		hostsFile            string
		runDNS               bool
		dnsPort              uint
	)
	flag.BoolVar(&isVersion, "v", false, "Show firewall-controller version")
	flag.StringVar(&metricsAddr, "metrics-addr", ":8080", "The address the metric endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "enable-leader-election", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&enableIDS, "enable-IDS", true, "Set this to false to exclude IDS.")
	flag.StringVar(&hostsFile, "hosts-file", "/etc/hosts", "The hosts file to manipulate for the droptailer.")
	flag.BoolVar(&enableSignatureCheck, "enable-signature-check", true, "Set this to false to ignore signature checking.")
	flag.BoolVar(&runDNS, "run-dns", false, "Set this to true to enable DNS based policies and run DNS proxy")
	flag.UintVar(&dnsPort, "dns-port", 1053, "Specify port to which DNS proxy should be bound")
	flag.Parse()

	if isVersion {
		fmt.Println(v.V.String())
		return
	}

	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))

	restConfig := ctrl.GetConfigOrDie()
	mgr, err := ctrl.NewManager(restConfig, ctrl.Options{
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

	crdMap, err := readCRDsFromVFS()
	if err != nil {
		setupLog.Error(err, "unable to read crds from virtual filesystem")
		os.Exit(1)
	}
	crds, err := crd.InstallCRDs(restConfig, crd.InstallOptions{
		CRDContents: crdMap,
	})
	if err != nil {
		setupLog.Error(err, "unable to create crds of firewall-controller")
		os.Exit(1)
	}

	err = crd.WaitForCRDs(restConfig, crds, crd.InstallOptions{MaxTime: 500 * time.Millisecond, PollInterval: 100 * time.Millisecond})
	if err != nil {
		setupLog.Error(err, "unable to wait for created crds of firewall-controller")
		os.Exit(1)
	}

	// Start DNS proxy if runDNS is specified
	var dnsCache *dns.DNSCache
	if runDNS {
		dnsCache = &dns.DNSCache{}

		dnsProxy := dns.NewDNSProxy(dnsPort, ctrl.Log.WithName("DNS proxy"), dnsCache)
		dnsProxy.Run()
	}

	// Droptailer Reconciler
	if err = (&controllers.DroptailerReconciler{
		Client:    mgr.GetClient(),
		Log:       ctrl.Log.WithName("controllers").WithName("Droptailer"),
		Scheme:    mgr.GetScheme(),
		HostsFile: hostsFile,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Droptailer")
		os.Exit(1)
	}

	// ClusterwideNetworkPolicy Reconciler
	if err = (&controllers.ClusterwideNetworkPolicyReconciler{
		Client: mgr.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("ClusterwideNetworkPolicy"),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ClusterwideNetworkPolicy")
		os.Exit(1)
	}

	// Firewall Reconciler
	caData := mgr.GetConfig().CAData
	caCert, err := sign.DecodeCertificate(caData)
	if err != nil {
		setupLog.Error(err, "unable to decode ca certificate")
		os.Exit(1)
	}

	caPubKey, err := sign.ExtractPubKey(caCert)
	if err != nil {
		setupLog.Error(err, "unable to extract rsa pub key from ca certificate")
		os.Exit(1)
	}

	if err = (&controllers.FirewallReconciler{
		Client:               mgr.GetClient(),
		Log:                  ctrl.Log.WithName("controllers").WithName("Firewall"),
		Scheme:               mgr.GetScheme(),
		EnableIDS:            enableIDS,
		EnableSignatureCheck: enableSignatureCheck,
		CAPubKey:             caPubKey,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Firewall")
		os.Exit(1)
	}
	// +kubebuilder:scaffold:builder

	<-ctx.Done()
}

func readCRDsFromVFS() (map[string][]byte, error) {
	crdMap := make(map[string][]byte)
	err := fs.WalkDir(crds, ".", func(path string, info os.DirEntry, err error) error {
		setupLog.Info("walk", "path", path)
		if info == nil || info.IsDir() {
			return nil
		}
		b, readerr := fs.ReadFile(crds, path)
		if readerr != nil {
			return fmt.Errorf("unable to readfile:%w", readerr)
		}
		crdMap[path] = b
		setupLog.Info("crd", "path", path)
		return nil
	})
	if err != nil {
		setupLog.Error(err, "unable to read crs from virtual fs")
		return nil, err
	}
	return crdMap, nil
}
