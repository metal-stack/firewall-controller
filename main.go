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

	_ "github.com/metal-stack/firewall-controller/statik"
	"github.com/rakyll/statik/fs"

	"github.com/metal-stack/firewall-controller/controllers"
	"github.com/metal-stack/firewall-controller/controllers/crd"
	"github.com/metal-stack/v"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
	// +kubebuilder:scaffold:imports
)

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
		metricsAddr          string
		enableLeaderElection bool
		hostsFile            string
		serviceIP            string
		privateVrfID         int64
	)
	flag.StringVar(&metricsAddr, "metrics-addr", ":8080", "The address the metric endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "enable-leader-election", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.StringVar(&hostsFile, "hosts-file", "/etc/hosts", "The hosts file to manipulate for the droptailer.")
	flag.StringVar(&serviceIP, "service-ip", "172.17.0.1", "The ip where firewall services are exposed.")
	flag.Int64Var(&privateVrfID, "private-vrf", 0, "the vrf id of the private network.")
	flag.Parse()

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
	stopCh := ctrl.SetupSignalHandler()
	go func() {
		setupLog.Info("starting firewall-controller", "version", v.V)
		if err := mgr.Start(stopCh); err != nil {
			setupLog.Error(err, "problem running firewall-controller")
			panic(err)
		}
	}()

	if started := mgr.GetCache().WaitForCacheSync(stopCh); !started {
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
	if err = (&controllers.FirewallReconciler{
		Client:       mgr.GetClient(),
		Log:          ctrl.Log.WithName("controllers").WithName("Firewall"),
		Scheme:       mgr.GetScheme(),
		ServiceIP:    serviceIP,
		PrivateVrfID: privateVrfID,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Firewall")
		os.Exit(1)
	}
	// +kubebuilder:scaffold:builder

	// FIXME howto cope with OS signals ?
	<-stopCh
}

func readCRDsFromVFS() (map[string][]byte, error) {
	statikFS, err := fs.NewWithNamespace("crd")
	if err != nil {
		setupLog.Error(err, "unable to create virtual fs")
		return nil, err
	}
	crdMap := make(map[string][]byte)
	err = fs.Walk(statikFS, "/", func(path string, info os.FileInfo, err error) error {
		setupLog.Info("p", "path", path)
		if info.IsDir() {
			return nil
		}
		b, readerr := fs.ReadFile(statikFS, path)
		if readerr != nil {
			return fmt.Errorf("unable to readfile:%v", readerr)
		}
		crdMap[path] = b
		setupLog.Info("crd", "path", path, "info", info)
		return nil
	})
	if err != nil {
		setupLog.Error(err, "unable to read crs from virtual fs")
		return nil, err
	}
	return crdMap, nil
}
