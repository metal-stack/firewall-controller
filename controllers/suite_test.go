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

//nolint
package controllers

import (
	"crypto/md5" //nolint:gosec
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	apimachineryruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/envtest/printer"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
	"github.com/metal-stack/firewall-controller/pkg/nftables"
	// +kubebuilder:scaffold:imports
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

var cfg *rest.Config
var k8sClient client.Client
var testEnv *envtest.Environment

func TestAPIs(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecsWithDefaultAndCustomReporters(t,
		"Controller Suite",
		[]Reporter{printer.NewlineReporter{}})
}

var _ = BeforeSuite(func(done Done) {
	logf.SetLogger(zap.LoggerTo(GinkgoWriter, true))

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths: []string{filepath.Join("..", "config", "crd", "bases")},
	}

	var err error
	cfg, err = testEnv.Start()
	Expect(err).ToNot(HaveOccurred())
	Expect(cfg).ToNot(BeNil())

	Expect(firewallv1.AddToScheme(scheme.Scheme)).NotTo(HaveOccurred())
	Expect(corev1.AddToScheme(scheme.Scheme)).NotTo(HaveOccurred())

	// +kubebuilder:scaffold:scheme

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	Expect(err).ToNot(HaveOccurred())
	Expect(k8sClient).ToNot(BeNil())

	close(done)
}, 60)

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).ToNot(HaveOccurred())
})

func setupScheme() *apimachineryruntime.Scheme {
	scheme := runtime.NewScheme()
	_ = firewallv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	return scheme
}

func newCWNPReconciler(
	createFW CreateFirewall,
	cache nftables.FQDNCache,
	objects []runtime.Object,
) *ClusterwideNetworkPolicyReconciler {
	return &ClusterwideNetworkPolicyReconciler{
		Client:         fake.NewFakeClientWithScheme(setupScheme(), objects...),
		Log:            zap.New(zap.UseDevMode(true)),
		CreateFirewall: createFW,
		cache:          cache,
		skipDNS:        true,
	}
}

func newFirewall() *firewallv1.Firewall {
	spec := firewallv1.FirewallSpec{}
	typeMeta := metav1.TypeMeta{
		Kind:       "Firewall",
		APIVersion: firewallv1.GroupVersion.String(),
	}
	objMeta := metav1.ObjectMeta{
		Name:      firewallName,
		Namespace: firewallv1.ClusterwideNetworkPolicyNamespace,
	}

	return &firewallv1.Firewall{
		TypeMeta:   typeMeta,
		ObjectMeta: objMeta,
		Spec:       spec,
	}
}

func newCWNP(name string, egress []firewallv1.EgressRule) *firewallv1.ClusterwideNetworkPolicy {
	spec := firewallv1.PolicySpec{
		Egress: egress,
	}
	typeMeta := metav1.TypeMeta{
		Kind:       "ClusterwideNetworkPolicy",
		APIVersion: firewallv1.GroupVersion.String(),
	}
	objMeta := metav1.ObjectMeta{
		Name:      name,
		Namespace: firewallv1.ClusterwideNetworkPolicyNamespace,
	}

	return &firewallv1.ClusterwideNetworkPolicy{
		TypeMeta:   typeMeta,
		ObjectMeta: objMeta,
		Spec:       spec,
	}
}

func getCWNPChecksum(name string, egress []firewallv1.EgressRule) [16]byte {
	spec := newCWNP(name, egress).Spec
	j, _ := json.Marshal(spec) //nolint
	return md5.Sum(j)
}

func createTestFirewallFunc(fw FirewallInterface) CreateFirewall {
	return func(
		cwnps *firewallv1.ClusterwideNetworkPolicyList,
		svcs *corev1.ServiceList,
		spec firewallv1.FirewallSpec,
		cache nftables.FQDNCache,
		log logr.Logger,
	) FirewallInterface {
		return fw
	}
}
