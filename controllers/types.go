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

package controllers

import (
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"

	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
	"github.com/metal-stack/firewall-controller/pkg/nftables"
)

type CreateFirewall = func(
	cwnps *firewallv1.ClusterwideNetworkPolicyList,
	svcs *corev1.ServiceList,
	spec firewallv1.FirewallSpec,
	cache nftables.FQDNCache,
	log logr.Logger,
) FirewallInterface

//go:generate mockgen -destination=./mocks/mock_firewall.go -package=mocks . FirewallInterface
type FirewallInterface interface {
	Reconcile() (bool, error)
	Flush() error
}

type DNSProxy interface {
	Run()
	UpdateDNSServerAddr(addr string) error
	Stop()
}

func NewFirewall(
	cwnps *firewallv1.ClusterwideNetworkPolicyList,
	svcs *corev1.ServiceList,
	spec firewallv1.FirewallSpec,
	cache nftables.FQDNCache,
	log logr.Logger,
) FirewallInterface {
	return nftables.NewFirewall(cwnps, svcs, spec, cache, log)
}
