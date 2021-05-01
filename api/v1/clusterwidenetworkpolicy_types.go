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

package v1

import (
	"fmt"
	"net"

	"github.com/hashicorp/go-multierror"
	corev1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// ClusterwideNetworkPolicy contains the desired state for a cluster wide network policy to be applied.
// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName=cwnp
// +kubebuilder:subresource:status
type ClusterwideNetworkPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec PolicySpec `json:"spec,omitempty"`
}

// ClusterwideNetworkPolicyList contains a list of ClusterwideNetworkPolicy
// +kubebuilder:object:root=true
type ClusterwideNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterwideNetworkPolicy `json:"items"`
}

const (
	// ClusterwideNetworkPolicyNamespace defines the namespace CNWPs are expected.
	ClusterwideNetworkPolicyNamespace = "firewall"
)

// PolicySpec defines the rules to create for ingress and egress
type PolicySpec struct {
	// Description is a free form string, it can be used by the creator of
	// the rule to store human readable explanation of the purpose of this
	// rule. Rules cannot be identified by comment.
	//
	// +optional
	Description string `json:"description,omitempty"`

	// List of ingress rules to be applied. Traffic is allowed to
	// a cluster if there is a ClusterwideNetworkPolicy that allows it, OR there is a service
	// exposed with type Loadbalancer. Clusters are isolated by default.
	// +optional
	Ingress []IngressRule `json:"ingress,omitempty"`

	// List of egress rules to be applied. Outgoing traffic is
	// allowed if there is a ClusterwideNetworkPolicy that allows it.
	// Clusters are isolated by default.
	// +optional
	Egress []EgressRule `json:"egress,omitempty"`
}

// IngressRule describes a particular set of traffic that is allowed to the cluster.
// The traffic must match both ports and from.
type IngressRule struct {
	// List of ports which should be made accessible on the cluster for this
	// rule. Each item in this list is combined using a logical OR. If this field is
	// empty or missing, this rule matches all ports (traffic not restricted by port).
	// If this field is present and contains at least one item, then this rule allows
	// traffic only if the traffic matches at least one port in the list.
	// +optional
	Ports []networking.NetworkPolicyPort `json:"ports,omitempty"`

	// List of sources which should be able to access the cluster for this rule.
	// Items in this list are combined using a logical OR operation. If this field is
	// empty or missing, this rule matches all sources (traffic not restricted by
	// source). If this field is present and contains at least one item, this rule
	// allows traffic only if the traffic matches at least one item in the from list.
	// +optional
	From []networking.IPBlock `json:"from,omitempty"`
}

// EgressRule describes a particular set of traffic that is allowed out of the cluster
// The traffic must match both ports and to.
type EgressRule struct {
	// List of destination ports for outgoing traffic.
	// Each item in this list is combined using a logical OR. If this field is
	// empty or missing, this rule matches all ports (traffic not restricted by port).
	// If this field is present and contains at least one item, then this rule allows
	// traffic only if the traffic matches at least one port in the list.
	// +optional
	Ports []networking.NetworkPolicyPort `json:"ports,omitempty"`

	// List of destinations for outgoing traffic of a cluster for this rule.
	// Items in this list are combined using a logical OR operation. If this field is
	// empty or missing, this rule matches all destinations (traffic not restricted by
	// destination). If this field is present and contains at least one item, this rule
	// allows traffic only if the traffic matches at least one item in the to list.
	// To rules can't contain ToFQDNs rules.
	// +optional
	To []networking.IPBlock `json:"to,omitempty"`

	// List of FQDNs(fully qualified domain name) for outgoing traffic of a cluster for this rule.
	// Items in this list are combined using a logical OR operation. This field is used as
	// whitelist of DNS names. If none specified, rule will not be applied.
	// ToFQDNs rules can't contain To rules.
	// +optional
	ToFQDNs []FQDNSelector `json:"toFQDNs,omitempty"`
}

// TODO add trailing dot?
// FQDNSelector describes rules for matching DNS names.
type FQDNSelector struct {
	// MatchName matches FQDN.
	// +kubebuilder:validation:Pattern=`^([-a-zA-Z0-9_]+[.]?)+$`
	MatchName string `json:"matchName,omitempty"`

	// MatchPattern allows using "*" to match DNS names.
	// "*" matches 0 or more valid characters.
	// +kubebuilder:validation:Pattern=`^([-a-zA-Z0-9_*]+[.]?)+$`
	MatchPattern string `json:"matchPattern,omitempty"`

	// Sets stores nftables sets used for rule
	// +optional
	Sets []string `json:"sets,omitempty"`
}

// Validate validates the spec of a ClusterwideNetworkPolicy
func (p *PolicySpec) Validate() error {
	var errors *multierror.Error
	for _, e := range p.Egress {
		errors = multierror.Append(errors, validatePorts(e.Ports), validateIPBlocks(e.To))
	}
	for _, i := range p.Ingress {
		errors = multierror.Append(errors, validatePorts(i.Ports), validateIPBlocks(i.From))
	}

	return errors.ErrorOrNil()
}

func validatePorts(ports []networking.NetworkPolicyPort) *multierror.Error {
	var errors *multierror.Error
	for _, p := range ports {
		if p.Port != nil && p.Port.Type != intstr.Int {
			errors = multierror.Append(errors, fmt.Errorf("only int ports are supported, but %v given", p.Port))
		}

		if p.Port != nil && (p.Port.IntValue() > 65535 || p.Port.IntValue() <= 0) {
			errors = multierror.Append(errors, fmt.Errorf("only ports between 0 and 65535 are allowed, but %v given", p.Port))
		}

		if p.Protocol != nil {
			proto := *p.Protocol
			if proto != corev1.ProtocolUDP && proto != corev1.ProtocolTCP {
				errors = multierror.Append(errors, fmt.Errorf("only TCP and UDP are supported as protocol, but %v given", proto))
			}
		}
	}
	return errors
}

func validateIPBlocks(blocks []networking.IPBlock) *multierror.Error {
	var errors *multierror.Error
	for _, b := range blocks {
		_, blockNet, err := net.ParseCIDR(b.CIDR)
		if err != nil {
			errors = multierror.Append(errors, fmt.Errorf("%v is not a valid IP CIDR", b.CIDR))
			continue
		}

		for _, e := range b.Except {
			exceptIP, exceptNet, err := net.ParseCIDR(b.CIDR)
			if err != nil {
				errors = multierror.Append(errors, fmt.Errorf("%v is not a valid IP CIDR", e))
				continue
			}

			if !blockNet.Contains(exceptIP) {
				errors = multierror.Append(errors, fmt.Errorf("%v is not contained in the IP CIDR %v", exceptIP, blockNet))
				continue
			}

			blockSize, _ := blockNet.Mask.Size()
			exceptSize, _ := exceptNet.Mask.Size()
			if exceptSize > blockSize {
				errors = multierror.Append(errors, fmt.Errorf("netmask size of network to be excluded must be smaller than netmask of the block CIDR"))
			}
		}
	}
	return errors
}

func init() {
	SchemeBuilder.Register(&ClusterwideNetworkPolicy{}, &ClusterwideNetworkPolicyList{})
}
