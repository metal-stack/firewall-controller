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
	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ClusterwideNetworkPolicy contains the desired state for a cluster wide network policy to be applied.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type ClusterwideNetworkPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec PolicySpec `json:"spec,omitempty"`

	Status ClusterwideNetworkPolicyStatus `json:"status,omitempty"`
}

// ClusterwideNetworkPolicyList contains a list of ClusterwideNetworkPolicy
// +kubebuilder:object:root=true
type ClusterwideNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterwideNetworkPolicy `json:"items"`
}

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
	// +optional
	To []networking.IPBlock `json:"to,omitempty"`
}

// ClusterwideNetworkPolicyStatus defines the observed state of ClusterwideNetworkPolicy
type ClusterwideNetworkPolicyStatus struct {
	Message string `json:"message,omitempty"`
}

func init() {
	SchemeBuilder.Register(&ClusterwideNetworkPolicy{}, &ClusterwideNetworkPolicyList{})
}
