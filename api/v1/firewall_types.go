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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// Firewall is the Schema for the firewalls API
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Interval",type=string,JSONPath=`.spec.interval`
// +kubebuilder:printcolumn:name="InternalPrefixes",type=string,JSONPath=`.spec.internalprefixes`
type Firewall struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   FirewallSpec   `json:"spec,omitempty"`
	Status FirewallStatus `json:"status,omitempty"`
}

// FirewallList contains a list of Firewall
// +kubebuilder:object:root=true
type FirewallList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Firewall `json:"items"`
}

// FirewallSpec defines the desired state of Firewall
type FirewallSpec struct {
	// Interval on which rule reconciliation should happen
	Interval string `json:"interval,omitempty"`
	// DryRun if set to true, firewall rules are not applied
	DryRun bool `json:"dryrun,omitempty"`
	// TrafficControl defines where to store the generated ipv4 firewall rules on disk
	Ipv4RuleFile string `json:"ipv4rulefile,omitempty"`
	// RateLimits allows configuration of rate limit rules for interfaces.
	RateLimits []RateLimit `json:"ratelimits,omitempty"`
	// InternalPrefixes specify prefixes which are considered local to the partition or all regions.
	// Traffic to/from these prefixes is accounted as internal traffic
	InternalPrefixes []string `json:"internalprefixes,omitempty"`
	// EgressRules
	EgressRules []EgressRuleSNAT `json:"egressrules,omitempty"`
	// MachineNetworks holds the machine networks known at the metal-api
	MachineNetworks []MachineNetwork `json:"machinenetworks,omitempty"`
}

// FirewallStatus defines the observed state of Firewall
type FirewallStatus struct {
	Message       string        `json:"message,omitempty"`
	FirewallStats FirewallStats `json:"stats"`
	Updated       metav1.Time   `json:"lastRun,omitempty"`
}

// FirewallStats contains firewall statistics
type FirewallStats struct {
	RuleStats   RuleStatsByAction   `json:"rules"`
	DeviceStats DeviceStatsByDevice `json:"devices"`
	IDSStats    IDSStatsByDevice    `json:"idsstats"`
}

// RuleStatsByAction contains firewall rule statistics groups by action: e.g. accept, drop, policy, masquerade
type RuleStatsByAction map[string]RuleStats

// RuleStats contains firewall rule statistics of all rules of an action
type RuleStats map[string]RuleStat

// RuleStat contains the statistics for a single nftables rule
type RuleStat struct {
	Counter Counter `json:"counter"`
}

// Counter holds values of a nftables counter object
type Counter struct {
	Bytes   uint64 `json:"bytes"`
	Packets uint64 `json:"packets"`
}

// EgressRuleSNAT holds a Source-NAT rule
type EgressRuleSNAT struct {
	NetworkID string   `json:"network"`
	IPs       []string `json:"ips"`
}

// RateLimit contains the rate limit rule for a network.
type RateLimit struct {
	// Network specifies the network which should be rate limited
	Network string `json:"network,omitempty"`
	// Rate is the input rate in MiB/s
	Rate uint32 `json:"rate,omitempty"`
}

// DeviceStatsByDevice contains DeviceStatistics grouped by device name
type DeviceStatsByDevice map[string]DeviceStat

// DeviceStat contains statistics of a device
type DeviceStat struct {
	InBytes  uint64 `json:"in"`
	OutBytes uint64 `json:"out"`
	// Deprecated: TotalBytes is kept for backwards compatibility
	TotalBytes uint64 `json:"total"`
}

type IDSStatsByDevice map[string]InterfaceStat

type InterfaceStat struct {
	Drop             int `json:"drop"`
	InvalidChecksums int `json:"invalidchecksums"`
	Packets          int `json:"packets"`
}

// this is a copy of the models.V1MachineNetwork struct of metal-go
// this is needed because when using the imported struct we get this error:
// api/v1/zz_generated.deepcopy.go:250:12: (*in)[i].DeepCopyInto undefined (type models.V1MachineNetwork has no field or method DeepCopyInto)
type MachineNetwork struct {
	Asn                 *int64   `json:"asn"`
	Destinationprefixes []string `json:"destinationprefixes"`
	Ips                 []string `json:"ips"`
	Nat                 *bool    `json:"nat"`
	Networkid           *string  `json:"networkid"`
	Networktype         *string  `json:"networktype"`
	Prefixes            []string `json:"prefixes"`
	Private             *bool    `json:"private"`
	Underlay            *bool    `json:"underlay"`
	Vrf                 *int64   `json:"vrf"`
}

func init() {
	SchemeBuilder.Register(&Firewall{}, &FirewallList{})
}
