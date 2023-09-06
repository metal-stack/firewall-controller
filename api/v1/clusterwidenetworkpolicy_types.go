package v1

import (
	"strings"

	dnsgo "github.com/miekg/dns"
	networking "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type IPVersion string

const (
	// ClusterwideNetworkPolicyNamespace defines the namespace CNWPs are expected.
	ClusterwideNetworkPolicyNamespace           = "firewall"
	allowedDNSCharsREGroup                      = "[-a-zA-Z0-9_.]"
	IPv4                              IPVersion = "ip"
	IPv6                              IPVersion = "ip6"
)

// ClusterwideNetworkPolicy contains the desired state for a cluster wide network policy to be applied.
// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName=cwnp
// +kubebuilder:subresource:status
type ClusterwideNetworkPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PolicySpec   `json:"spec,omitempty"`
	Status PolicyStatus `json:"status,omitempty"`
}

// ClusterwideNetworkPolicyList contains a list of ClusterwideNetworkPolicy
// +kubebuilder:object:root=true
type ClusterwideNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterwideNetworkPolicy `json:"items"`
}

// PolicySpec defines the rules to create for ingress and egress
type PolicySpec struct {
	// Description is a free form string, it can be used by the creator of
	// the rule to store human-readable explanation of the purpose of this
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

type FQDNState map[string][]IPSet

// PolicyStatus defines the observed state for CWNP resource
type PolicyStatus struct {
	// FQDNState stores mapping from FQDN rules to nftables sets used for a firewall rule.
	// Key is either MatchName or MatchPattern
	// +optional
	FQDNState FQDNState `json:"fqdn_state,omitempty"`
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

	// List of FQDNs (fully qualified domain names) for outgoing traffic of a cluster for this rule.
	// Items in this list are combined using a logical OR operation. This field is used as
	// whitelist for DNS names. If none specified, no rule will be applied.
	// ToFQDNs rules can't contain To rules.
	// +optional
	ToFQDNs []FQDNSelector `json:"toFQDNs,omitempty"`
}

// FQDNSelector describes rules for matching DNS names.
type FQDNSelector struct {
	// MatchName matches FQDN.
	// +kubebuilder:validation:Pattern=`^([-a-zA-Z0-9_]+[.]?)+$`
	MatchName string `json:"matchName,omitempty"`

	// MatchPattern allows using "*" to match DNS names.
	// "*" matches 0 or more valid characters.
	// +kubebuilder:validation:Pattern=`^([-a-zA-Z0-9_*]+[.]?)+$`
	MatchPattern string `json:"matchPattern,omitempty"`
}

// IPSet stores set name association to IP addresses
type IPSet struct {
	FQDN           string      `json:"fqdn,omitempty"`
	SetName        string      `json:"setName,omitempty"`
	IPs            []string    `json:"ips,omitempty"`
	ExpirationTime metav1.Time `json:"expirationTime,omitempty"`
	Version        IPVersion   `json:"version,omitempty"`
}

func (l *ClusterwideNetworkPolicyList) GetFQDNs() []FQDNSelector {
	s := []FQDNSelector{}
	for _, i := range l.Items {
		for _, e := range i.Spec.Egress {
			s = append(s, e.ToFQDNs...)
		}
	}

	return s
}

func (s FQDNSelector) GetName() string {
	if s.MatchName != "" {
		return s.MatchName
	}

	return s.MatchPattern
}

func (s FQDNSelector) GetMatchName() string {
	return dnsgo.Fqdn(s.MatchName)
}

// GetRegex converts a MatchPattern into a regexp string
func (s FQDNSelector) GetRegex() string {
	// Handle "*" as match-all case
	if s.MatchPattern == "*" {
		return "(^(" + allowedDNSCharsREGroup + "+[.])+$)|(^[.]$)"
	}

	pattern := strings.TrimSpace(s.MatchPattern)
	pattern = strings.ToLower(dnsgo.Fqdn(pattern))

	// "." becomes a literal .
	pattern = strings.ReplaceAll(pattern, ".", "[.]")

	// "*" -- match-all allowed chars
	pattern = strings.ReplaceAll(pattern, "*", allowedDNSCharsREGroup+"*")

	// Anchor the match to require the whole string to match this expression
	return "^" + pattern + "$"
}
