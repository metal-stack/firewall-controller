// Package v1 contains API Schema definitions for the firewall v1 API group
// +kubebuilder:object:generate=true
// +groupName=metal-stack.io
//
// +kubebuilder:webhook:path=/validate-metal-stack-io-v1-clusterwide-network-policy,mutating=false,failurePolicy=fail,groups=metal-stack.io,resources=clusterwidenetworkpolicy,verbs=create;update,versions=v1,name=metal-stack.io,sideEffects=None,admissionReviewVersions=v1
//
// +kubebuilder:webhook:path=/mutate-metal-stack-io-v1-clusterwide-network-policy,mutating=true,failurePolicy=fail,groups=metal-stack.io,resources=clusterwidenetworkpolicy,verbs=create,versions=v1,name=metal-stack.io,sideEffects=None,admissionReviewVersions=v1
package v1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion is group version used to register these objects
	GroupVersion = schema.GroupVersion{Group: "metal-stack.io", Version: "v1"}

	// SchemeBuilder is used to add go types to the GroupVersionKind scheme
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func init() {
	SchemeBuilder.Register(
		&ClusterwideNetworkPolicy{},
		&ClusterwideNetworkPolicyList{},
	)
}
