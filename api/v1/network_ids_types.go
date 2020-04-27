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
	"time"

	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	// NetworkIDSCRD is the apiresource of a NetworkIDS
	NetworkIDSCRD = apiextensionsv1beta1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "networkids." + GroupVersion.Group,
		},
		Spec: apiextensionsv1beta1.CustomResourceDefinitionSpec{
			Group:   GroupVersion.Group,
			Version: GroupVersion.Version,
			Scope:   apiextensionsv1beta1.NamespaceScoped,
			Names: apiextensionsv1beta1.CustomResourceDefinitionNames{
				Kind:     "NetworkIDS",
				Plural:   "networkids",
				Singular: "networkids",
				ListKind: "NetworkIDSList",
			},
			Subresources: &apiextensionsv1beta1.CustomResourceSubresources{
				Status: &apiextensionsv1beta1.CustomResourceSubresourceStatus{},
			},
		},
	}
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// NetworkIDSSpec defines the desired state of Network
type NetworkIDSSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	Enabled  bool          `json:"enabled,omitempty"`
	Interval time.Duration `json:"interval,omitempty"`
	StatsLog string        `json:"statslog,omitempty"`
}

// NetworkIDSStatus defines the observed state of Network
type NetworkIDSStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	IDSStatistic IDSStatistic `json:"IDSstatistics"`
	Updated      metav1.Time  `json:"lastRun,omitempty"`
}

// IDSStatistic contains ids statistics
type IDSStatistic struct {
	Items map[string]int64 `json:"stats"`
}

// +kubebuilder:object:root=true

// NetworkIDS is the Schema for the networks API
type NetworkIDS struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NetworkIDSSpec   `json:"spec,omitempty"`
	Status NetworkIDSStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NetworkIDSList contains a list of Network
type NetworkIDSList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NetworkIDS `json:"items"`
}
