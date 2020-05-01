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

// NetworkIDSSpec defines the desired state of Network
type NetworkIDSSpec struct {
	Enabled  bool   `json:"enabled,omitempty"`
	Interval string `json:"interval,omitempty"`
	StatsLog string `json:"statslog,omitempty"`
}

// NetworkIDSStatus defines the observed state of Network
type NetworkIDSStatus struct {
	IDSStatistic IDSStatistic `json:"IDSstatistics"`
	Updated      metav1.Time  `json:"lastRun,omitempty"`
}

// IDSStatistic contains ids statistics
type IDSStatistic struct {
	Items map[string]int64 `json:"stats"`
}

// NetworkIDS is the Schema for the networks API
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Enabled",type=boolean,JSONPath=`.spec.enabled`
// +kubebuilder:printcolumn:name="Interval",type=string,JSONPath=`.spec.interval`
type NetworkIDS struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NetworkIDSSpec   `json:"spec,omitempty"`
	Status NetworkIDSStatus `json:"status,omitempty"`
}

// NetworkIDSList contains a list of Network
// +kubebuilder:object:root=true
type NetworkIDSList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NetworkIDS `json:"items"`
}
