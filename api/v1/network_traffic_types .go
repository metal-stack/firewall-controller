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

// NetworkTrafficSpec defines the desired state of Network
type NetworkTrafficSpec struct {
	Enabled       bool   `json:"enabled,omitempty"`
	Interval      string `json:"interval,omitempty"`
	NodeExportURL string `json:"nodeexporterurl,omitempty"`
	Interfaces    string `json:"interfaces,omitempty"`
}

// NetworkTrafficStatus defines the observed state of Network
type NetworkTrafficStatus struct {
	DeviceStatistics DeviceStatistics `json:"devicestatistics"`
	Updated          metav1.Time      `json:"lastRun,omitempty"`
}

// DeviceStatistics is a list of statistics of all devices
type DeviceStatistics struct {
	Items []DeviceStatistic `json:"items"`
}

// DeviceStatistic contains statistics of a device
type DeviceStatistic struct {
	DeviceName string `json:"device"`
	InBytes    int64  `json:"in"`
	OutBytes   int64  `json:"out"`
}

// +kubebuilder:object:root=true

// NetworkTraffic is the Schema for the networks API
// +kubebuilder:printcolumn:name="NodeExporter",type=string,JSONPath=`.spec.nodeexporterurl`
// +kubebuilder:printcolumn:name="Enabled",type=boolean,JSONPath=`.spec.enabled`
// +kubebuilder:printcolumn:name="Interval",type=string,JSONPath=`.spec.interval`
// +kubebuilder:printcolumn:name="Interfaces",type=string,JSONPath=`.spec.interfaces`
type NetworkTraffic struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NetworkTrafficSpec   `json:"spec,omitempty"`
	Status NetworkTrafficStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NetworkTrafficList contains a list of Network
type NetworkTrafficList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NetworkTraffic `json:"items"`
}
