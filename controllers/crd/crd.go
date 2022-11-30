/*
Copyright 2018 The Kubernetes Authors.

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

// shameless copy from kubernetes-sigs/controller-runtime

package crd

import (
	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
	"strings"

	"time"

	"github.com/gobuffalo/flect"
	"k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"
)

// InstallOptions are the options for installing CRDs
type InstallOptions struct {
	// MaxTime is the max time to wait
	MaxTime time.Duration

	// PollInterval is the interval to check
	PollInterval time.Duration
}

// WaitForCRDs waits for the resources to appear in discovery
func WaitForCRDs(config *rest.Config, options InstallOptions, resourceNames ...string) error {
	waitingFor := map[schema.GroupVersion]*sets.String{}
	waitingFor[firewallv1.GroupVersion] = &sets.String{}
	for _, name := range resourceNames {
		plural := flect.Pluralize(strings.ToLower(name))
		waitingFor[firewallv1.GroupVersion].Insert(plural)
	}

	// Poll until all resources are found in discovery
	p := &poller{config: config, waitingFor: waitingFor}
	return wait.PollImmediate(options.PollInterval, options.MaxTime, p.poll)
}

// poller checks if all the resources have been found in discovery, and returns false if not
type poller struct {
	// config is used to get discovery
	config *rest.Config

	// waitingFor is the map of resources keyed by group version that have not yet been found in discovery
	waitingFor map[schema.GroupVersion]*sets.String
}

// poll checks if all the resources have been found in discovery, and returns false if not
func (p *poller) poll() (done bool, err error) {
	// Create a new clientset to avoid any client caching of discovery
	cs, err := clientset.NewForConfig(p.config)
	if err != nil {
		return false, err
	}

	allFound := true
	for gv, resources := range p.waitingFor {
		// All resources found, do nothing
		if resources.Len() == 0 {
			delete(p.waitingFor, gv)
			continue
		}

		// Get the Resources for this GroupVersion
		// TODO: Maybe the controller-runtime client should be able to do this...
		resourceList, err := cs.Discovery().ServerResourcesForGroupVersion(gv.Group + "/" + gv.Version)
		if err != nil {
			return false, nil //nolint:nilerr
		}

		// Remove each found resource from the resources set that we are waiting for
		for _, resource := range resourceList.APIResources {
			resources.Delete(resource.Name)
		}

		// Still waiting on some resources in this group version
		if resources.Len() != 0 {
			allFound = false
		}
	}
	return allFound, nil
}
