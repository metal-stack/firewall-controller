package helper

import (
	"fmt"
	"net/netip"

	"go4.org/netipx"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
)

const (
	forbiddenCIDR = "ForbiddenCIDR"
)

// Create an IPSet from a given list of strings describing networks.
func BuildNetworksIPSet(networks []string) (*netipx.IPSet, error) {
	var externalBuilder netipx.IPSetBuilder

	for _, externalNetwork := range networks {
		parsedExternal, err := netip.ParsePrefix(externalNetwork)
		if err != nil {
			return nil, fmt.Errorf("failed to parse prefix: %w", err)
		}
		externalBuilder.AddPrefix(parsedExternal)
	}
	externalSet, err := externalBuilder.IPSet()
	if err != nil {
		return nil, fmt.Errorf("failed to create ipset: %w", err)
	}
	return externalSet, nil
}

func NetworkSetAsString(externalSet *netipx.IPSet) string {
	var allowedNetworksStr string
	if externalSet != nil {
		for i, r := range externalSet.Ranges() {
			if i > 0 {
				allowedNetworksStr += ","
			}
			if p, ok := r.Prefix(); ok {
				allowedNetworksStr += p.String()
			} else {
				allowedNetworksStr += r.String()
			}
		}
	}
	return allowedNetworksStr
}

func ValidateCIDR(name string, o runtime.Object, cidr string, ipset *netipx.IPSet, rec record.EventRecorder) (bool, error) {
	parsedTo, err := netip.ParsePrefix(cidr)
	if err != nil {
		return false, fmt.Errorf("failed to parse to address: %w", err)
	}
	if !ipset.ContainsPrefix(parsedTo) {
		allowedNetworksStr := NetworkSetAsString(ipset)
		if rec != nil {
			rec.Eventf(
				o,
				corev1.EventTypeWarning,
				forbiddenCIDR,
				"the specified of %q to address:%q is outside of the allowed network range:%q, ignoring",
				name, parsedTo.String(), allowedNetworksStr)
		}
		return false, nil
	}
	return true, nil
}
