package network

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/Masterminds/semver/v3"
	"github.com/go-logr/logr"
	apiv2 "github.com/metal-stack/api/go/metalstack/api/v2"
	firewallv2 "github.com/metal-stack/firewall-controller-manager/api/v2"
	"github.com/metal-stack/os-installer/pkg/frr"
	osnet "github.com/metal-stack/os-installer/pkg/network"
)

const (
	MetalNetworkerConfig = "/etc/metal/install.yaml"
	frrConfig            = "/etc/frr/frr.conf"
)

// ReconcileNetwork reconciles the network settings for a firewall
// Changes both the FRR-Configuration and Nftable rules when network prefixes or FRR template changes
func ReconcileNetwork(log logr.Logger, f *firewallv2.Firewall, allocation *apiv2.MachineAllocation, frrVersion *semver.Version) (bool, error) {
	changed, err := frr.Render(context.Background(), &frr.Config{
		Log:        slog.New(logr.ToSlogHandler(log)),
		Reload:     true,
		Validate:   true,
		Network:    osnet.New(allocation),
		FRRVersion: frrVersion,
	})
	if err != nil {
		return changed, fmt.Errorf("error during network reconciliation: %w", err)
	}

	return changed, nil
}
