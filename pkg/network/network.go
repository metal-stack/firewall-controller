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

type network struct {
	log        logr.Logger
	allocation *apiv2.MachineAllocation
}

func NewNetwork(log logr.Logger, allocation *apiv2.MachineAllocation) *network {
	return &network{
		log:        log,
		allocation: allocation,
	}
}

// GetNewNetworks returns updated network models
func GetNewNetworks(f *firewallv2.Firewall, oldNetworks []*apiv2.MachineNetwork) []*apiv2.MachineNetwork {
	networkMap := map[string]firewallv2.FirewallNetwork{}
	for _, n := range f.Status.FirewallNetworks {
		if n.NetworkType == nil {
			continue
		}
		networkMap[*n.NetworkID] = n
	}

	newNetworks := []*apiv2.MachineNetwork{}
	for _, n := range oldNetworks {
		if n == nil {
			continue
		}

		newNet := n
		newNet.Prefixes = networkMap[n.Network].Prefixes
		newNetworks = append(newNetworks, newNet)
	}

	return newNetworks
}

// ReconcileNetwork reconciles the network settings for a firewall
// Changes both the FRR-Configuration and Nftable rules when network prefixes or FRR template changes
func (n *network) ReconcileNetwork(f *firewallv2.Firewall, frrVersion *semver.Version) (bool, error) {
	n.allocation.Networks = GetNewNetworks(f, n.allocation.Networks)

	changed, err := frr.Render(context.Background(), &frr.Config{
		Log:        slog.New(logr.ToSlogHandler(n.log)),
		Reload:     true,
		Validate:   true,
		Network:    osnet.New(n.allocation),
		FRRVersion: frrVersion,
	})
	if err != nil {
		return changed, fmt.Errorf("error during network reconciliation: %w", err)
	}

	return changed, nil
}
