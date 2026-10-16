package network

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/Masterminds/semver/v3"
	"github.com/go-logr/logr"
	apiv2 "github.com/metal-stack/api/go/metalstack/api/v2"
	firewallv2 "github.com/metal-stack/firewall-controller-manager/api/v2"
	"github.com/metal-stack/os-installer/pkg/frr"
	osnet "github.com/metal-stack/os-installer/pkg/network"
	"google.golang.org/protobuf/proto"
)

const (
	MetalNetworkerConfig = "/etc/metal/install.yaml"
	frrConfig            = "/etc/frr/frr.conf"
)

// GetNewNetworks returns updated network models
func GetNewNetworks(log logr.Logger, f *firewallv2.Firewall, oldNetworks []*apiv2.MachineNetwork) []*apiv2.MachineNetwork {
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

		newNet := proto.CloneOf(n)
		if newNetwork, ok := networkMap[n.Network]; ok {
			newNet.Prefixes = newNetwork.Prefixes
			newNetworks = append(newNetworks, newNet)
		} else {
			log.Error(errors.New("network not present firewall networks"), "network", n.Network)
		}
	}

	return newNetworks
}

// ReconcileNetwork reconciles the network settings for a firewall
// Changes both the FRR-Configuration and Nftable rules when network prefixes or FRR template changes
func ReconcileNetwork(log logr.Logger, f *firewallv2.Firewall, allocation *apiv2.MachineAllocation, frrVersion *semver.Version) (bool, error) {
	allocation.Networks = GetNewNetworks(log, f, allocation.Networks)

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
