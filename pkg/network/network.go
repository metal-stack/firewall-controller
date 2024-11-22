package network

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	firewallv2 "github.com/metal-stack/firewall-controller-manager/api/v2"
	"github.com/metal-stack/metal-go/api/models"
	"github.com/metal-stack/metal-networker/pkg/netconf"
)

const (
	MetalNetworkerConfig = "/etc/metal/install.yaml"
	frrConfig            = "/etc/frr/frr.conf"
)

var logger *slog.Logger

func init() {
	jsonHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{})
	l := slog.New(jsonHandler)

	logger = l.WithGroup("networker")
}

func GetLogger() *slog.Logger {
	return logger
}

// GetNewNetworks returns updated network models
func GetNewNetworks(f *firewallv2.Firewall, oldNetworks []*models.V1MachineNetwork) []*models.V1MachineNetwork {
	networkMap := map[string]firewallv2.FirewallNetwork{}
	for _, n := range f.Status.FirewallNetworks {
		if n.NetworkType == nil {
			continue
		}
		networkMap[*n.NetworkID] = n
	}

	newNetworks := []*models.V1MachineNetwork{}
	for _, n := range oldNetworks {
		if n == nil {
			continue
		}

		newNet := n
		newNet.Prefixes = networkMap[*n.Networkid].Prefixes
		newNetworks = append(newNetworks, newNet)
	}

	return newNetworks
}

// ReconcileNetwork reconciles the network settings for a firewall
// Changes both the FRR-Configuration and Nftable rules when network prefixes or FRR template changes
// Note: Right here the FRR Configs are being applied.
func ReconcileNetwork(f *firewallv2.Firewall) (changed bool, err error) {
	tmpFile, err := tmpFile(frrConfig)
	if err != nil {
		return false, fmt.Errorf("error during network reconciliation %v: %w", tmpFile, err)
	}
	defer func() {
		os.Remove(tmpFile)
	}()

	c, err := netconf.New(GetLogger(), MetalNetworkerConfig)
	if err != nil || c == nil {
		return false, fmt.Errorf("failed to init networker config: %w", err)
	}
	c.Networks = GetNewNetworks(f, c.Networks)
	c.FirewallDistance = uint8(f.Distance)

	a := netconf.NewFrrConfigApplier(netconf.Firewall, *c, tmpFile)
	tpl := netconf.MustParseTpl(netconf.TplFirewallFRR)

	changed, err = a.Apply(*tpl, tmpFile, frrConfig, true)
	if err != nil {
		return changed, fmt.Errorf("error during network reconciliation: %v: %w", tmpFile, err)
	}

	return changed, nil
}

func tmpFile(file string) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(file), filepath.Base(file))
	if err != nil {
		return "", err
	}

	err = f.Close()
	if err != nil {
		return "", err
	}

	return f.Name(), nil
}
