package network

import (
	"fmt"
	"os"
	"path/filepath"
	"text/template"

	"go.uber.org/zap"

	firewallv2 "github.com/metal-stack/firewall-controller-manager/api/v2"
	"github.com/metal-stack/metal-go/api/models"
	"github.com/metal-stack/metal-networker/pkg/netconf"

	"embed"
)

const (
	MetalNetworkerConfig = "/etc/metal/install.yaml"
	frrConfig            = "/etc/frr/frr.conf"
)

//go:embed *.tpl
var templates embed.FS
var logger *zap.SugaredLogger

func init() {
	l, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}

	logger = l.Sugar()
}

func GetLogger() *zap.SugaredLogger {
	return logger
}

// GetNewNetworks returns updated network models
func GetNewNetworks(f firewallv2.Firewall, oldNetworks []*models.V1MachineNetwork) []*models.V1MachineNetwork {
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
func ReconcileNetwork(f firewallv2.Firewall) (changed bool, err error) {
	tmpFile, err := tmpFile(frrConfig)
	if err != nil {
		return false, fmt.Errorf("error during network reconcilation %v: %w", tmpFile, err)
	}
	defer func() {
		os.Remove(tmpFile)
	}()

	c, err := netconf.New(GetLogger(), MetalNetworkerConfig)
	if err != nil || c == nil {
		return false, fmt.Errorf("failed to init networker config: %w", err)
	}
	c.Networks = GetNewNetworks(f, c.Networks)

	a := netconf.NewFrrConfigApplier(netconf.Firewall, *c, tmpFile)
	tpl, err := readTpl(netconf.TplFirewallFRR)
	if err != nil {
		return false, fmt.Errorf("error during network reconcilation: %v: %w", tmpFile, err)
	}

	changed, err = a.Apply(*tpl, tmpFile, frrConfig, true)
	if err != nil {
		return changed, fmt.Errorf("error during network reconcilation: %v: %w", tmpFile, err)
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

func readTpl(tplName string) (*template.Template, error) {
	contents, err := templates.ReadFile(tplName)
	if err != nil {
		return nil, err
	}

	t, err := template.New(tplName).Parse(string(contents))
	if err != nil {
		return nil, fmt.Errorf("could not parse template %v from embed.FS: %w", tplName, err)
	}

	return t, nil
}
