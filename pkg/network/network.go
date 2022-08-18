package network

import (
	"fmt"
	"os"
	"path/filepath"
	"text/template"

	"github.com/metal-stack/metal-go/api/models"
	"github.com/metal-stack/metal-networker/pkg/netconf"
	"go.uber.org/zap"

	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"

	"embed"
)

const (
	metalNetworkerConfig = "/etc/metal/install.yaml"
	frrConfig            = "/etc/frr/frr.conf"
)

//go:embed *.tpl
var templates embed.FS

// GetKnowledgeBase returns Knowledge Base instance filled with data only from install.yaml
// It could be useful for retrieving host IP, before controller has the access to the kube-api.
func GetKnowledgeBase() netconf.KnowledgeBase {
	zlog, _ := zap.NewProduction()
	return netconf.NewKnowledgeBase(MetalKnowledgeBase)
}

// GetUpdatedKnowledgeBase return Knowledge Base instance filled with data from the Firewall resource.
func GetUpdatedKnowledgeBase(f firewallv1.Firewall) netconf.KnowledgeBase {
	kb := GetKnowledgeBase()
	networkMap := map[string]firewallv1.FirewallNetwork{}
	for _, n := range f.Spec.FirewallNetworks {
		if n.Networktype == nil {
			continue
		}
		networkMap[*n.Networkid] = n
	}

	newNetworks := []*models.V1MachineNetwork{}
	for _, n := range kb.Networks {
		newNet := n
		newNet.Prefixes = networkMap[*n.Networkid].Prefixes
		newNetworks = append(newNetworks, newNet)
	}
	kb.Networks = newNetworks

	return kb
}

// ReconcileNetwork reconciles the network settings for a firewall
// Changes both the FRR-Configuration and Nftable rules when network prefixes or FRR template changes
func ReconcileNetwork(kb netconf.KnowledgeBase) (changed bool, err error) {
	tmpFile, err := tmpFile(frrConfig)
	if err != nil {
		return false, fmt.Errorf("error during network reconcilation %v: %w", tmpFile, err)
	}
	defer func() {
		os.Remove(tmpFile)
	}()

	a := netconf.NewFrrConfigApplier(netconf.Firewall, *kb, tmpFile)
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
