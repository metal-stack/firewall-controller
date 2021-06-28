package network

import (
	"github.com/metal-stack/metal-networker/pkg/netconf"
)

func ReconcileSuricata(kb netconf.KnowledgeBase, enableIDS bool) {
	configurator := netconf.FirewallConfigurator{
		CommonConfigurator: netconf.CommonConfigurator{
			Kb: kb,
		},
		EnableIDS: enableIDS,
	}
	configurator.ConfigureSuricata()
}
