package nftables

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/go-logr/logr"
	firewallv2 "github.com/metal-stack/firewall-controller-manager/api/v2"
	osnet "github.com/metal-stack/os-installer/pkg/network"
	renderer "github.com/metal-stack/os-installer/pkg/template-renderer"
)

const (
	suricataNFTablesPath     = "/etc/nftables/suricata.nft"
	suricataNFTablesTemplate = `table inet suricata {
    chain forward {
        type filter hook forward priority -10; policy accept;
        iifname "{{ .Interface }}" queue num 0 bypass comment "suricata nfqueue incoming"
        oifname "{{ .Interface }}" queue num 0 bypass comment "suricata nfqueue outgoing"
    }
}
`
)

type Suricata struct {
	network *osnet.Network
	log     logr.Logger
}

func NewSuricata(network *osnet.Network, log logr.Logger) *Suricata {
	return &Suricata{
		network: network,
		log:     log,
	}
}

func (s *Suricata) Reconcile(ctx context.Context, mode *firewallv2.SuricataListenMode) error {
	enabled := mode != nil && *mode == firewallv2.SuricataListenModeNfqueue

	if !enabled {
		if err := os.Remove(suricataNFTablesPath); err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return fmt.Errorf("unable to remove suricata nftables rules: %w", err)
		}

		return reloadNFTablesService(ctx)
	}

	if s.network == nil {
		return errors.New("network is required for suricata nfqueue mode")
	}

	externalInterface, err := s.network.GetDefaultRouteNetworkVlan()
	if err != nil {
		return fmt.Errorf("unable to determine external interface for suricata nfqueue mode: %w", err)
	}

	r, err := renderer.New(&renderer.Config{
		Log:            slog.New(logr.ToSlogHandler(s.log)),
		TemplateString: suricataNFTablesTemplate,
		Data: map[string]string{
			"Interface": externalInterface,
		},
		Validate: validateNFTablesFile,
	})
	if err != nil {
		return fmt.Errorf("unable to create suricata nftables renderer: %w", err)
	}

	changed, err := r.Render(ctx, suricataNFTablesPath)
	if err != nil {
		return fmt.Errorf("unable to render suricata nftables rules: %w", err)
	}
	if !changed {
		return nil
	}

	return reloadNFTablesService(ctx)
}
