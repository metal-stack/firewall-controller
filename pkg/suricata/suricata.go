package suricata

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/metal-stack/metal-networker/pkg/netconf"

	"github.com/ks2211/go-suricata/client"
)

const (
	suricataService = "suricata.service"
	systemctlBin    = "/bin/systemctl"

	// defaultSocket to communicate with suricata
	defaultSocket = "/run/suricata-command.socket"
)

type Suricata struct {
	socket    string
	enableIDS bool
	enableIPS bool
}

type InterfaceStats map[string]InterFaceStat

type InterFaceStat struct {
	Drop             int
	InvalidChecksums int
	Pkts             int
}

func New() *Suricata {
	return &Suricata{
		socket: defaultSocket,
	}
}

func (s *Suricata) InterfaceStats() (*InterfaceStats, error) {
	suricata, err := client.CreateSocket(s.socket)
	if err != nil {
		return nil, err
	}
	defer suricata.Close()

	ifaces, err := suricata.IFaceListCommand(context.Background())
	if err != nil {
		return nil, err
	}
	result := InterfaceStats{}
	for _, iface := range ifaces.Ifaces {
		stat, err := suricata.IFaceStatCommand(context.Background(), client.IFaceStatRequest{IFace: iface})
		if err != nil {
			return nil, err
		}
		result[iface] = InterFaceStat{
			Drop:             stat.Drop,
			InvalidChecksums: stat.InvalidChecksums,
			Pkts:             stat.Pkts,
		}
	}

	return &result, nil
}

func (s *Suricata) ReconcileSuricata(kb netconf.KnowledgeBase, enableIDS, enableIPS bool) error {
	// If IPS is enabled, IDS also should be enabled
	// But it matters only internally for imlementation,
	// user can specify only enableIPS without enableIDS
	if enableIPS {
		enableIDS = true
	}

	if enableIDS != s.enableIDS || enableIPS != s.enableIPS {
		configurator := netconf.FirewallConfigurator{
			CommonConfigurator: netconf.CommonConfigurator{
				Kb: kb,
			},
			EnableIDS: enableIDS,
			EnableIPS: enableIPS,
		}
		configurator.ConfigureSuricata()

		s.enableIDS = enableIDS
		s.enableIPS = enableIPS

		if err := s.restart(); err != nil {
			return fmt.Errorf("failed to restart suricata: %w", err)
		}
	}

	return nil
}

func (s *Suricata) restart() error {
	c := exec.Command(systemctlBin, "daemon-reload", suricataService)
	if err := c.Run(); err != nil {
		return fmt.Errorf("could not reload suricata daemon, err: %w", err)
	}

	c = exec.Command(systemctlBin, "restart", suricataService)
	if err := c.Run(); err != nil {
		return fmt.Errorf("could not reload suricata service, err: %w", err)
	}
	return nil
}
