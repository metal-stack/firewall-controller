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

func (s *Suricata) ReconcileSuricata(kb netconf.KnowledgeBase, enableIDS bool) error {
	if enableIDS != s.enableIDS {
		configurator := netconf.FirewallConfigurator{
			CommonConfigurator: netconf.CommonConfigurator{
				Kb: kb,
			},
			EnableIDS: enableIDS,
		}
		configurator.ConfigureSuricata()

		if err := s.restart(); err != nil {
			return fmt.Errorf("failed to restart suricata: %w", err)
		}
		s.enableIDS = enableIDS
	}

	return nil
}

func (s *Suricata) restart() error {
	c := exec.Command(systemctlBin, "restart", suricataService)
	err := c.Run()
	if err != nil {
		return fmt.Errorf("could not reload suricata service, err: %w", err)
	}
	return nil
}
