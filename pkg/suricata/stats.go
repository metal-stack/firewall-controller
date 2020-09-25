package suricata

import (
	"context"

	"github.com/ks2211/go-suricata/client"
)

// defaultSocket to communicate with suricata
const defaultSocket = "/run/suricata-command.socket"

type Suricata struct {
	socket string
}

type InterfaceStats map[string]InterFaceStat

type InterFaceStat struct {
	Drop             int
	InvalidChecksums int
	Pkts             int
}

func New() Suricata {
	return Suricata{socket: defaultSocket}
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
