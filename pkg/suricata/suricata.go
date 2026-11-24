package suricata

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"github.com/ks2211/go-suricata/client"
	firewallv2 "github.com/metal-stack/firewall-controller-manager/api/v2"
	"github.com/metal-stack/firewall-controller/v2/pkg/systemd"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	suricataAfPacketService = "suricata.service"
	suricataNFQueueService  = "suricata-nfqueue.service"
	suricataUpdateService   = "suricata_update.service"
	eveboxAgentService      = "evebox-agent.service"

	eveboxAgentConfigPath = "/etc/evebox/agent.yaml"
	eveboxSocketDir       = "/run/evebox"
	eveboxSocketPath      = "/run/evebox/eve.sock"

	suricataUpdate = "suricata-update"
	suricatasc     = "suricatasc"

	// defaultSocket to communicate with suricata
	defaultSocket = "/run/suricata-command.socket"
)

type (
	Suricata struct {
		socket string
		log    logr.Logger
	}

	InterfaceStats map[string]InterFaceStat

	InterFaceStat struct {
		Drop             int
		InvalidChecksums int
		Pkts             int
	}
)

func New(log logr.Logger) *Suricata {
	return &Suricata{
		socket: defaultSocket,
		log:    log,
	}
}

func (s *Suricata) InterfaceStats(ctx context.Context) (InterfaceStats, error) {
	suricata, err := client.CreateSocket(s.socket)
	if err != nil {
		return nil, err
	}
	defer suricata.Close()

	ifaces, err := suricata.IFaceListCommand(ctx)
	if err != nil {
		return nil, err
	}
	result := InterfaceStats{}
	for _, iface := range ifaces.Ifaces {
		stat, err := suricata.IFaceStatCommand(ctx, client.IFaceStatRequest{IFace: iface})
		if err != nil {
			return nil, err
		}
		result[iface] = InterFaceStat{
			Drop:             stat.Drop,
			InvalidChecksums: stat.InvalidChecksums,
			Pkts:             stat.Pkts,
		}
	}

	return result, nil
}

func (s *Suricata) Status(ctx context.Context, c kclient.Client) (*firewallv2.SuricataStatus, error) {
	status := &firewallv2.SuricataStatus{
		Running:                    false,
		Uptime:                     metav1.Duration{},
		Version:                    "",
		AvailableDetectionRulesets: []string{},
		EnabledDetectionRulesets:   []string{},
		EveboxAgentRunning:         false,
		EveboxServerRunning:        false,
	}

	enabled, err := systemd.AnyUnitFileEnabled(ctx, suricataAfPacketService, suricataNFQueueService)
	if err != nil {
		return nil, fmt.Errorf("unable to figure out if service is running: %w", err)
	}

	if !enabled {
		return status, nil
	}

	querySuricata := func(command string) (json.RawMessage, error) {
		out, err := runCommand(ctx, suricatasc, s.socket, "-c", command)
		if err != nil {
			return nil, fmt.Errorf("unable to query suricata socket: %w", err)
		}

		var response struct {
			Return  string          `json:"return"`
			Message json.RawMessage `json:"message"`
		}

		if err := json.Unmarshal(out, &response); err != nil {
			return nil, fmt.Errorf("unable to parse suricata %s response: %w", command, err)
		}

		if response.Return != "OK" {
			return nil, fmt.Errorf("suricata command %s returned %q", command, response.Return)
		}

		return response.Message, nil
	}

	uptimeResponse, err := querySuricata("uptime")
	if err != nil {
		return nil, err
	}

	var uptimeSeconds int64
	if err := json.Unmarshal(uptimeResponse, &uptimeSeconds); err != nil {
		return nil, fmt.Errorf("unable to parse suricata uptime: %w", err)
	}
	status.Uptime = metav1.Duration{Duration: time.Duration(uptimeSeconds) * time.Second}
	status.Running = true

	versionResponse, err := querySuricata("version")
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(versionResponse, &status.Version); err != nil {
		return nil, fmt.Errorf("unable to parse suricata version: %w", err)
	}

	enabled, err = systemd.AnyUnitFileEnabled(ctx, eveboxAgentService)
	if err != nil {
		return nil, err
	}

	status.EveboxAgentRunning = enabled

	deploy := &appsv1.Deployment{
		Name:      "evebox",
		Namespace: firewallv2.FirewallShootNamespace,
	}
	err = c.Get(ctx, kclient.ObjectKeyFromObject(deploy), deploy)
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, err
	}

	if err == nil && deploy.Status.Replicas > 0 && deploy.Status.Replicas == deploy.Status.ReadyReplicas {
		status.EveboxServerRunning = true
	}

	status.AvailableDetectionRulesets, err = availableDetectionRulesets()
	if err != nil {
		return nil, err
	}

	status.EnabledDetectionRulesets, err = enabledDetectionRulesets()
	if err != nil {
		return nil, err
	}

	return status, nil
}
