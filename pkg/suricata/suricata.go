package suricata

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/coreos/go-systemd/v22/dbus"
	"github.com/ks2211/go-suricata/client"
	firewallv2 "github.com/metal-stack/firewall-controller-manager/api/v2"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

// defaultSocket to communicate with suricata
const defaultSocket = "/run/suricata-command.socket"

type (
	Suricata struct {
		socket string
	}

	InterfaceStats map[string]InterFaceStat

	InterFaceStat struct {
		Drop             int
		InvalidChecksums int
		Pkts             int
	}
)

func New() *Suricata {
	return &Suricata{socket: defaultSocket}
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
	isServiceEnabled := func(name string) (bool, error) {
		dbc, err := dbus.NewSystemConnectionContext(ctx)
		if err != nil {
			return false, fmt.Errorf("unable to connect to dbus: %w", err)
		}
		defer dbc.Close()

		units, err := dbc.ListUnitFilesContext(ctx)
		if err != nil {
			return false, fmt.Errorf("failed to list unit files: %w", err)
		}

		for _, unit := range units {
			if path.Base(unit.Path) != name {
				continue
			}

			return unit.Type == "enabled" || unit.Type == "enabled-runtime", nil
		}

		return false, nil
	}

	const (
		suricatasc = "suricatasc"
	)

	status := &firewallv2.SuricataStatus{
		Running:                    false,
		Uptime:                     metav1.Duration{},
		Version:                    "",
		AvailableDetectionRulesets: []string{},
		EnabledDetectionRulesets:   []string{},
		EveboxAgentRunning:         false,
		EveboxServerRunning:        false,
	}

	enabled, err := isServiceEnabled("suricata.service")
	if err != nil {
		return nil, fmt.Errorf("unable to figure out if service is running: %w", err)
	}

	if !enabled {
		return status, nil
	}

	querySuricata := func(command string) (json.RawMessage, error) {
		cmd := exec.CommandContext(ctx, suricatasc, s.socket, "-c", command)
		out, err := cmd.Output()
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

	enabled, err = isServiceEnabled("evebox-agent.service")
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

	const stateDir = "/var/lib/suricata/"

	path := filepath.Join(stateDir, "update", "cache", "index.yaml")
	content, err := os.ReadFile(path)
	switch {
	case err == nil:
		var index struct {
			Sources map[string]map[string]any `json:"sources"`
		}
		if err := yaml.Unmarshal(content, &index); err != nil {
			return nil, fmt.Errorf("unable to parse suricata update source index: %w", err)
		}

		for name, source := range index.Sources {
			if _, ok := source["deprecated"]; ok {
				continue
			}
			if _, ok := source["obsolete"]; ok {
				continue
			}

			status.AvailableDetectionRulesets = append(status.AvailableDetectionRulesets, name)
		}
		sort.Strings(status.AvailableDetectionRulesets)
	case errors.Is(err, fs.ErrNotExist):
		// noop
	default:
		return nil, fmt.Errorf("unable to read suricata update source index: %w", err)
	}

	err = filepath.WalkDir(filepath.Join(stateDir, "update", "sources"), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".yaml") {
			return nil
		}

		content, err := os.ReadFile(p)
		if err != nil {
			return err
		}

		var source struct {
			Source string `json:"source"`
		}
		if err := yaml.Unmarshal(content, &source); err != nil {
			return fmt.Errorf("unable to parse suricata source config %s: %w", p, err)
		}
		if source.Source != "" {
			status.EnabledDetectionRulesets = append(status.EnabledDetectionRulesets, source.Source)
		}

		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("unable to read enabled suricata sources: %w", err)
	}
	sort.Strings(status.EnabledDetectionRulesets)

	return status, nil
}
