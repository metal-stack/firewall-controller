package controllers

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
	"github.com/go-logr/logr"
	firewallv2 "github.com/metal-stack/firewall-controller-manager/api/v2"
	firewallv1 "github.com/metal-stack/firewall-controller/v2/api/v1"
	"github.com/metal-stack/firewall-controller/v2/pkg/collector"
	"github.com/metal-stack/firewall-controller/v2/pkg/suricata"
	"github.com/metal-stack/v"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/yaml"
)

// FirewallMonitorReconciler reconciles a firewall monitor object
type FirewallMonitorReconciler struct {
	ShootClient client.Client

	Recorder record.EventRecorder
	Log      logr.Logger

	FirewallName string
	Namespace    string

	IDSEnabled bool
	Interval   time.Duration

	seedUpdated metav1.Time
}

func (r *FirewallMonitorReconciler) SeedUpdated() {
	r.seedUpdated = metav1.NewTime(time.Now())
}

// SetupWithManager configures this controller to watch for the CRDs in a specific namespace
func (r *FirewallMonitorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Interval == 0 {
		r.Interval = reconciliationInterval
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&firewallv2.FirewallMonitor{}).
		WithEventFilter(predicate.Funcs{
			UpdateFunc: func(ce event.UpdateEvent) bool {
				return false
			},
			DeleteFunc: func(de event.DeleteEvent) bool {
				return false
			},
		}).
		Complete(r)
}

// Reconcile updates the firewall monitor.
func (r *FirewallMonitorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	c := collector.NewNFTablesCollector(&r.Log)
	ruleStats := c.CollectRuleStats()

	deviceStats, err := c.CollectDeviceStats()
	if err != nil {
		return ctrl.Result{}, err
	}

	idsStats := firewallv2.IDSStatsByDevice{}
	if r.IDSEnabled {
		s := suricata.New()
		ss, err := s.InterfaceStats(ctx)
		if err != nil {
			return ctrl.Result{}, err
		}
		for iface, stat := range *ss {
			idsStats[iface] = firewallv2.InterfaceStat{
				Drop:             stat.Drop,
				InvalidChecksums: stat.InvalidChecksums,
				Packets:          stat.Pkts,
			}
		}
	}

	suricataStatus, err := r.suricataStatus(ctx)
	if err != nil {
		r.Log.Error(err, "unable to figure out suricata status")
	}

	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		mon := &firewallv2.FirewallMonitor{
			Name:      r.FirewallName,
			Namespace: firewallv1.ClusterwideNetworkPolicyNamespace,
		}

		if err := r.ShootClient.Get(ctx, client.ObjectKeyFromObject(mon), mon); err != nil {
			if apierrors.IsNotFound(err) {
				r.Log.Info("resource no longer exists")
				return nil
			}

			return fmt.Errorf("error retrieving resource: %w", err)
		}

		if !mon.GetDeletionTimestamp().IsZero() {
			return nil
		}

		now := time.Now()

		mon.ControllerStatus = &firewallv2.ControllerStatus{
			Message: fmt.Sprintf("updated firewall monitor resource at %s", now.String()),
			FirewallStats: &firewallv2.FirewallStats{
				RuleStats:   ruleStats,
				DeviceStats: deviceStats,
				IDSStats:    idsStats,
			},
			ControllerVersion:       v.Version,
			NftablesExporterVersion: "", // TODO
			Updated:                 metav1.NewTime(now),
			Distance:                0,
			DistanceSupported:       false,
		}

		if suricataStatus != nil {
			mon.ControllerStatus.Suricata = *suricataStatus
		}

		if !r.seedUpdated.IsZero() {
			mon.ControllerStatus.SeedUpdated = r.seedUpdated
		}

		err := r.ShootClient.Update(ctx, mon)
		if err != nil {
			return err
		}

		r.Log.Info(fmt.Sprintf("firewall monitor successfully updated, requeuing in %s", r.Interval.String()), "name", mon.Name, "namespace", mon.Namespace)

		return nil
	})
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("unable to update firewall monitor status, err: %w", err)
	}

	return ctrl.Result{
		// TODO: the interval can change over the lifetime of a firewall resource
		// in case the interval has changed nothing happens at the moment
		RequeueAfter: r.Interval,
	}, nil
}

func (r *FirewallMonitorReconciler) suricataStatus(ctx context.Context) (*firewallv2.SuricataStatus, error) {
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
		suricatasc     = "suricatasc"
		suricataSocket = "/run/suricata-command.socket"
	)

	s := &firewallv2.SuricataStatus{
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
		return s, nil
	}

	querySuricata := func(command string) (json.RawMessage, error) {
		cmd := exec.CommandContext(ctx, suricatasc, suricataSocket, "-c", command)
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
	s.Uptime = metav1.Duration{Duration: time.Duration(uptimeSeconds) * time.Second}
	s.Running = true

	versionResponse, err := querySuricata("version")
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(versionResponse, &s.Version); err != nil {
		return nil, fmt.Errorf("unable to parse suricata version: %w", err)
	}

	enabled, err = isServiceEnabled("evebox-agent.service")
	if err != nil {
		return nil, err
	}

	s.EveboxAgentRunning = enabled

	deploy := &appsv1.Deployment{
		Name:      "evebox",
		Namespace: firewallv2.FirewallShootNamespace,
	}
	err = r.ShootClient.Get(ctx, client.ObjectKeyFromObject(deploy), deploy)
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, err
	}

	if err == nil && deploy.Status.Replicas > 0 && deploy.Status.Replicas == deploy.Status.ReadyReplicas {
		s.EveboxServerRunning = true
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

			s.AvailableDetectionRulesets = append(s.AvailableDetectionRulesets, name)
		}
		sort.Strings(s.AvailableDetectionRulesets)
	case errors.Is(err, fs.ErrNotExist):
		r.Log.Info("suricata update source index not found, skipping available detection rule sets", "path", path)
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
			s.EnabledDetectionRulesets = append(s.EnabledDetectionRulesets, source.Source)
		}

		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("unable to read enabled suricata sources: %w", err)
	}
	sort.Strings(s.EnabledDetectionRulesets)

	return s, nil
}
