package suricata

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/go-logr/logr"
	firewallv2 "github.com/metal-stack/firewall-controller-manager/api/v2"
	"github.com/metal-stack/firewall-controller/v2/pkg/nftables"
	"github.com/metal-stack/firewall-controller/v2/pkg/systemd"
	osnet "github.com/metal-stack/os-installer/pkg/network"
	renderer "github.com/metal-stack/os-installer/pkg/template-renderer"
)

const eveboxAgentConfigTemplate = `server:
  url: {{ .ServerURL | quote }}
{{- if .Key }}
  key: {{ .Key | quote }}
{{- end }}
input:
  sockets:
    - path: {{ .SocketPath | quote }}
      type: unix_stream
`

type eveboxAgentTemplateData struct {
	ServerURL  string
	Key        string `json:"-"`
	SocketPath string
}

func (s *Suricata) Reconcile(ctx context.Context, log logr.Logger, f *firewallv2.Firewall, network *osnet.Network) error {
	enabled := true

	if f.Spec.Suricata.Enabled != nil {
		enabled = *f.Spec.Suricata.Enabled
	}

	if !enabled {
		log.Info("disabling suricata")

		if err := s.deleteEveboxAgent(ctx); err != nil {
			return err
		}

		if err := systemd.DisableAndStop(ctx, suricataAfPacketService); err != nil {
			return fmt.Errorf("unable to disable suricata service: %w", err)
		}
		if err := systemd.DisableAndStop(ctx, suricataNFQueueService); err != nil {
			return fmt.Errorf("unable to disable suricata nfqueue service: %w", err)
		}
		if err := nftables.NewSuricata(network, s.log).Reconcile(ctx, nil); err != nil {
			return err
		}

		return nil
	}

	log.Info("enabling suricata", "listen-mode", f.Spec.Suricata.ListenMode, "evebox", f.Spec.Suricata.Evebox.Enabled, "evebox-server-url", f.Spec.Suricata.Evebox.ServerURL)

	if f.Spec.Suricata.Evebox.Enabled {
		if err := s.deployEveboxAgent(ctx, &f.Spec.Suricata.Evebox); err != nil {
			return err
		}

		log.Info("evebox agent deployed")
	} else {
		if err := s.deleteEveboxAgent(ctx); err != nil {
			return err
		}

		log.Info("evebox agent deleted")
	}

	if err := nftables.NewSuricata(network, s.log).Reconcile(ctx, f.Spec.Suricata.ListenMode); err != nil {
		return err
	}

	if err := s.reconcileListenMode(ctx, f.Spec.Suricata.ListenMode); err != nil {
		return err
	}

	suricataService, _, err := suricataUnits(f.Spec.Suricata.ListenMode)
	if err != nil {
		return err
	}

	rulesetsChanged, err := s.reconcileDetectionRulesets(ctx, f.Spec.Suricata.DetectionRulesets)
	if err != nil {
		return err
	}

	dropRulesChanged, err := reconcileDropRules(f.Spec.Suricata.DropRules)
	if err != nil {
		return err
	}

	if !rulesetsChanged && !dropRulesChanged {
		return nil
	}

	log.Info("suricata rule configuration changed, updating rules", "detection-rulesets-changed", rulesetsChanged, "drop-rules-changed", dropRulesChanged)

	if err := systemd.Start(ctx, suricataUpdateService); err != nil {
		return fmt.Errorf("unable to update suricata rules: %w", err)
	}

	if err := systemd.Reload(ctx, suricataService); err != nil {
		return fmt.Errorf("unable to reload suricata with updated rules: %w", err)
	}

	return nil
}

func (s *Suricata) deployEveboxAgent(ctx context.Context, box *firewallv2.Evebox) error {
	if box.ServerURL == "" {
		return errors.New("evebox server URL must not be empty")
	}

	// TlsEnabled, Certificate and CertificateKey are currently not used because
	// the EveBox agent does not support client certificates. TLS is selected by
	// the scheme of the server URL.
	if err := os.MkdirAll(filepath.Dir(eveboxAgentConfigPath), 0755); err != nil {
		return fmt.Errorf("unable to create evebox config directory: %w", err)
	}
	if err := os.MkdirAll(eveboxSocketDir, 0755); err != nil {
		return fmt.Errorf("unable to create evebox socket directory: %w", err)
	}

	r, err := renderer.New(&renderer.Config{
		Log:            slog.New(logr.ToSlogHandler(s.log)),
		TemplateString: eveboxAgentConfigTemplate,
		Data: eveboxAgentTemplateData{
			ServerURL:  box.ServerURL,
			Key:        box.Key,
			SocketPath: eveboxSocketPath,
		},
	})
	if err != nil {
		return fmt.Errorf("unable to create evebox agent config renderer: %w", err)
	}

	changed, err := r.Render(ctx, eveboxAgentConfigPath)
	if err != nil {
		return fmt.Errorf("unable to render evebox agent config: %w", err)
	}

	if err := os.Chmod(eveboxAgentConfigPath, 0600); err != nil {
		return fmt.Errorf("unable to restrict evebox agent config permissions: %w", err)
	}

	if changed {
		if err := systemd.EnableAndRestart(ctx, eveboxAgentService); err != nil {
			return fmt.Errorf("unable to enable and restart evebox agent service: %w", err)
		}
	} else {
		if err := systemd.EnableAndStart(ctx, eveboxAgentService); err != nil {
			return fmt.Errorf("unable to enable and start evebox agent service: %w", err)
		}
	}

	return nil
}

func (s *Suricata) deleteEveboxAgent(ctx context.Context) error {
	if err := systemd.DisableAndStop(ctx, eveboxAgentService); err != nil {
		return fmt.Errorf("unable to disable evebox agent service: %w", err)
	}

	if err := os.Remove(eveboxAgentConfigPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("unable to remove evebox agent config: %w", err)
	}

	return nil
}

func (s *Suricata) reconcileListenMode(ctx context.Context, mode *firewallv2.SuricataListenMode) error {
	desiredService, otherService, err := suricataUnits(mode)
	if err != nil {
		return err
	}

	if err := systemd.DisableAndStop(ctx, otherService); err != nil {
		return fmt.Errorf("unable to disable suricata service %s: %w", otherService, err)
	}

	if err := systemd.EnableAndStart(ctx, desiredService); err != nil {
		return fmt.Errorf("unable to enable suricata service %s: %w", desiredService, err)
	}

	return nil
}

func suricataUnits(mode *firewallv2.SuricataListenMode) (desired string, other string, err error) {
	listenMode := firewallv2.SuricataListenModeAfPacket
	if mode != nil {
		listenMode = *mode
	}

	switch listenMode {
	case firewallv2.SuricataListenModeAfPacket:
		return suricataAfPacketService, suricataNFQueueService, nil
	case firewallv2.SuricataListenModeNfqueue:
		return suricataNFQueueService, suricataAfPacketService, nil
	default:
		return "", "", fmt.Errorf("unsupported suricata listen mode %q", listenMode)
	}
}

// reconcileDetectionRulesets enables the desired suricata-update sources and disables all others.
// It returns true if the enabled sources were changed and the rules need to be updated.
func (s *Suricata) reconcileDetectionRulesets(ctx context.Context, rulesets []string) (bool, error) {
	desired := []string{defaultDetectionRule}
	if len(rulesets) > 0 {
		desired = uniqueSorted(rulesets)
	}

	enabled, err := enabledDetectionRulesets()
	if err != nil {
		return false, err
	}

	if slices.Equal(desired, enabled) {
		return false, nil
	}

	for _, ruleset := range desired {
		if slices.Contains(enabled, ruleset) {
			continue
		}

		if _, err := runCommand(ctx, suricataUpdate, "enable-source", ruleset); err != nil {
			return false, fmt.Errorf("unable to enable suricata detection ruleset %q: %w", ruleset, err)
		}
	}

	// Enabling a source can implicitly enable the default source. Re-read the
	// enabled sources and disable everything that is not desired.
	enabled, err = enabledDetectionRulesets()
	if err != nil {
		return false, err
	}

	for _, ruleset := range enabled {
		if slices.Contains(desired, ruleset) {
			continue
		}

		if _, err := runCommand(ctx, suricataUpdate, "disable-source", ruleset); err != nil {
			return false, fmt.Errorf("unable to disable suricata detection ruleset %q: %w", ruleset, err)
		}
	}

	return true, nil
}

// reconcileDropRules writes the drop.conf for suricata-update, which converts the matching rules from alert to drop.
// It returns true if the file was changed and the rules need to be updated.
func reconcileDropRules(rules []string) (bool, error) {
	return reconcileDropRulesFile(suricataDropConfPath, rules)
}

func reconcileDropRulesFile(path string, rules []string) (bool, error) {
	desired := uniqueSorted(rules)

	for _, rule := range desired {
		if strings.ContainsAny(rule, "\r\n") {
			return false, fmt.Errorf("suricata drop rule %q must not contain line breaks", rule)
		}
		if strings.HasPrefix(rule, "#") {
			return false, fmt.Errorf("suricata drop rule %q must not start with a comment character", rule)
		}
	}

	current, err := os.ReadFile(path)
	exists := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, fmt.Errorf("unable to read suricata drop config: %w", err)
	}

	if len(desired) == 0 {
		if !exists {
			return false, nil
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return false, fmt.Errorf("unable to remove suricata drop config: %w", err)
		}
		return true, nil
	}

	content := []byte(dropConfHeader + strings.Join(desired, "\n") + "\n")

	if exists && bytes.Equal(current, content) {
		return false, nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return false, fmt.Errorf("unable to create suricata config directory: %w", err)
	}

	if err := os.WriteFile(path, content, 0644); err != nil { // nolint:gosec
		return false, fmt.Errorf("unable to write suricata drop config: %w", err)
	}

	return true, nil
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			return nil, fmt.Errorf("%s %s failed: %w", name, strings.Join(args, " "), err)
		}

		return nil, fmt.Errorf("%s %s failed: %w: %s", name, strings.Join(args, " "), err, message)
	}

	return out, nil
}
