package suricata

import (
	"context"

	firewallv2 "github.com/metal-stack/firewall-controller-manager/api/v2"
)

func (s *Suricata) Reconcile(ctx context.Context, f *firewallv2.Firewall) error {
	enabled := true

	if f.Spec.Suricata.Enabled != nil {
		enabled = *f.Spec.Suricata.Enabled
	}

	if !enabled {
		if err := s.deleteEveboxAgent(ctx); err != nil {
			return err
		}
		// disable service

		return nil
	}

	if f.Spec.Suricata.Evebox.Enabled {
		if err := s.deployEveboxAgent(ctx, &f.Spec.Suricata.Evebox); err != nil {
			return err
		}
	} else {
		if err := s.deleteEveboxAgent(ctx); err != nil {
			return err
		}
	}

	if err := s.reconcileListenMode(ctx, f.Spec.Suricata.ListenMode); err != nil {
		return nil
	}

	return nil
}

func (s *Suricata) deployEveboxAgent(ctx context.Context, box *firewallv2.Evebox) error {
	// configure and start evebox agent service on the firewall
	// evebox is already installed on the machine, systemd service is present, but no configuration exists

	return nil
}

func (s *Suricata) deleteEveboxAgent(ctx context.Context) error {
	return nil
}

func (s *Suricata) reconcileListenMode(ctx context.Context, mode *firewallv2.SuricataListenMode) error {
	// TODO
	return nil
}
