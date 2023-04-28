package updater

import (
	"fmt"
	"net/url"
	"os"

	firewallv2 "github.com/metal-stack/firewall-controller-manager/api/v2"
	"github.com/metal-stack/v"
	corev1 "k8s.io/api/core/v1"
)

const (
	binaryLocation = "/usr/local/bin/firewall-controller"
)

// updateFirewallController updates the firewall-controller binary to the version specified in the firewall spec.
func (u *Updater) updateFirewallController(f *firewallv2.Firewall) error {
	if f.Spec.ControllerVersion == "" {
		return nil
	}

	if f.Spec.ControllerVersion == v.Version {
		u.log.Info("firewall-controller version is already in place", "version", v.Version)
		return nil
	}

	_, err := url.Parse(f.Spec.ControllerURL)
	if err != nil {
		return err
	}

	u.recorderCallback(f, corev1.EventTypeNormal, "Self-Reconciliation", fmt.Sprintf("replacing firewall-controller version %s with version %s", v.Version, f.Spec.ControllerVersion))

	binaryReader, checksum, err := fetchBinaryAndChecksum(f.Spec.ControllerURL)
	if err != nil {
		return fmt.Errorf("could not download binary or checksum for firewall-controller version %s, err: %w", f.Spec.ControllerVersion, err)
	}

	err = replaceBinary(binaryReader, binaryLocation, checksum)
	if err != nil {
		return fmt.Errorf("could not replace firewall-controller with version %s, err: %w", f.Spec.ControllerVersion, err)
	}

	u.recorderCallback(f, corev1.EventTypeNormal, "Self-Reconciliation", fmt.Sprintf("replaced firewall-controller version %s with version %s successfully", v.Version, f.Spec.ControllerVersion))

	// after a successful self-reconciliation of the firewall-controller binary we want to get restarted by exiting and letting systemd restart the process.
	os.Exit(0)
	return nil
}
