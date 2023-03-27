package updater

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"

	firewallv2 "github.com/metal-stack/firewall-controller-manager/api/v2"
	corev1 "k8s.io/api/core/v1"
)

const (
	nftablesVersionFile = "/etc/metal/nftables-exporter.version"
)

// updateNFTablesExporter updates the nftables-exporter binary to the version specified in the firewall spec.
func (u *Updater) updateNFTablesExporter(ctx context.Context, f *firewallv2.Firewall) error {
	targetVersion := f.Spec.NftablesExporterVersion
	if targetVersion == "" {
		return nil
	}
	nftablesBinary, err := exec.LookPath("nftables-exporter")
	if err != nil {
		u.log.Info("nftables-exporter binary not found, ignoring", "err", err)
		return nil
	}

	v, err := os.ReadFile(nftablesVersionFile)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	version := string(v)
	if targetVersion == version {
		u.log.Info("nftables-exporter version is already in place", "version", version)
		return nil
	}

	_, err = url.Parse(f.Spec.NftablesExporterURL)
	if err != nil {
		u.log.Error(err, "error parsing nftables-exporter url")
		return err
	}

	u.recorderCallback(f, corev1.EventTypeNormal, "nftables-exporter", fmt.Sprintf("replacing nftables-exporter version %s with version %s", version, targetVersion))

	binaryReader, checksum, err := fetchBinaryAndChecksum(f.Spec.NftablesExporterURL)
	if err != nil {
		u.log.Error(err, "error fetching nftables-exporter binary and checksum")
		return fmt.Errorf("could not download binary or checksum for nftables-exporter version %s, err: %w", targetVersion, err)
	}

	err = replaceBinary(binaryReader, nftablesBinary, checksum)
	if err != nil {
		u.log.Error(err, "error replacing nftables-exporter binary")
		return fmt.Errorf("could not replace nftables-exporter with version %s, err: %w", targetVersion, err)
	}

	err = os.WriteFile(nftablesVersionFile, []byte(targetVersion), 0600)
	if err != nil {
		u.log.Error(err, "error writing nftables-exporter version file")
		return err
	}

	err = restart(ctx, "nftables-exporter.service")
	if err != nil {
		u.log.Error(err, "error restarting nftables-exporter")
		return err
	}

	u.log.Info("successfully restarted nftables-exporter")

	u.recorderCallback(f, corev1.EventTypeNormal, "nftables-exporter", fmt.Sprintf("replaced nftables-exporter version %s with version %s successfully", version, targetVersion))

	return nil
}
