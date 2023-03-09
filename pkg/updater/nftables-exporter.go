package updater

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"

	"github.com/coreos/go-systemd/v22/dbus"

	"github.com/go-logr/logr"
	firewallv2 "github.com/metal-stack/firewall-controller-manager/api/v2"
	corev1 "k8s.io/api/core/v1"
)

const (
	nftablesVersionFile = "/etc/metal/nftables-exporter.version"
)

// UpdateNFTablesExporterToSpecVersion updates the nftables-exporter binary to the version specified in the firewall spec.
func UpdateNFTablesExporterToSpecVersion(ctx context.Context, f firewallv2.Firewall, log logr.Logger, recorder func(eventtype, reason, message string)) error {
	targetVersion := f.Spec.NftablesExporterVersion
	if targetVersion == "" {
		return nil
	}
	nftablesBinary, err := exec.LookPath("nftables-exporter")
	if err != nil {
		log.Info("nftables-exporter binary not found, ignoring", "err", err)
		return nil
	}

	v, err := os.ReadFile(nftablesVersionFile)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	version := string(v)
	if targetVersion == version {
		log.Info("nftables-exporter version is already in place", "version", version)
		return nil
	}

	_, err = url.Parse(f.Spec.NftablesExporterURL)
	if err != nil {
		return err
	}

	recorder(corev1.EventTypeNormal, "nftables-exporter", fmt.Sprintf("replacing nftables-exporter version %s with version %s", version, targetVersion))

	binaryReader, checksum, err := fetchBinaryAndChecksum(f.Spec.NftablesExporterURL)
	if err != nil {
		return fmt.Errorf("could not download binary or checksum for nftables-exporter version %s, err: %w", targetVersion, err)
	}

	err = replaceBinary(binaryReader, nftablesBinary, checksum)
	if err != nil {
		return fmt.Errorf("could not replace nftables-exporter with version %s, err: %w", targetVersion, err)
	}

	err = os.WriteFile(nftablesVersionFile, []byte(targetVersion), 0600)
	if err != nil {
		return err
	}

	err = restart(ctx, "nftables-exporter")
	if err != nil {
		return err
	}

	recorder(corev1.EventTypeNormal, "nftables-exporter", fmt.Sprintf("replaced nftables-exporter version %s with version %s successfully", version, targetVersion))

	return nil
}

const done = "done"

func restart(ctx context.Context, unitName string) error {
	dbc, err := dbus.NewWithContext(ctx)
	if err != nil {
		return fmt.Errorf("unable to connect to dbus: %w", err)
	}
	defer dbc.Close()

	c := make(chan string)
	_, err = dbc.RestartUnitContext(ctx, unitName, "replace", c)

	if err != nil {
		return err
	}

	job := <-c
	if job != done {
		return fmt.Errorf("restart failed %s", job)
	}

	return nil
}
