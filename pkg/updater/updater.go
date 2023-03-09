package updater

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-logr/logr"
	firewallv2 "github.com/metal-stack/firewall-controller-manager/api/v2"
	"github.com/metal-stack/v"
	corev1 "k8s.io/api/core/v1"
)

const (
	binaryLocation = "/usr/local/bin/firewall-controller"
)

// UpdateToSpecVersion updates the firewall-controller binary to the version specified in the firewall spec.
func UpdateToSpecVersion(f firewallv2.Firewall, log logr.Logger, recorder func(eventtype, reason, message string)) error {
	if f.Spec.ControllerVersion == "" {
		return nil
	}

	if f.Spec.ControllerVersion == v.Version {
		log.Info("firewall-controller version is already in place", "version", v.Version)
		return nil
	}

	_, err := url.Parse(f.Spec.ControllerURL)
	if err != nil {
		return err
	}

	recorder(corev1.EventTypeNormal, "Self-Reconciliation", fmt.Sprintf("replacing firewall-controller version %s with version %s", v.Version, f.Spec.ControllerVersion))

	binaryReader, checksum, err := fetchBinaryAndChecksum(f.Spec.ControllerURL)
	if err != nil {
		return fmt.Errorf("could not download binary or checksum for firewall-controller version %s, err: %w", f.Spec.ControllerVersion, err)
	}

	err = replaceBinary(binaryReader, binaryLocation, checksum)
	if err != nil {
		return fmt.Errorf("could not replace firewall-controller with version %s, err: %w", f.Spec.ControllerVersion, err)
	}

	recorder(corev1.EventTypeNormal, "Self-Reconciliation", fmt.Sprintf("replaced firewall-controller version %s with version %s successfully", v.Version, f.Spec.ControllerVersion))

	// after a successful self-reconciliation of the firewall-controller binary we want to get restarted by exiting and letting systemd restart the process.
	os.Exit(0)
	return nil
}

func fetchBinaryAndChecksum(url string) (io.ReadCloser, string, error) {
	checksum, err := slurpFile(url + ".sha256")
	if err != nil {
		return nil, "", fmt.Errorf("could not slurp checksum file at %s, err: %w", url, err)
	}

	//nolint:gosec,noctx
	resp, err := http.Get(url)
	if err != nil {
		return nil, "", fmt.Errorf("could not download url %s, err: %w", url, err)
	}

	return resp.Body, checksum, nil
}

func replaceBinary(binaryReader io.ReadCloser, binaryPath, checksum string) error {
	filename, err := copyToTempFile(binaryReader, binaryPath)
	if err != nil {
		return err
	}

	err = validateChecksum(filename, checksum)
	if err != nil {
		return err
	}

	if err = os.Rename(filename, binaryPath); err != nil {
		return err
	}
	return nil
}

func copyToTempFile(binaryReader io.ReadCloser, filename string) (string, error) {
	file, err := os.CreateTemp(filepath.Dir(filename), filepath.Base(filename))
	if err != nil {
		return "", err
	}

	_, err = io.Copy(file, binaryReader)
	if err != nil {
		return "", err
	}
	defer binaryReader.Close()

	err = os.Chmod(file.Name(), 0755)
	if err != nil {
		return "", err
	}
	return file.Name(), nil
}

func validateChecksum(filename string, checksum string) error {
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(bytes)
	sum := string(hex.EncodeToString(hash[:]))
	if sum != checksum {
		return fmt.Errorf("checksum error")
	}
	return nil
}

func slurpFile(url string) (string, error) {
	//nolint:gosec,noctx
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return strings.Split(string(content), " ")[0], nil
}
