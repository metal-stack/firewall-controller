package updater

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-logr/logr"
	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
	"github.com/metal-stack/v"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/record"
)

const (
	binaryLocation = "/usr/local/bin/firewall-controller"
)

// UpdateToSpecVersion updates the firewall-controller binary to the version specified in the firewall spec.
func UpdateToSpecVersion(f firewallv1.Firewall, log logr.Logger, recorder record.EventRecorder) error {
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

	recorder.Eventf(&f, corev1.EventTypeNormal, "Self-Reconcilation", "replacing firewall-controller version %s with version %s", v.Version, f.Spec.ControllerVersion)

	binaryReader, checksum, err := FetchBinaryAndChecksum(f.Spec.ControllerURL)
	if err != nil {
		return fmt.Errorf("could not download binary or checksum for firewall-controller version %s, err: %w", f.Spec.ControllerVersion, err)
	}

	err = replaceBinary(binaryReader, checksum)
	if err != nil {
		return fmt.Errorf("could not replace firewall-controller with version %s, err: %w", f.Spec.ControllerVersion, err)
	}

	recorder.Eventf(&f, corev1.EventTypeNormal, "Self-Reconcilation", "replaced firewall-controller version %s with version %s successfully", v.Version, f.Spec.ControllerVersion)

	// after a successful self-reconcilation of the firewall-controller binary we want to get restarted by exiting and letting systemd restart the process.
	os.Exit(0)
	return nil
}

func FetchBinaryAndChecksum(url string) (io.ReadCloser, string, error) {
	checksum, err := slurpFile(url + ".sha256")
	if err != nil {
		return nil, "", fmt.Errorf("could not slurp checksum file at %s, err: %w", url, err)
	}

	resp, err := http.Get(url)
	if err != nil {
		return nil, "", fmt.Errorf("could not download url %s, err: %w", url, err)
	}

	return resp.Body, checksum, nil
}

func replaceBinary(binaryReader io.ReadCloser, checksum string) error {
	filename, err := copyToTempFile(binaryReader, binaryLocation)
	if err != nil {
		return err
	}

	err = validateChecksum(filename, checksum)
	if err != nil {
		return err
	}

	if err = os.Rename(filename, binaryLocation); err != nil {
		return err
	}
	return nil
}

func copyToTempFile(binaryReader io.ReadCloser, filename string) (string, error) {
	file, err := ioutil.TempFile(filepath.Dir(filename), filepath.Base(filename))
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
	bytes, err := ioutil.ReadFile(filename)
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
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return strings.Split(string(content), " ")[0], nil
}
