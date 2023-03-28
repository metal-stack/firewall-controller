package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/coreos/go-systemd/v22/dbus"
)

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
