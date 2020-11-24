package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/go-logr/logr"
	"github.com/google/go-github/github"
	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
	"github.com/metal-stack/v"
)

const (
	gitHubOwner    = "metal-stack"
	gitHubRepo     = "firewall-controller"
	gitHubArtifact = "firewall-controller"
	binaryLocation = "/usr/local/bin/firewall-controller"
)

// UpdateToSpecVersion updates the firewall-controller binary to the version specified in the firewall spec.
func UpdateToSpecVersion(f firewallv1.Firewall, log logr.Logger) error {
	if f.Spec.ControllerVersion == "" {
		return nil
	}

	if f.Spec.ControllerVersion == v.Version {
		log.Info("firewall-controller version %s is already in place", v.Version)
		return nil
	}

	log.Info("replacing firewall-controller version %s with version %s", v.Version, f.Spec.ControllerVersion)
	asset, err := determineGithubAsset(f.Spec.ControllerVersion)
	if err != nil {
		return err
	}

	binaryReader, checksum, err := fetchGithubAssetAndChecksum(asset)
	if err != nil {
		return fmt.Errorf("could not fetch github asset and checksum for firewall-controller version %s, err: %w", f.Spec.ControllerVersion, err)
	}

	err = replaceBinary(binaryReader, checksum)
	if err != nil {
		return fmt.Errorf("could not replace firewall-controller with version %s, err: %w", f.Spec.ControllerVersion, err)
	}

	log.Info("replaced firewall-controller version %s with version %s - triggering restart of firewall-controller", v.Version, f.Spec.ControllerVersion)

	os.Exit(0)
	return nil
}

func determineGithubAsset(githubTag string) (*github.ReleaseAsset, error) {
	client := github.NewClient(nil)
	releases, _, err := client.Repositories.ListReleases(context.Background(), gitHubOwner, gitHubRepo, &github.ListOptions{})
	if err != nil {
		panic(err)
	}

	var rel *github.RepositoryRelease
	for _, r := range releases {
		if r.TagName != nil && *r.TagName == githubTag {
			rel = r
			break
		}
	}

	var asset *github.ReleaseAsset
	for _, ra := range rel.Assets {
		if ra.GetName() == gitHubArtifact {
			asset = &ra
			break
		}
	}

	if asset == nil {
		return nil, fmt.Errorf("could not find artifact %s in github release with tag %s", gitHubArtifact, githubTag)
	}
	return asset, nil
}

func fetchGithubAssetAndChecksum(ra *github.ReleaseAsset) (io.ReadCloser, string, error) {
	checksum, err := slurpFile(ra.GetBrowserDownloadURL() + ".sha256")
	if err != nil {
		return nil, "", fmt.Errorf("could not slurp checksum file for asset %s, err: %w", ra.GetBrowserDownloadURL(), err)
	}

	resp, err := http.Get(ra.GetBrowserDownloadURL())
	if err != nil {
		return nil, "", fmt.Errorf("could not download asset %s, err: %w", ra.GetBrowserDownloadURL(), err)
	}
	return resp.Body, checksum, nil
}

func replaceBinary(binaryReader io.ReadCloser, checksum string) error {
	filename, err := copyToTempFile(binaryReader)
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

func copyToTempFile(binaryReader io.ReadCloser) (string, error) {
	file, err := ioutil.TempFile("/var/tmp", gitHubArtifact)
	if err != nil {
		return "", err
	}

	_, err = io.Copy(file, binaryReader)
	if err != nil {
		return "", err
	}
	defer binaryReader.Close()

	err = os.Chmod(file.Name(), 0764)
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
