package suricata

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"
)

const (
	suricataStateDir        = "/var/lib/suricata"
	suricataSourcesDir      = suricataStateDir + "/update/sources"
	suricataUpdateIndexPath = suricataStateDir + "/update/cache/index.yaml"
	defaultDetectionRule    = "et/open"
)

func availableDetectionRulesets() ([]string, error) {
	result := []string{}

	content, err := os.ReadFile(suricataUpdateIndexPath)
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

			result = append(result, name)
		}
		sort.Strings(result)
	case errors.Is(err, fs.ErrNotExist):
		// noop
	default:
		return nil, fmt.Errorf("unable to read suricata update source index: %w", err)
	}

	return result, nil
}

func enabledDetectionRulesets() ([]string, error) {
	result := []string{}

	err := filepath.WalkDir(suricataSourcesDir, func(p string, d fs.DirEntry, err error) error {
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
			result = append(result, source.Source)
		}

		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("unable to read enabled suricata sources: %w", err)
	}

	sort.Strings(result)

	return result, nil
}

func uniqueSorted(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || slices.Contains(result, value) {
			continue
		}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
