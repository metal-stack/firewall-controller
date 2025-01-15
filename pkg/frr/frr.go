package frr

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/Masterminds/semver/v3"
)

func DetectVersion() (*semver.Version, error) {

	vtysh, err := exec.LookPath("vtysh")
	if err != nil {
		return nil, fmt.Errorf("unable to detect path to vtysh: %w", err)
	}
	// $ vtysh -c "show version"|grep FRRouting
	// FRRouting 10.2.1 (shoot--pz9cjf--mwen-fel-firewall-dcedd) on Linux(6.6.60-060660-generic).
	c := exec.Command(vtysh, "-c", "show version")
	out, err := c.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("unable to detect frr version with dpkg: %w", err)
	}

	var frrVersion string
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "FRRouting") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		frrVersion = fields[1]
		break
	}
	if frrVersion == "" {
		return nil, fmt.Errorf("unable to detect frr version")
	}

	ver, err := semver.NewVersion(frrVersion)
	if err != nil {
		return nil, fmt.Errorf("unable to parse frr version to semver: %w", err)
	}
	return ver, nil
}
