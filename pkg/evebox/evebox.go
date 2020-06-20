package evebox

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"text/template"

	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
	"github.com/metal-stack/firewall-controller/pkg/file"
	_ "github.com/metal-stack/firewall-controller/pkg/nftables/statik"
	"github.com/rakyll/statik/fs"
)

const (
	eveboxAgentService = "evebox-agent.service"
	systemctlBin       = "/bin/systemctl"
)

// Evebox configures the Evebox agent
type Evebox struct {
	ServerURL string
	Username  *string
	Password  *string
	ClusterID string
	ProjectID string
	agentFile string
	statikFS  http.FileSystem
}

// NewEvebox creates a evebox object which manages the evebox-agent
func NewEvebox(spec firewallv1.FirewallSpec) *Evebox {
	statikFS, err := fs.NewWithNamespace("tpl")
	if err != nil {
		panic(err)
	}

	agentFile := "/etc/evebox/agent.yaml"
	return &Evebox{
		ServerURL: spec.IDS.ServerURL,
		Username:  spec.IDS.Username,
		Password:  spec.IDS.Password,
		ClusterID: spec.ClusterID,
		ProjectID: spec.ProjectID,
		statikFS:  statikFS,
		agentFile: agentFile,
	}
}

// Reconcile drives the nftables firewall against the desired state by comparison with the current rule file.
func (e *Evebox) Reconcile() error {
	tmpFile, err := ioutil.TempFile("/var/tmp", "agent.yaml")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())

	desired := tmpFile.Name()
	err = e.write(desired)
	if err != nil {
		return err
	}
	if file.Equal(e.agentFile, desired) {
		return nil
	}
	err = os.Rename(desired, e.agentFile)
	if err != nil {
		return err
	}
	return e.reload(e.agentFile)
}

func (e *Evebox) write(file string) error {
	c, err := e.renderString()
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(file, []byte(c), 0644)
	if err != nil {
		return fmt.Errorf("error writing to eve agent file '%s': %w", file, err)
	}
	return nil
}

func (e *Evebox) renderString() (string, error) {
	var b bytes.Buffer

	tplString, err := e.readTpl()
	if err != nil {
		return "", err
	}

	tpl := template.Must(template.New("yaml").Parse(tplString))

	err = tpl.Execute(&b, e)
	if err != nil {
		return "", err
	}

	return b.String(), nil
}

func (e *Evebox) readTpl() (string, error) {
	r, err := e.statikFS.Open("/agent.yaml.tpl")
	if err != nil {
		return "", err
	}
	defer r.Close()
	bytes, err := ioutil.ReadAll(r)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func (e *Evebox) reload(file string) error {
	c := exec.Command(systemctlBin, "reload", eveboxAgentService)
	err := c.Run()
	if err != nil {
		return fmt.Errorf("%s could not be applied, err: %w", file, err)
	}
	return nil
}
