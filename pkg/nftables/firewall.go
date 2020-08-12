package nftables

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"text/template"

	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
	_ "github.com/metal-stack/firewall-controller/pkg/nftables/statik"
	"github.com/rakyll/statik/fs"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
)

const (
	defaultIpv4RuleFile = "/etc/nftables/firewall-controller.v4"
	nftablesService     = "nftables.service"
	nftBin              = "/usr/sbin/nft"
	systemctlBin        = "/bin/systemctl"
)

// Firewall assembles nftable rules based on k8s entities
type Firewall struct {
	Ingress          []string
	Egress           []string
	RateLimits       []firewallv1.RateLimit
	Ipv4RuleFile     string
	DryRun           bool
	InternalPrefixes string
	statikFS         http.FileSystem
	PrivateVrfID     int64
}

// NewDefaultFirewall creates a new default nftables firewall.
func NewDefaultFirewall(vrfID int64) *Firewall {
	defaultSpec := firewallv1.FirewallSpec{}
	return NewFirewall(&firewallv1.ClusterwideNetworkPolicyList{}, &v1.ServiceList{}, defaultSpec, vrfID, nil)
}

type podLister func(map[string]string) v1.PodList

// NewFirewall creates a new nftables firewall object based on k8s entities
func NewFirewall(nps *firewallv1.ClusterwideNetworkPolicyList, svcs *corev1.ServiceList, spec firewallv1.FirewallSpec, vrfID int64, podLister podLister) *Firewall {
	ingress := []string{}
	egress := []string{}

	for _, np := range nps.Items {
		if len(np.Spec.Egress) > 0 {
			egress = append(egress, egressForNetworkPolicy(np, podLister)...)
		}
		if len(np.Spec.Ingress) > 0 {
			ingress = append(ingress, ingressForNetworkPolicy(np)...)
		}
	}
	for _, svc := range svcs.Items {
		ingress = append(ingress, ingressForService(svc)...)
	}
	statikFS, err := fs.NewWithNamespace("tpl")
	if err != nil {
		panic(err)
	}

	ipv4File := defaultIpv4RuleFile
	if spec.Ipv4RuleFile != "" {
		ipv4File = spec.Ipv4RuleFile
	}
	return &Firewall{
		Egress:           uniqueSorted(egress),
		Ingress:          uniqueSorted(ingress),
		RateLimits:       spec.RateLimits,
		Ipv4RuleFile:     ipv4File,
		DryRun:           spec.DryRun,
		InternalPrefixes: strings.Join(spec.InternalPrefixes, ", "),
		statikFS:         statikFS,
		PrivateVrfID:     vrfID,
	}
}

// Flush flushes the nftables rules that were deduced from a k8s resources
// after that the firewall is a "plain metal firewall" with default policy accept in the forward chain.
func (f *Firewall) Flush() error {
	_, err := os.Stat(f.Ipv4RuleFile)
	if os.IsNotExist(err) {
		return f.reload()
	}
	// only remove if rule file exists
	err = os.Remove(f.Ipv4RuleFile)
	if err != nil {
		return fmt.Errorf("could not delete ipv4 rule file: %w", err)
	}
	return f.reload()
}

// Reconcile drives the nftables firewall against the desired state by comparison with the current rule file.
func (f *Firewall) Reconcile() error {
	tmpFile, err := ioutil.TempFile("/var/tmp", "firewall-controller_nftables.v4")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())

	desired := tmpFile.Name()
	err = f.renderFile(desired)
	if err != nil {
		return err
	}
	if equal(f.Ipv4RuleFile, desired) {
		return nil
	}
	err = os.Rename(desired, f.Ipv4RuleFile)
	if err != nil {
		return err
	}
	if f.DryRun {
		return nil
	}
	err = f.reload()
	if err != nil {
		return err
	}
	return nil
}

func (f *Firewall) renderFile(file string) error {
	err := f.write(file)
	if err != nil {
		return err
	}
	if f.DryRun {
		return nil
	}
	err = f.validate(file)
	if err != nil {
		return err
	}
	return nil
}

func (f *Firewall) write(file string) error {
	c, err := f.renderString()
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(file, []byte(c), 0644)
	if err != nil {
		return fmt.Errorf("error writing to nftables file '%s': %w", file, err)
	}
	return nil
}

func (f *Firewall) renderString() (string, error) {
	var b bytes.Buffer

	tplString, err := f.readTpl()
	if err != nil {
		return "", err
	}

	tpl := template.Must(template.New("v4").Parse(tplString))

	err = tpl.Execute(&b, f)
	if err != nil {
		return "", err
	}

	return b.String(), nil
}

func (f *Firewall) readTpl() (string, error) {
	r, err := f.statikFS.Open("/nftables.tpl")
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

func (f *Firewall) validate(file string) error {
	c := exec.Command(nftBin, "-c", "-f", file)
	out, err := c.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nftables file '%s' is invalid: %s, err: %w", file, string(out), err)
	}
	return nil
}

func (f *Firewall) reload() error {
	c := exec.Command(systemctlBin, "reload", nftablesService)
	err := c.Run()
	if err != nil {
		return fmt.Errorf("could not reload nftables service, err: %w", err)
	}
	return nil
}
