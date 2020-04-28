package nftables

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"text/template"

	firewallv1 "github.com/metal-stack/firewall-builder/api/v1"
	corev1 "k8s.io/api/core/v1"
)

const (
	nftablesService = "nftables.service"
	nftBin          = "/usr/sbin/nft"
	nftFile         = "/etc/nftables/firewall-controller.v4"
	systemctlBin    = "/bin/systemctl"
)

// Firewall assembles nftable rules based on k8s entities
type Firewall struct {
	Ingress []string
	Egress  []string
}

// NewFirewall creates a new nftables firewall object based on k8s entities
func NewFirewall(nps *firewallv1.ClusterwideNetworkPolicyList, svcs *corev1.ServiceList) *Firewall {
	ingress := []string{}
	egress := []string{}
	for _, np := range nps.Items {
		if len(np.Spec.Egress) > 0 {
			egress = append(egress, egressForNetworkPolicy(np)...)
		}
		if len(np.Spec.Ingress) > 0 {
			ingress = append(ingress, ingressForNetworkPolicy(np)...)
		}
	}
	for _, svc := range svcs.Items {
		ingress = append(ingress, ingressForService(svc)...)
	}
	return &Firewall{
		Egress:  uniqueSorted(egress),
		Ingress: uniqueSorted(ingress),
	}
}

// Reconcile drives the nftables firewall against the desired state by comparison with the current rule file.
func (r *Firewall) Reconcile() error {
	desired := "/tmp/firewall-controller_nftables.v4"
	err := r.renderFile(desired)
	if err != nil {
		return err
	}
	if equal(nftFile, desired) {
		return nil
	}
	err = os.Rename(desired, nftFile)
	if err != nil {
		return err
	}
	err = r.reload()
	if err != nil {
		return err
	}
	return nil
}

func (r *Firewall) renderFile(file string) error {
	err := r.write(file)
	if err != nil {
		return err
	}
	err = r.validate(file)
	if err != nil {
		return err
	}
	return nil
}

func (r *Firewall) write(file string) error {
	c, err := r.renderString()
	err = ioutil.WriteFile(file, []byte(c), 0644)
	if err != nil {
		return fmt.Errorf("error writing to nftables file '%s': %w", file, err)
	}
	return nil
}

func (r *Firewall) renderString() (string, error) {
	var b bytes.Buffer
	tpl := template.Must(template.New("v4").Parse(nftableTemplateIpv4))
	err := tpl.Execute(&b, r)
	if err != nil {
		return "", err
	}
	return b.String(), nil
}

func (r *Firewall) validate(file string) error {
	c := exec.Command(nftBin, "-c", "-f", file)
	out, err := c.Output()
	if err != nil {
		return fmt.Errorf("nftables file '%s' is invalid: %s, err: %w", file, fmt.Sprint(out), err)
	}
	return nil
}

func (r *Firewall) reload() error {
	c := exec.Command(systemctlBin, "reload", nftablesService)
	err := c.Run()
	if err != nil {
		return fmt.Errorf("%s could not be reloaded, err: %w", nftablesService, err)
	}
	return nil
}
