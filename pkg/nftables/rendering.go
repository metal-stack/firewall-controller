package nftables

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"text/template"
)

// firewallRenderingData holds the data available in the nftables template
type firewallRenderingData struct {
	ForwardingRules  forwardingRules
	RateLimitRules   nftablesRules
	SnatRules        nftablesRules
	InternalPrefixes string
	PrivateVrfID     uint
}

func newFirewallRenderingData(f *Firewall) (*firewallRenderingData, error) {
	ingress, egress := nftablesRules{}, nftablesRules{}
	for _, np := range f.clusterwideNetworkPolicies.Items {
		err := np.Spec.Validate()
		if err != nil {
			continue
		}
		i, e := clusterwideNetworkPolicyRules(np)
		ingress = append(ingress, i...)
		egress = append(egress, e...)
	}

	for _, svc := range f.services.Items {
		ingress = append(ingress, serviceRules(svc)...)
	}

	snatRules, err := snatRules(f)
	if err != nil {
		return &firewallRenderingData{}, err
	}

	return &firewallRenderingData{
		PrivateVrfID:     uint(*f.primaryPrivateNet.Vrf),
		InternalPrefixes: strings.Join(f.spec.InternalPrefixes, ", "),
		ForwardingRules: forwardingRules{
			Ingress: ingress,
			Egress:  egress,
		},
		RateLimitRules: rateLimitRules(f),
		SnatRules:      snatRules,
	}, nil
}

func (d *firewallRenderingData) write(file string) (bool, string, error) {
	newContent, err := d.renderString()
	if err != nil {
		return false, "", err
	}

	newContentBytes := []byte(newContent)
	oldContentBytes, err := os.ReadFile(file)
	if err != nil && !os.IsNotExist(err) {
		return false, "", err
	}

	if !os.IsNotExist(err) && reflect.DeepEqual(newContentBytes, oldContentBytes) {
		return false, "", nil
	}

	tmpFile, err := os.CreateTemp(filepath.Dir(file), filepath.Base(file))
	if err != nil {
		return false, "", err
	}

	err = os.WriteFile(tmpFile.Name(), newContentBytes, 0600)
	if err != nil {
		return false, "", fmt.Errorf("error writing to nftables file '%s': %w", file, err)
	}
	return true, tmpFile.Name(), nil
}

func (d *firewallRenderingData) renderString() (string, error) {
	var b bytes.Buffer

	tplString, err := d.readTpl()
	if err != nil {
		return "", err
	}

	tpl := template.Must(template.New("v4").Parse(tplString))

	err = tpl.Execute(&b, d)
	if err != nil {
		return "", err
	}

	return b.String(), nil
}

func (d *firewallRenderingData) readTpl() (string, error) {
	r, err := templates.Open("nftables.tpl")
	if err != nil {
		return "", err
	}
	defer r.Close()
	bytes, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}
