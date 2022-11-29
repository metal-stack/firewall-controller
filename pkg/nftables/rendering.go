package nftables

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"text/template"

	"github.com/metal-stack/firewall-controller/pkg/dns"
)

// firewallRenderingData holds the data available in the nftables template
type firewallRenderingData struct {
	ForwardingRules  forwardingRules
	RateLimitRules   nftablesRules
	SnatRules        nftablesRules
	Sets             []dns.RenderIPSet
	InternalPrefixes string
	PrivateVrfID     uint
}

func newFirewallRenderingData(f *Firewall) (*firewallRenderingData, error) {
	ingress, egress := nftablesRules{}, nftablesRules{}
	for ind, np := range f.clusterwideNetworkPolicies.Items {
		err := np.Spec.Validate()
		if err != nil {
			continue
		}

		i, e, u := clusterwideNetworkPolicyRules(f.cache, np, f.logAcceptedConnections)
		ingress = append(ingress, i...)
		egress = append(egress, e...)
		f.clusterwideNetworkPolicies.Items[ind] = u
	}

	for _, svc := range f.services.Items {
		ingress = append(ingress, serviceRules(svc, f.logAcceptedConnections)...)
	}

	snatRules, err := snatRules(f)
	if err != nil {
		return &firewallRenderingData{}, err
	}

	var sets []dns.RenderIPSet
	if f.cache.IsInitialized() {
		sets = f.cache.GetSetsForRendering(f.clusterwideNetworkPolicies.GetFQDNs())
	}
	return &firewallRenderingData{
		PrivateVrfID:     uint(*f.primaryPrivateNet.Vrf),
		InternalPrefixes: strings.Join(f.firewall.Spec.InternalPrefixes, ", "),
		ForwardingRules: forwardingRules{
			Ingress: ingress,
			Egress:  egress,
		},
		RateLimitRules: rateLimitRules(f),
		SnatRules:      snatRules,
		Sets:           sets,
	}, nil
}

func (d *firewallRenderingData) write(file string) error {
	c, err := d.renderString()
	if err != nil {
		return err
	}
	err = os.WriteFile(file, []byte(c), 0600)
	if err != nil {
		return fmt.Errorf("error writing to nftables file '%s': %w", file, err)
	}
	return nil
}

func (d *firewallRenderingData) renderString() (string, error) {
	var b bytes.Buffer

	tplString, err := d.readTpl()
	if err != nil {
		return "", err
	}

	tpl := template.Must(
		template.New("v4").
			Funcs(template.FuncMap{"StringsJoin": strings.Join}).
			Parse(tplString),
	)

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
