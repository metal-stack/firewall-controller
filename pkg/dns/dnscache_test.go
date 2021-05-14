package dns

import (
	"testing"

	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
)

// TODO
func Test_GetSetsForFQDN(t *testing.T) {
	tests := []struct {
		name         string
		fqdnSelector firewallv1.FQDNSelector
	}{
		{
			name: "restore sets",
			fqdnSelector: firewallv1.FQDNSelector{
				Sets: []firewallv1.IPSet{{
					FQDN:    "test-fqdn",
					SetName: "test-set",
				}},
			},
		},
	}

	cache := NewDNSCache()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache.GetSetsForFQDN(tt.fqdnSelector, true)
			for _, s := range tt.fqdnSelector.Sets {
				if _, ok := cache.setNames[s.SetName]; !ok {
					t.Errorf("set name %s wasn't added to cache", s.SetName)
				}
				if _, ok := cache.fqdnToEntry[s.FQDN]; !ok {
					t.Errorf("FQDN %s wasn't added to cache", s.FQDN)
				}
			}
		})
	}
}
