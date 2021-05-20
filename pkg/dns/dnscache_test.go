package dns

import (
	"testing"

	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
)

func Test_GetSetsForFQDN(t *testing.T) {
	tests := []struct {
		name         string
		fqdnToEntry  map[string]cacheEntry
		expectedSets []string
		fqdnSelector firewallv1.FQDNSelector
	}{
		{
			name: "get result for matchName",
			fqdnToEntry: map[string]cacheEntry{
				"test.com.": {
					ipv4: &ipEntry{
						setName: "testv4",
					},
					ipv6: &ipEntry{
						setName: "testv6",
					},
				},
			},
			expectedSets: []string{"testv4", "testv6"},
			fqdnSelector: firewallv1.FQDNSelector{
				MatchName: "test.com",
			},
		},
		{
			name: "get result for matchPattern",
			fqdnToEntry: map[string]cacheEntry{
				"test.com.": {
					ipv4: &ipEntry{
						setName: "testv4",
					},
					ipv6: &ipEntry{
						setName: "testv6",
					},
				},
				"test.io.": {
					ipv4: &ipEntry{
						setName: "testiov4",
					},
					ipv6: &ipEntry{
						setName: "testiov6",
					},
				},
				"example.com.": {
					ipv4: &ipEntry{
						setName: "examplev4",
					},
					ipv6: &ipEntry{
						setName: "examplev6",
					},
				},
			},
			expectedSets: []string{"testv4", "testv6", "examplev4", "examplev6"},
			fqdnSelector: firewallv1.FQDNSelector{
				MatchPattern: "*.com",
			},
		},
		{
			name:        "restore sets",
			fqdnToEntry: map[string]cacheEntry{},
			fqdnSelector: firewallv1.FQDNSelector{
				Sets: []firewallv1.IPSet{{
					FQDN:    "test-fqdn",
					SetName: "test-set",
				}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := DNSCache{
				fqdnToEntry: tt.fqdnToEntry,
				setNames:    make(map[string]struct{}),
			}
			result := cache.GetSetsForFQDN(tt.fqdnSelector, tt.fqdnSelector.Sets != nil)
			for i, s := range tt.expectedSets {
				if result[i].SetName != s {
					t.Errorf("set name %s isn't same as expected %s", result[i].SetName, s)
				}
			}

			// Check if cache was updated
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
