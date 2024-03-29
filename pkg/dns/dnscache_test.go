package dns

import (
	"testing"

	"github.com/go-logr/logr"

	firewallv1 "github.com/metal-stack/firewall-controller/v2/api/v1"
)

func Test_GetSetsForFQDN(t *testing.T) {
	tests := []struct {
		name         string
		fqdnToEntry  map[string]cacheEntry
		expectedSets []string
		fqdnSelector firewallv1.FQDNSelector
		cachedSets   []firewallv1.IPSet
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
				"second.example.com.": {
					ipv4: &ipEntry{
						setName: "2examplev4",
					},
					ipv6: &ipEntry{
						setName: "2examplev6",
					},
				},
			},
			expectedSets: []string{"testv4", "testv6", "examplev4", "examplev6", "2examplev4", "2examplev6"},
			fqdnSelector: firewallv1.FQDNSelector{
				MatchPattern: "*.com",
			},
		},
		{
			name: "pattern from integration testing",
			fqdnToEntry: map[string]cacheEntry{
				"www.freechess.org.": {
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
				MatchPattern: "ww*.freechess.org",
			},
		},
		{
			name:         "restore sets",
			fqdnToEntry:  map[string]cacheEntry{},
			fqdnSelector: firewallv1.FQDNSelector{},
			cachedSets: []firewallv1.IPSet{{
				FQDN:    "test-fqdn",
				SetName: "test-set",
			}},
		},
	}

	for _, tt := range tests {
		tc := tt
		t.Run(tc.name, func(t *testing.T) {
			cache := DNSCache{
				log:         logr.Discard(),
				fqdnToEntry: tc.fqdnToEntry,
				setNames:    make(map[string]struct{}),
				ipv4Enabled: true,
				ipv6Enabled: true,
			}
			result := cache.getSetsForFQDN(tc.fqdnSelector, tc.cachedSets)

			set := make(map[string]bool, len(tc.expectedSets))
			for _, s := range tc.expectedSets {
				set[s] = false
			}
			for _, r := range result {
				if _, found := set[r.SetName]; !found {
					t.Errorf("set name %s wasn't expected", r.SetName)
				}
				set[r.SetName] = true
			}
			for s, b := range set {
				if !b {
					t.Errorf("set name %s didn't occurred in result", s)
				}
			}

			// Check if cache was updated
			for _, s := range tc.cachedSets {
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
