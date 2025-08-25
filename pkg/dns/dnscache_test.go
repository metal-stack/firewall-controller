package dns

import (
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
	firewallv1 "github.com/metal-stack/firewall-controller/v2/api/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Test_GetSetsForFQDN(t *testing.T) {
	tests := []struct {
		name        string
		fqdnToEntry map[string]CacheEntry
		want        []firewallv1.IPSet
		fqdn        firewallv1.FQDNSelector
	}{
		{
			name: "get result for matchName",
			fqdnToEntry: map[string]CacheEntry{
				"test.com.": {
					IPv4: &IPEntry{
						SetName: "testv4",
					},
					IPv6: &IPEntry{
						SetName: "testv6",
					},
				},
			},
			want: []firewallv1.IPSet{
				{
					SetName:           "testv4",
					FQDN:              "test.com.",
					Version:           "ip",
					IPExpirationTimes: map[string]v1.Time{},
				},
				{
					SetName:           "testv6",
					FQDN:              "test.com.",
					Version:           "ip6",
					IPExpirationTimes: map[string]v1.Time{},
				},
			},
			fqdn: firewallv1.FQDNSelector{
				MatchName: "test.com",
			},
		},
		{
			name: "get result for matchPattern",
			fqdnToEntry: map[string]CacheEntry{
				"test.com.": {
					IPv4: &IPEntry{
						SetName: "testv4",
					},
					IPv6: &IPEntry{
						SetName: "testv6",
					},
				},
				"test.io.": {
					IPv4: &IPEntry{
						SetName: "testiov4",
					},
					IPv6: &IPEntry{
						SetName: "testiov6",
					},
				},
				"example.com.": {
					IPv4: &IPEntry{
						SetName: "examplev4",
					},
					IPv6: &IPEntry{
						SetName: "examplev6",
					},
				},
				"second.example.com.": {
					IPv4: &IPEntry{
						SetName: "2examplev4",
					},
					IPv6: &IPEntry{
						SetName: "2examplev6",
					},
				},
			},
			want: []firewallv1.IPSet{
				{
					SetName:           "2examplev4",
					FQDN:              "second.example.com.",
					Version:           "ip",
					IPExpirationTimes: map[string]v1.Time{},
				},
				{
					SetName:           "2examplev6",
					FQDN:              "second.example.com.",
					IPExpirationTimes: map[string]v1.Time{},
					Version:           "ip6",
				},
				{
					SetName:           "examplev4",
					FQDN:              "example.com.",
					IPExpirationTimes: map[string]v1.Time{},
					Version:           "ip",
				},
				{
					SetName:           "examplev6",
					FQDN:              "example.com.",
					IPExpirationTimes: map[string]v1.Time{},
					Version:           "ip6",
				},
				{
					SetName:           "testv4",
					FQDN:              "test.com.",
					IPExpirationTimes: map[string]v1.Time{},
					Version:           "ip",
				},
				{
					SetName:           "testv6",
					FQDN:              "test.com.",
					IPExpirationTimes: map[string]v1.Time{},
					Version:           "ip6",
				},
			},
			fqdn: firewallv1.FQDNSelector{
				MatchPattern: "*.com",
			},
		},
		{
			name: "pattern from integration testing",
			fqdnToEntry: map[string]CacheEntry{
				"www.freechess.org.": {
					IPv4: &IPEntry{
						SetName: "testv4",
					},
					IPv6: &IPEntry{
						SetName: "testv6",
					},
				},
			},
			want: []firewallv1.IPSet{
				{
					SetName:           "testv4",
					FQDN:              "www.freechess.org.",
					IPExpirationTimes: map[string]v1.Time{},
					Version:           "ip",
				},
				{
					SetName:           "testv6",
					FQDN:              "www.freechess.org.",
					IPExpirationTimes: map[string]v1.Time{},
					Version:           "ip6",
				},
			},
			fqdn: firewallv1.FQDNSelector{
				MatchPattern: "ww*.freechess.org",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := DNSCache{
				log:         logr.Discard(),
				fqdnToEntry: tt.fqdnToEntry,
				setNames:    make(map[string]struct{}),
				ipv4Enabled: true,
				ipv6Enabled: true,
			}

			got := cache.getSetsForFQDN(tt.fqdn)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("DNSCache.getSetsForFQDN diff = %s", diff)
			}
		})
	}
}

func Test_createIPSetFromIPEntry(t *testing.T) {
	tests := []struct {
		name    string
		fqdn    string
		version firewallv1.IPVersion
		entry   *IPEntry
		want    firewallv1.IPSet
	}{
		{
			name:    "empty ip entry",
			fqdn:    "www.freechess.org",
			version: "ip",
			entry: &IPEntry{
				SetName: "test",
			},
			want: firewallv1.IPSet{
				FQDN:              "www.freechess.org",
				SetName:           "test",
				IPExpirationTimes: map[string]v1.Time{},
				Version:           "ip",
			},
		},
		{
			name:    "entry contains ips",
			fqdn:    "www.freechess.org",
			version: "ip",
			entry: &IPEntry{
				SetName: "test",
				IPs: map[string]time.Time{
					"1.2.3.4": time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC),
				},
			},
			want: firewallv1.IPSet{
				FQDN:    "www.freechess.org",
				SetName: "test",
				IPExpirationTimes: map[string]v1.Time{
					"1.2.3.4": v1.NewTime(time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC)),
				},
				Version: "ip",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := createIPSetFromIPEntry(tt.fqdn, tt.version, tt.entry)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("createIPSetFromIPEntry() diff = %s", diff)
			}
		})
	}
}
