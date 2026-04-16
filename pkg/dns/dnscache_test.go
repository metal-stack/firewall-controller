package dns

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
	"github.com/google/nftables"
	firewallv1 "github.com/metal-stack/firewall-controller/v2/api/v1"
	dnsgo "github.com/miekg/dns"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func Test_GetSetsForFQDN(t *testing.T) {
	tests := []struct {
		name        string
		fqdnToEntry map[string]cacheEntry
		want        []firewallv1.IPSet
		fqdn        firewallv1.FQDNSelector
	}{
		{
			name: "get result for matchName",
			fqdnToEntry: map[string]cacheEntry{
				"test.com.": {
					IPv4: &iPEntry{
						SetName: "testv4",
					},
					IPv6: &iPEntry{
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
			fqdnToEntry: map[string]cacheEntry{
				"test.com.": {
					IPv4: &iPEntry{
						SetName: "testv4",
					},
					IPv6: &iPEntry{
						SetName: "testv6",
					},
				},
				"test.io.": {
					IPv4: &iPEntry{
						SetName: "testiov4",
					},
					IPv6: &iPEntry{
						SetName: "testiov6",
					},
				},
				"example.com.": {
					IPv4: &iPEntry{
						SetName: "examplev4",
					},
					IPv6: &iPEntry{
						SetName: "examplev6",
					},
				},
				"second.example.com.": {
					IPv4: &iPEntry{
						SetName: "2examplev4",
					},
					IPv6: &iPEntry{
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
			fqdnToEntry: map[string]cacheEntry{
				"www.freechess.org.": {
					IPv4: &iPEntry{
						SetName: "testv4",
					},
					IPv6: &iPEntry{
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
		entry   *iPEntry
		want    firewallv1.IPSet
	}{
		{
			name:    "empty ip entry",
			fqdn:    "www.freechess.org",
			version: "ip",
			entry: &iPEntry{
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
			entry: &iPEntry{
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

const (
	raceNumGoroutines = 10
	raceNumIterations = 100
)

func newTestDNSCache(entries map[string]cacheEntry) *DNSCache {
	return &DNSCache{
		log:           logr.Discard(),
		fqdnToEntry:   entries,
		setNames:      make(map[string]struct{}),
		dnsServerAddr: "127.0.0.1:53",
		ctx:           context.Background(),
		shootClient:   fake.NewClientBuilder().Build(),
		ipv4Enabled:   true,
		ipv6Enabled:   true,
	}
}

func makeTestRRs(fqdn string, ip string) []dnsgo.RR {
	return []dnsgo.RR{
		&dnsgo.A{
			Hdr: dnsgo.RR_Header{Name: fqdn, Rrtype: dnsgo.TypeA, Ttl: 300},
			A:   net.ParseIP(ip),
		},
	}
}

func seedEntries(n int) map[string]cacheEntry {
	entries := make(map[string]cacheEntry, n)
	for i := range n {
		fqdn := fmt.Sprintf("host%d.example.com.", i)
		entries[fqdn] = cacheEntry{
			IPv4: &iPEntry{
				SetName: fmt.Sprintf("set%d", i),
				IPs:     map[string]time.Time{fmt.Sprintf("10.0.0.%d", i%256): time.Now().Add(5 * time.Minute)},
			},
		}
	}
	return entries
}

func TestRace_UpdateAndGetSetsForRendering(t *testing.T) {
	cache := newTestDNSCache(seedEntries(5))
	fqdns := []firewallv1.FQDNSelector{{MatchPattern: "*.example.com"}}

	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := range raceNumGoroutines {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			<-start
			fqdn := fmt.Sprintf("writer%d.example.com.", id)
			for j := range raceNumIterations {
				_ = cache.updateIPEntry(fqdn, makeTestRRs(fqdn, fmt.Sprintf("10.1.%d.%d", id, j%256)), time.Now(), nftables.TypeIPAddr)
			}
		}(i)
	}

	for range raceNumGoroutines {
		wg.Go(func() {
			<-start
			for range raceNumIterations {
				cache.getSetsForRendering(fqdns)
			}
		})
	}

	close(start)
	wg.Wait()
}

func TestRace_UpdateAndGetSetNameForRegex(t *testing.T) {
	cache := newTestDNSCache(seedEntries(5))

	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := range raceNumGoroutines {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			<-start
			fqdn := fmt.Sprintf("writer%d.example.com.", id)
			for j := range raceNumIterations {
				_ = cache.updateIPEntry(fqdn, makeTestRRs(fqdn, fmt.Sprintf("10.2.%d.%d", id, j%256)), time.Now(), nftables.TypeIPAddr)
			}
		}(i)
	}

	for range raceNumGoroutines {
		wg.Go(func() {
			<-start
			for range raceNumIterations {
				cache.getSetNameForRegex(`.*\.example\.com\.`)
			}
		})
	}

	close(start)
	wg.Wait()
}

func TestRace_UpdateAndGetSetNameForFQDN(t *testing.T) {
	cache := newTestDNSCache(seedEntries(5))

	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := range raceNumGoroutines {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			<-start
			fqdn := fmt.Sprintf("host%d.example.com.", id%5)
			for j := range raceNumIterations {
				_ = cache.updateIPEntry(fqdn, makeTestRRs(fqdn, fmt.Sprintf("10.3.%d.%d", id, j%256)), time.Now(), nftables.TypeIPAddr)
			}
		}(i)
	}

	for i := range raceNumGoroutines {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			<-start
			fqdn := fmt.Sprintf("host%d.example.com.", id%5)
			for range raceNumIterations {
				cache.getSetNameForFQDN(fqdn)
			}
		}(i)
	}

	close(start)
	wg.Wait()
}

func TestRace_UpdateAndWriteStateToConfigmap(t *testing.T) {
	cache := newTestDNSCache(seedEntries(5))

	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := range raceNumGoroutines {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			<-start
			fqdn := fmt.Sprintf("writer%d.example.com.", id)
			for j := range raceNumIterations {
				_ = cache.updateIPEntry(fqdn, makeTestRRs(fqdn, fmt.Sprintf("10.4.%d.%d", id, j%256)), time.Now(), nftables.TypeIPAddr)
			}
		}(i)
	}

	for range raceNumGoroutines {
		wg.Go(func() {
			<-start
			for range raceNumIterations {
				_ = cache.writeStateToConfigmap()
			}
		})
	}

	close(start)
	wg.Wait()
}

func TestRace_UpdateDNSServerAddr(t *testing.T) {
	cache := newTestDNSCache(seedEntries(1))

	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := range raceNumGoroutines {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			<-start
			for j := range raceNumIterations {
				cache.updateDNSServerAddr(fmt.Sprintf("10.0.%d.%d:53", id, j%256))
			}
		}(i)
	}

	for range raceNumGoroutines {
		wg.Go(func() {
			<-start
			for range raceNumIterations {
				cache.RLock()
				_ = cache.dnsServerAddr
				cache.RUnlock()
			}
		})
	}

	close(start)
	wg.Wait()
}

func TestRace_ConcurrentMultipleReaders(t *testing.T) {
	cache := newTestDNSCache(seedEntries(10))
	fqdns := []firewallv1.FQDNSelector{{MatchPattern: "*.example.com"}}

	var wg sync.WaitGroup
	start := make(chan struct{})

	for range raceNumGoroutines {
		wg.Go(func() {
			<-start
			for range raceNumIterations {
				cache.getSetsForRendering(fqdns)
			}
		})
	}

	for range raceNumGoroutines {
		wg.Go(func() {
			<-start
			for range raceNumIterations {
				cache.getSetNameForRegex(`.*\.example\.com\.`)
			}
		})
	}

	for i := range raceNumGoroutines {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			<-start
			fqdn := fmt.Sprintf("host%d.example.com.", id%10)
			for range raceNumIterations {
				cache.getSetNameForFQDN(fqdn)
			}
		}(i)
	}

	close(start)
	wg.Wait()
}

func TestDNSCache_shouldWriteStateToConfigmap(t *testing.T) {
	now := time.Now()

	cache := &DNSCache{
		stateUpdateInterval: 2 * time.Second,
	}

	if got := cache.shouldWriteStateToConfigmap(now); !got {
		t.Fatalf("expected first write attempt to be allowed")
	}

	if got := cache.shouldWriteStateToConfigmap(now.Add(1500 * time.Millisecond)); got {
		t.Fatalf("expected write attempt within interval to be throttled")
	}

	if got := cache.shouldWriteStateToConfigmap(now.Add(2 * time.Second)); !got {
		t.Fatalf("expected write attempt at interval boundary to be allowed")
	}
}
