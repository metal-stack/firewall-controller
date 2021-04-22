package dns

import (
	"time"

	dnsgo "github.com/miekg/dns"
)

type cacheEntry struct {
	ips []string
	ttl
}

type DNSCache struct {
	fqdnToEntry map[string]cacheEntry
}

func (c *DNSCache) GetIPs(fqdn string) []string {}

func (c *DNSCache) GetIPsForRegex(regex string) []string {}

func (c *DNSCache) Update(lookupTime time.Time, msg *dnsgo.Msg) bool {

}
