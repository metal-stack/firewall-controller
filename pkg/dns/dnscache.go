package dns

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/google/nftables"
	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"
	dnsgo "github.com/miekg/dns"
)

const (
	tableName = "firewall"
)

type ipEntry struct {
	ips            []net.IP
	expirationTime time.Time
	setName        string
}

func newIPEntry(setName string, expirationTime time.Time, dtype nftables.SetDatatype) (*ipEntry, error) {
	if err := createNftSet(setName, dtype); err != nil {
		return nil, fmt.Errorf("failed to create nft set: %w", err)
	}

	return &ipEntry{
		expirationTime: expirationTime,
		setName:        setName,
	}, nil
}

func (e *ipEntry) update(setName string, ips []net.IP, expirationTime time.Time, dtype nftables.SetDatatype) error {
	newIPs, deletedIPs := e.getNewAndDeletedIPs(ips)
	if !e.expirationTime.After(time.Now()) {
		e.expirationTime = expirationTime
	}

	if newIPs != nil || deletedIPs != nil {
		e.ips = ips
		if err := updateNftSet(newIPs, deletedIPs, setName, dtype); err != nil {
			return fmt.Errorf("failed to update nft set: %w", err)
		}
	}

	return nil
}

func (e *ipEntry) getNewAndDeletedIPs(ips []net.IP) (newIPs, deletedIPs []nftables.SetElement) {
	currentIps := make(map[string]bool, len(e.ips))
	for _, ip := range e.ips {
		currentIps[ip.String()] = false
	}

	for _, ip := range ips {
		s := ip.String()
		if _, ok := currentIps[s]; ok {
			currentIps[s] = true
		} else {
			newIPs = append(newIPs, nftables.SetElement{Key: ip})
		}
	}

	for ip, exists := range currentIps {
		if !exists {
			deletedIPs = append(deletedIPs, nftables.SetElement{Key: net.ParseIP(ip)})
		}
	}

	return
}

type cacheEntry struct {
	ipv4 *ipEntry
	ipv6 *ipEntry
}

type DNSCache struct {
	sync.RWMutex

	client      *dnsgo.Client
	fqdnToEntry map[string]cacheEntry
	setNames    map[string]struct{}
}

func NewDNSCache() *DNSCache {
	return &DNSCache{
		fqdnToEntry: map[string]cacheEntry{},
		setNames:    map[string]struct{}{},
	}
}

// GetSetsForFQDN returns sets for FQDN selector
// If sets present in fqdn.Sets missing in cache, add those sets to cache
func (c *DNSCache) GetSetsForFQDN(fqdn firewallv1.FQDNSelector) (result []string) {
	sets := map[string]struct{}{}
	for _, s := range fqdn.Sets {
		sets[s.SetName] = struct{}{}

		// Add cache entries from fqdn.Sets if missing
		c.Lock()
		if _, ok := c.setNames[s.SetName]; !ok {
			c.setNames[s.SetName] = struct{}{}
			entry, exists := c.fqdnToEntry[s.FQDN]
			if !exists {
				entry = cacheEntry{}
			}

			ipe := &ipEntry{
				ips:            s.IPs,
				expirationTime: s.ExpirationTime.Time,
				setName:        s.SetName,
			}
			switch s.Version {
			case firewallv1.IPv4:
				entry.ipv4 = ipe
			case firewallv1.IPv6:
				entry.ipv6 = ipe
			}

			c.fqdnToEntry[s.FQDN] = entry
		}
		c.Unlock()
	}

	if fqdn.MatchName != "" {
		if s := c.getSetNameForFQDN(fqdn.GetMatchName()); s != "" {
			sets[s] = struct{}{}
		}

	} else if fqdn.MatchPattern != "" {
		for _, s := range c.getSetNameForRegex(fqdn.GetRegex()) {
			sets[s] = struct{}{}
		}
	}

	result = make([]string, 0, len(sets))
	for s := range sets {
		result = append(result, s)
	}

	return
}

// getSetNameForFQDN returns set name for FQDN
func (c *DNSCache) getSetNameForFQDN(fqdn string) string {
	c.RLock()
	defer c.RUnlock()

	entry, found := c.fqdnToEntry[fqdn]
	if !found {
		return ""
	}

	return entry.ipv4.setName
}

// getSetNameForRegex returns list of IPs for FQDN that match provided regex
func (c *DNSCache) getSetNameForRegex(regex string) (sets []string) {
	c.RLock()
	defer c.RUnlock()

	for n, e := range c.fqdnToEntry {
		if matched, _ := regexp.MatchString(regex, n); !matched {
			continue
		}

		sets = append(sets, e.ipv4.setName)
	}

	return nil
}

// Update DNS cache.
// It expects that there was only one question to DNS(majority of cases).
// So it picks first qname and skips all others(if there is).
func (c *DNSCache) Update(lookupTime time.Time, msg *dnsgo.Msg) error {
	qname := strings.ToLower(msg.Question[0].Name)

	ipv4 := []net.IP{}
	ipv6 := []net.IP{}
	minIPv4TTL := uint32(math.MaxUint32)
	minIPv6TTL := uint32(math.MaxUint32)

	for _, ans := range msg.Answer {
		if strings.ToLower(ans.Header().Name) != qname {
			continue
		}

		switch rr := ans.(type) {
		case *dnsgo.A:
			ipv4 = append(ipv4, rr.A)
			if minIPv4TTL > rr.Hdr.Ttl {
				minIPv4TTL = rr.Hdr.Ttl
			}
		case *dnsgo.AAAA:
			ipv6 = append(ipv6, rr.AAAA)
			if minIPv6TTL > rr.Hdr.Ttl {
				minIPv6TTL = rr.Hdr.Ttl
			}
		}
	}

	if err := c.updateIPEntry(qname, ipv4, lookupTime.Add(time.Duration(minIPv4TTL)), nftables.TypeIPAddr); err != nil {
		return fmt.Errorf("failed to update IPv4 addresses: %w", err)
	}
	if err := c.updateIPEntry(qname, ipv6, lookupTime.Add(time.Duration(minIPv6TTL)), nftables.TypeIP6Addr); err != nil {
		return fmt.Errorf("failed to update IPv6 addresses: %w", err)
	}

	return nil
}

func (c *DNSCache) updateIPEntry(qname string, ips []net.IP, expirationTime time.Time, dtype nftables.SetDatatype) error {
	var (
		setName string
		err     error
	)

	c.Lock()
	defer c.Unlock()

	entry, exists := c.fqdnToEntry[qname]
	if !exists {
		entry = cacheEntry{}
	}

	var ipe *ipEntry
	switch dtype {
	case nftables.TypeIPAddr:
		if entry.ipv4 == nil {
			setName = c.createSetName(qname, dtype.Name, 0)
			if ipe, err = newIPEntry(setName, expirationTime, dtype); err != nil {
				return fmt.Errorf("failed to create IPv4 entry")
			}
			entry.ipv4 = ipe
		}
		ipe = entry.ipv4
	case nftables.TypeIP6Addr:
		if entry.ipv6 == nil {
			setName = c.createSetName(qname, dtype.Name, 0)
			if ipe, err = newIPEntry(setName, expirationTime, dtype); err != nil {
				return fmt.Errorf("failed to create IPv6 entry")
			}
			entry.ipv6 = ipe
		}
		ipe = entry.ipv6
	}

	ipe.update(setName, ips, expirationTime, dtype)
	c.fqdnToEntry[qname] = entry

	return nil
}

func (c *DNSCache) createSetName(qname, dataType string, suffix int) (setName string) {
	md5Hash := md5.Sum([]byte(qname + dataType))
	hex := hex.EncodeToString(md5Hash[:])

	for i, ch := range hex {
		if !unicode.IsDigit(ch) {
			setName = hex[i : i+16]
			break
		}
	}

	// Check that set name isn't taken already
	if _, ok := c.setNames[setName]; ok {
		setName = c.createSetName(qname, dataType, suffix+1)
		return
	}

	c.setNames[setName] = struct{}{}
	return
}

// createNftSet creates new Nftables set
func createNftSet(setName string, dataType nftables.SetDatatype) (err error) {
	conn := nftables.Conn{}

	table := &nftables.Table{
		Name:   tableName,
		Family: nftables.TableFamilyINet,
	}
	set := &nftables.Set{
		Table:   table,
		Name:    setName,
		KeyType: dataType,
	}

	if err = conn.AddSet(set, nil); err != nil {
		return fmt.Errorf("failed to add set: %w", err)
	}
	if err = conn.Flush(); err != nil {
		return fmt.Errorf("failed to save set: %w", err)
	}

	return nil
}

// updateNftSet adds/deletes elements from Nftables set
func updateNftSet(
	newIPs, deletedIPs []nftables.SetElement,
	setName string,
	dataType nftables.SetDatatype,
) error {
	conn := nftables.Conn{}

	table := &nftables.Table{
		Name:   tableName,
		Family: nftables.TableFamilyINet,
	}
	set := &nftables.Set{
		Table:   table,
		Name:    setName,
		KeyType: dataType,
	}

	if err := conn.SetAddElements(set, newIPs); err != nil {
		return fmt.Errorf("failed to add set elements: %w", err)
	}
	if err := conn.SetDeleteElements(set, deletedIPs); err != nil {
		return fmt.Errorf("failed to delete set elements: %w", err)

	}

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("failed to save changes to set: %w", err)
	}
	return nil
}
