package dns

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/google/nftables"
	dnsgo "github.com/miekg/dns"
)

const (
	tableName              = "firewall"
	allowedDNSCharsREGroup = "[-a-zA-Z0-9_]"
)

type ipEntry struct {
	ips            []net.IP
	expirationTime time.Time
	setName        string
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
	fqdnToEntry map[string]cacheEntry
	setNames    map[string]struct{}
}

// GetSetNameForFQDN returns set name for FQDN
func (c *DNSCache) GetSetNameForFQDN(fqdn string) (name string, found bool) {
	entry, found := c.fqdnToEntry[fqdn]
	if !found {
		return "", false
	}

	return entry.ipv4.setName, true
}

// GetSetNameForRegex returns list of IPs for FQDN that match provided regex
func (c *DNSCache) GetSetNameForPattern(pattern string) (sets []string) {
	regex := toRegexp(pattern)

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

	if err := c.updateIPV4Entry(qname, ipv4, lookupTime, time.Duration(minIPv4TTL)); err != nil {
		return fmt.Errorf("failed to update IPv4 addresses: %w", err)
	}
	if err := c.updateIPV6Entry(qname, ipv6, lookupTime, time.Duration(minIPv6TTL)); err != nil {
		return fmt.Errorf("failed to update IPv6 addresses: %w", err)
	}

	return nil
}

func (c *DNSCache) updateIPV4Entry(qname string, ips []net.IP, lookupTime time.Time, ttl time.Duration) error {
	var (
		setName string
		err     error
	)

	entry, exists := c.fqdnToEntry[qname]
	if !exists {
		entry = cacheEntry{}
	}

	if entry.ipv4 == nil {
		if setName, err = c.createNftSet(qname, nftables.TypeIPAddr); err != nil {
			return fmt.Errorf("failed to create nft set: %w", err)
		}
		entry.ipv4 = &ipEntry{
			expirationTime: lookupTime.Add(ttl),
			setName:        setName,
		}
	}

	newIPs, deletedIPs := entry.ipv4.getNewAndDeletedIPs(ips)
	if !entry.ipv4.expirationTime.After(time.Now()) {
		entry.ipv4.expirationTime = lookupTime.Add(ttl)
	}

	if newIPs != nil || deletedIPs != nil {
		entry.ipv4.ips = ips
		if err = c.updateNftSet(newIPs, deletedIPs, setName, nftables.TypeIPAddr); err != nil {
			return fmt.Errorf("failed to update nft set: %w", err)
		}
	}

	return nil
}

func (c *DNSCache) updateIPV6Entry(qname string, ips []net.IP, lookupTime time.Time, ttl time.Duration) error {
	var (
		setName string
		err     error
	)

	entry, exists := c.fqdnToEntry[qname]
	if !exists {
		entry = cacheEntry{}
	}

	if entry.ipv6 == nil {
		if setName, err = c.createNftSet(qname, nftables.TypeIP6Addr); err != nil {
			return fmt.Errorf("failed to create nft set: %w", err)
		}
		entry.ipv6 = &ipEntry{
			expirationTime: lookupTime.Add(ttl),
			setName:        setName,
		}
	}

	newIPs, deletedIPs := entry.ipv6.getNewAndDeletedIPs(ips)
	if !entry.ipv6.expirationTime.After(time.Now()) {
		entry.ipv6.expirationTime = lookupTime.Add(ttl)
	}

	if newIPs != nil || deletedIPs != nil {
		entry.ipv6.ips = ips
		if err = c.updateNftSet(newIPs, deletedIPs, setName, nftables.TypeIP6Addr); err != nil {
			return fmt.Errorf("failed to update nft set: %w", err)
		}
	}

	return nil
}

// createNftSet creates new Nftables set
func (c *DNSCache) createNftSet(qname string, dataType nftables.SetDatatype) (setName string, err error) {
	setName = c.createSetName(qname, dataType.Name, 0)
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
		return "", fmt.Errorf("failed to add set: %w", err)
	}
	if err = conn.Flush(); err != nil {
		return "", fmt.Errorf("failed to save set: %w", err)
	}

	return setName, nil
}

// updateNftSet adds/deletes elements from Nftables set
func (c *DNSCache) updateNftSet(
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

func (c *DNSCache) createSetName(qname, dataType string, suffix int) (setName string) {
	md5Hash := md5.Sum([]byte(qname + dataType))
	hex := hex.EncodeToString(md5Hash[:])

	for i, c := range hex {
		if !unicode.IsDigit(c) {
			setName = hex[i : i+16]
			break
		}
	}

	// Check that set name isn't taken already
	if _, ok := c.setNames[setName]; ok {
		setName = c.createSetName(qname, dataType, suffix+1)
	}

	c.setNames[setName] = struct{}{}
	return
}

// ToRegexp converts a pattern into a regexp string
func toRegexp(pattern string) string {
	pattern = strings.TrimSpace(pattern)
	pattern = strings.ToLower(pattern)

	// handle the * match-all case. This will filter down to the end.
	if pattern == "*" {
		return "(^(" + allowedDNSCharsREGroup + "+[.])+$)|(^[.]$)"
	}

	// base case. * becomes .*, but only for DNS valid characters
	// NOTE: this only works because the case above does not leave the *
	pattern = strings.Replace(pattern, "*", allowedDNSCharsREGroup+"*", -1)

	// base case. "." becomes a literal .
	pattern = strings.Replace(pattern, ".", "[.]", -1)

	// Anchor the match to require the whole string to match this expression
	return "^" + pattern + "$"
}
