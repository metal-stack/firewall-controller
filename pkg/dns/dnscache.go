package dns

import (
	"crypto/md5" //nolint:gosec
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/go-logr/logr"
	"github.com/google/nftables"
	dnsgo "github.com/miekg/dns"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	firewallv1 "github.com/metal-stack/firewall-controller/v2/api/v1"
)

type IPVersion string

const (
	tableName = "firewall"

	// Versions specifically for nftables rendering purposes
	IPv4 IPVersion = "ipv4_addr"
	IPv6 IPVersion = "ipv6_addr"

	// How many DNS redirections (CNAME/DNAME) are followed, to break up redirection loops.
	maxDNSRedirects = 10
)

// RenderIPSet stores set info for rendering
type RenderIPSet struct {
	SetName string    `json:"setName,omitempty"`
	IPs     []string  `json:"ips,omitempty"`
	Version IPVersion `json:"version,omitempty"`
}

type ipEntry struct {
	ips            []string
	expirationTime time.Time
	setName        string
}

func newIPEntry(setName string, expirationTime time.Time) *ipEntry {
	return &ipEntry{
		expirationTime: expirationTime,
		setName:        setName,
	}
}

func (e *ipEntry) update(setName string, ips []net.IP, expirationTime time.Time, dtype nftables.SetDatatype) error {
	newIPs, deletedIPs := e.getNewAndDeletedIPs(ips)
	if !e.expirationTime.After(time.Now()) {
		e.expirationTime = expirationTime
	}

	if newIPs != nil || deletedIPs != nil {
		e.ips = make([]string, len(ips))
		for i, ip := range ips {
			e.ips[i] = ip.String()
		}
		sort.Strings(e.ips)

		if err := updateNftSet(newIPs, deletedIPs, setName, dtype); err != nil {
			return fmt.Errorf("failed to update nft set: %w", err)
		}
	}

	return nil
}

func (e *ipEntry) getNewAndDeletedIPs(ips []net.IP) (newIPs, deletedIPs []nftables.SetElement) {
	currentIps := make(map[string]bool, len(e.ips))
	for _, ip := range e.ips {
		currentIps[ip] = false
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

	log           logr.Logger
	fqdnToEntry   map[string]cacheEntry
	setNames      map[string]struct{}
	dnsServerAddr string
	ipv4Enabled   bool
	ipv6Enabled   bool
}

func newDNSCache(dns string, ipv4Enabled, ipv6Enabled bool, log logr.Logger) *DNSCache {
	return &DNSCache{
		log:           log,
		fqdnToEntry:   map[string]cacheEntry{},
		setNames:      map[string]struct{}{},
		dnsServerAddr: dns,
		ipv4Enabled:   ipv4Enabled,
		ipv6Enabled:   ipv6Enabled,
	}
}

// getSetsForFQDN returns sets for FQDN selector
func (c *DNSCache) getSetsForFQDN(fqdn firewallv1.FQDNSelector, fqdnSets []firewallv1.IPSet) (result []firewallv1.IPSet) {
	c.restoreSets(fqdnSets)

	sets := map[string]firewallv1.IPSet{}
	if fqdn.MatchName != "" {
		for _, s := range c.getSetNameForFQDN(fqdn.GetMatchName()) {
			sets[s.SetName] = s
		}

	} else if fqdn.MatchPattern != "" {
		for _, s := range c.getSetNameForRegex(fqdn.GetRegex()) {
			sets[s.SetName] = s
		}
	}

	result = make([]firewallv1.IPSet, 0, len(sets))
	for _, s := range sets {
		result = append(result, s)
	}

	c.log.WithValues("fqdn", fqdn, "sets", result).Info("sets for FQDN")
	return
}

func (c *DNSCache) getSetsForRendering(fqdns []firewallv1.FQDNSelector) (result []RenderIPSet) {
	for n, e := range c.fqdnToEntry {
		var matched bool
		for _, fqdn := range fqdns {
			if fqdn.MatchName != "" {
				if fqdn.GetMatchName() == n {
					matched = true
					break
				}
			} else if fqdn.MatchPattern != "" {
				if m, _ := regexp.MatchString(fqdn.GetRegex(), n); m {
					matched = true
					break
				}
			}
		}
		if matched {
			if e.ipv4 != nil {
				result = append(result, createRenderIPSetFromIPEntry(IPv4, e.ipv4))
			}
			if e.ipv6 != nil {
				result = append(result, createRenderIPSetFromIPEntry(IPv6, e.ipv6))
			}
		}
	}

	return
}

func (c *DNSCache) updateDNSServerAddr(addr string) {
	c.dnsServerAddr = addr
}

// restoreSets add missing sets from FQDNSelector.Sets
func (c *DNSCache) restoreSets(fqdnSets []firewallv1.IPSet) {
	for _, s := range fqdnSets {
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
}

// getSetNameForFQDN returns FQDN set data
func (c *DNSCache) getSetNameForFQDN(fqdn string) (result []firewallv1.IPSet) {
	c.RLock()
	entry, found := c.fqdnToEntry[fqdn]

	if !found {
		c.RUnlock()
		if err := c.loadDataFromDNSServer([]string{fqdn}); err != nil {
			c.log.Error(err, "failed to load data for FQDN")
			return nil
		}

		c.RLock()
		if entry, found = c.fqdnToEntry[fqdn]; !found {
			c.log.Error(nil, "failed to find DNS entry for FQDN")
			c.RUnlock()
			return nil
		}
	}
	defer c.RUnlock()

	if entry.ipv4 != nil {
		result = append(result, createIPSetFromIPEntry(fqdn, firewallv1.IPv4, entry.ipv4))
	}
	if entry.ipv6 != nil {
		result = append(result, createIPSetFromIPEntry(fqdn, firewallv1.IPv6, entry.ipv6))
	}
	return
}

func (c *DNSCache) loadDataFromDNSServer(fqdns []string) error {
	c.log.V(4).Info("DEBUG dnscache loadDataFromDNSServer function called", "fqdns", fqdns)
	if len(fqdns) == 0 {
		return fmt.Errorf("no fqdn given")
	}
	if len(fqdns) > maxDNSRedirects+1 {
		return fmt.Errorf("too many hops, fqdn chain: %s", strings.Join(fqdns, ","))
	}
	qname := fqdns[len(fqdns)-1]
	cl := new(dnsgo.Client)
	for _, t := range []uint16{dnsgo.TypeA, dnsgo.TypeAAAA} {
		m := new(dnsgo.Msg)
		m.Id = dnsgo.Id()
		m.SetQuestion(qname, t)
		c.log.V(4).Info("DEBUG dnscache loadDataFromDNSServer function querying DNS", "message", m)
		in, _, err := cl.Exchange(m, c.dnsServerAddr)
		if err != nil {
			return fmt.Errorf("failed to get DNS data about fqdn %s: %w", fqdns[0], err)
		}
		c.log.V(4).Info("DEBUG dnscache loadDataFromDNSServer function calling Update function", "answer", in, "fqdns", fqdns)
		if _, err = c.Update(time.Now(), qname, in, fqdns); err != nil {
			return fmt.Errorf("failed to update DNS data for fqdn %s: %w", fqdns[0], err)
		}
	}

	return nil
}

// getSetNameForRegex returns list of FQDN set data that match provided regex
func (c *DNSCache) getSetNameForRegex(regex string) (sets []firewallv1.IPSet) {
	c.RLock()
	defer c.RUnlock()

	for n, e := range c.fqdnToEntry {
		if matched, _ := regexp.MatchString(regex, n); !matched {
			continue
		}

		if e.ipv4 != nil {
			sets = append(sets, createIPSetFromIPEntry(n, firewallv1.IPv4, e.ipv4))
		}
		if e.ipv6 != nil {
			sets = append(sets, createIPSetFromIPEntry(n, firewallv1.IPv6, e.ipv6))
		}
	}

	return
}

// Update DNS cache.
// It expects that there was only one question to DNS(majority of cases).
// So it picks first qname and skips all others(if there is).
func (c *DNSCache) Update(lookupTime time.Time, qname string, msg *dnsgo.Msg, fqdnsfield ...[]string) (bool, error) {
	c.log.V(4).Info("DEBUG dnscache Update function called", "Message", msg, "fqdnsfield", fqdnsfield)

	fqdns := []string{}
	if len(fqdnsfield) == 0 {
		fqdns = append(fqdns, qname)
		c.log.V(4).Info("DEBUG dnscache Update function not called with fqdnsfield parameter", "fqdns", fqdns)
	} else {
		fqdns = fqdnsfield[0]
		c.log.V(4).Info("DEBUG dnscache Update function called with fqdnsfield parameter", "fqdns", fqdns)
	}
	if len(fqdns) > maxDNSRedirects+1 {
		return true, fmt.Errorf("too many hops, fqdn chain: %s", strings.Join(fqdns, ","))
	}

	ipv4 := []net.IP{}
	ipv6 := []net.IP{}
	minIPv4TTL := uint32(math.MaxUint32)
	minIPv6TTL := uint32(math.MaxUint32)
	found := false

	for _, ans := range msg.Answer {
		c.log.V(4).Info("DEBUG dnscache Update function", "considering DNS answer", ans)
		if strings.ToLower(ans.Header().Name) != qname {
			c.log.V(4).Info("DEBUG dnscache Update function name does not match our query, continuing", "name", strings.ToLower(ans.Header().Name), "qname", qname)
			continue
		}

		switch rr := ans.(type) {
		case *dnsgo.A:
			ipv4 = append(ipv4, rr.A)
			if minIPv4TTL > rr.Hdr.Ttl {
				minIPv4TTL = rr.Hdr.Ttl
			}
			found = true
			c.log.V(4).Info("DEBUG dnscache Update function A record found", "IPs", ipv4)
		case *dnsgo.AAAA:
			ipv6 = append(ipv6, rr.AAAA)
			if minIPv6TTL > rr.Hdr.Ttl {
				minIPv6TTL = rr.Hdr.Ttl
			}
			found = true
			c.log.V(4).Info("DEBUG dnscache Update function AAAA record found", "IPs", ipv6)
		case *dnsgo.CNAME:
			c.log.V(4).Info("DEBUG dnscache Update function CNAME record found. Looking for resolution in same DNS reply", "CNAME", rr.Target, "fqdns slice", append(fqdns, rr.Target))
			stop, err := c.Update(lookupTime, rr.Target, msg, append(fqdns, rr.Target))
			if err != nil {
				return found, fmt.Errorf("error while trying to resolve CNAME %s within the same DNS reply: %w", rr.Target, err)
			}
			if stop {
				return true, nil
			}
			c.log.V(4).Info("DEBUG dnscache Update function CNAME record found, could not resolve in same DNS reply. Performing DNS lookup", "CNAME", rr.Target, "fqdns slice", append(fqdns, rr.Target))
			err = c.loadDataFromDNSServer(append(fqdns, rr.Target))
			if err != nil {
				return true, fmt.Errorf("could not look up address for CNAME %s: %w", rr.Target, err)
			}
			return true, nil
		default:
			continue
		}
	}

	for _, fqdn := range fqdns {
		c.log.V(4).Info("DEBUG dnscache Update function Updating DNS cache for", "fqdn", fqdn, "ipv4", ipv4, "ipv6", ipv6)
		if c.ipv4Enabled && len(ipv4) > 0 {
			if err := c.updateIPEntry(fqdn, ipv4, lookupTime.Add(time.Duration(minIPv4TTL)), nftables.TypeIPAddr); err != nil {
				return false, fmt.Errorf("failed to update IPv4 addresses: %w", err)
			}
		}
		if c.ipv6Enabled && len(ipv6) > 0 {
			if err := c.updateIPEntry(fqdn, ipv6, lookupTime.Add(time.Duration(minIPv6TTL)), nftables.TypeIP6Addr); err != nil {
				return false, fmt.Errorf("failed to update IPv6 addresses: %w", err)
			}
		}
	}

	return found, nil
}

func (c *DNSCache) updateIPEntry(qname string, ips []net.IP, expirationTime time.Time, dtype nftables.SetDatatype) error {
	scopedLog := c.log.WithValues(
		"fqdn", qname,
		"ip_len", len(ips),
		"dtype", dtype.Name,
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
			setName := c.createSetName(qname, dtype.Name, 0)
			ipe = newIPEntry(setName, expirationTime)
			entry.ipv4 = ipe
		}
		ipe = entry.ipv4
	case nftables.TypeIP6Addr:
		if entry.ipv6 == nil {
			setName := c.createSetName(qname, dtype.Name, 0)
			ipe = newIPEntry(setName, expirationTime)
			entry.ipv6 = ipe
		}
		ipe = entry.ipv6
	}

	setName := ipe.setName
	if err := ipe.update(setName, ips, expirationTime, dtype); err != nil {
		return fmt.Errorf("failed to update ipEntry: %w", err)
	}
	c.fqdnToEntry[qname] = entry

	scopedLog.WithValues("set", setName).Info("added new IP entry")
	return nil
}

func (c *DNSCache) createSetName(qname, dataType string, suffix int) (setName string) {
	md5Hash := md5.Sum([]byte(qname + dataType)) //nolint:gosec
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

	// Skip if set doesn't exist
	if s, err := conn.GetSetByName(table, setName); s == nil || err != nil {
		return nil //nolint:nilerr
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

func createIPSetFromIPEntry(fqdn string, version firewallv1.IPVersion, entry *ipEntry) firewallv1.IPSet {
	return firewallv1.IPSet{
		FQDN:           fqdn,
		SetName:        entry.setName,
		IPs:            entry.ips,
		ExpirationTime: metav1.Time{Time: entry.expirationTime},
		Version:        version,
	}
}

func createRenderIPSetFromIPEntry(version IPVersion, entry *ipEntry) RenderIPSet {
	return RenderIPSet{
		SetName: entry.setName,
		IPs:     entry.ips,
		Version: version,
	}
}
