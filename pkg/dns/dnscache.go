package dns

import (
	"context"
	"crypto/md5" //nolint:gosec
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/go-logr/logr"
	"github.com/google/nftables"
	dnsgo "github.com/miekg/dns"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

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

	// Configmap that holds the FQDN state
	fqdnStateConfigmapName = "fqdnstate"
	fqdnStateNamespace     = "firewall"
	fqdnStateConfigmapKey  = "state"
)

// RenderIPSet stores set info for rendering
type RenderIPSet struct {
	SetName string    `json:"setName,omitempty"`
	IPs     []string  `json:"ips,omitempty"`
	Version IPVersion `json:"version,omitempty"`
}

type IPEntry struct {
	// ips is a map of the ip address and its expiration time which is the time of the DNS lookup + the TTL
	IPs     map[string]time.Time `json:"ips,omitempty"`
	SetName string               `json:"setName,omitempty"`
}

func newIPEntry(setName string) *IPEntry {
	return &IPEntry{
		SetName: setName,
		IPs:     map[string]time.Time{},
	}
}

func (e *IPEntry) update(log logr.Logger, setName string, rrs []dnsgo.RR, lookupTime time.Time, dtype nftables.SetDatatype) error {
	deletedIPs := e.expireIPs()
	newIPs := e.addAndUpdateIPs(log, rrs, lookupTime)

	if newIPs != nil || deletedIPs != nil {
		if err := updateNftSet(newIPs, deletedIPs, setName, dtype); err != nil {
			return fmt.Errorf("failed to update nft set: %w", err)
		}
	}

	return nil
}

func (e *IPEntry) expireIPs() (deletedIPs []nftables.SetElement) {
	for ip, expirationTime := range e.IPs {
		if expirationTime.Before(time.Now()) {
			deletedIPs = append(deletedIPs, nftables.SetElement{Key: []byte(ip)})
			delete(e.IPs, ip)
		}
	}
	return
}

func (e *IPEntry) addAndUpdateIPs(log logr.Logger, rrs []dnsgo.RR, lookupTime time.Time) (newIPs []nftables.SetElement) {
	for _, rr := range rrs {
		var s string
		switch r := rr.(type) {
		case *dnsgo.A:
			s = r.A.String()
		case *dnsgo.AAAA:
			s = r.AAAA.String()
		}
		if _, ok := e.IPs[s]; ok {
			newIPs = append(newIPs, nftables.SetElement{Key: []byte(s)})
		}
		log.WithValues("ip", s, "rr header ttl", rr.Header().Ttl, "expiration time", lookupTime.Add(time.Duration(rr.Header().Ttl)*time.Second))
		e.IPs[s] = lookupTime.Add(time.Duration(rr.Header().Ttl) * time.Second)

	}
	return
}

type CacheEntry struct {
	IPv4 *IPEntry `json:"ipv4,omitempty"`
	IPv6 *IPEntry `json:"ipv6,omitempty"`
}

type DNSCache struct {
	sync.RWMutex

	log           logr.Logger
	fqdnToEntry   map[string]CacheEntry
	setNames      map[string]struct{}
	dnsServerAddr string
	shootClient   client.Client
	ctx           context.Context
	ipv4Enabled   bool
	ipv6Enabled   bool
}

func newDNSCache(ctx context.Context, dns string, ipv4Enabled, ipv6Enabled bool, shootClient client.Client, log logr.Logger) (*DNSCache, error) {
	c := DNSCache{
		log:           log,
		fqdnToEntry:   map[string]CacheEntry{},
		setNames:      map[string]struct{}{},
		dnsServerAddr: dns,
		shootClient:   shootClient,
		ipv4Enabled:   ipv4Enabled,
		ipv6Enabled:   ipv6Enabled,
	}

	nn := types.NamespacedName{Name: fqdnStateConfigmapName, Namespace: fqdnStateNamespace}
	scm := &v1.ConfigMap{}

	err := shootClient.Get(ctx, nn, scm)
	if err != nil && !apierrors.IsNotFound(err) {
		c.log.V(4).Info("DEBUG error reading fqndstate configmap")
		return nil, err
	}
	if scm.Data == nil {
		c.log.V(4).Info("DEBUG cm contains no data", "cm", scm)
		return &c, nil

	}
	if scm.Data[fqdnStateConfigmapKey] == "" {
		c.log.V(4).Info("DEBUG cm does not contain the right key", "cm", scm, "key", fqdnStateConfigmapKey)
		return &c, nil

	}
	err = json.Unmarshal([]byte(scm.Data[fqdnStateConfigmapKey]), &c.fqdnToEntry)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// writeStateToConfigmap writes the whole DNS cache to the state configmap
func (c *DNSCache) writeStateToConfigmap() error {
	s, err := json.Marshal(c.fqdnToEntry)
	if err != nil {
		return err
	}
	if s == nil {
		return nil
	}
	c.log.V(4).Info("DEBUG writing cache to configmap", "fqdnToEntry", s)

	// debugging: Try to read, create, update simple configmap.
	dnn := types.NamespacedName{Name: "dcm", Namespace: fqdnStateNamespace}
	cdcm := v1.ConfigMap{}

	dcm := v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dcm",
			Namespace: fqdnStateNamespace,
		},
		Data: map[string]string{
			"testkey": "testvalue",
		},
	}

	c.log.V(4).Info("DEBUG looking for debug configmap", "namespacedname", dnn)
	err = c.shootClient.Get(c.ctx, dnn, &cdcm)
	if err != nil && !apierrors.IsNotFound(err) {
		c.log.V(4).Info("DEBUG error reading debug configmap", "namespacedname", dnn, "error", err)
		return err
	}

	if apierrors.IsNotFound(err) {
		c.log.V(4).Info("DEBUG debug configmap not found, trying to create", "namespacedname", dnn)
		err = c.shootClient.Create(c.ctx, &dcm)
		if err != nil {
			c.log.V(4).Info("DEBUG error creating debug configmap", "configmap", dcm, "error", err)
			return err
		}
	} else {
		c.log.V(4).Info("DEBUG debug configmap found, trying to update", "current configmap", cdcm, "configmap", dcm)
		err = c.shootClient.Update(c.ctx, &dcm)
		if err != nil {
			c.log.V(4).Info("DEBUG error updating debug configmap", "configmap", dcm, "error", err)
			return err
		}
	}

	// end debugging code

	nn := types.NamespacedName{Name: fqdnStateConfigmapName, Namespace: fqdnStateNamespace}
	meta := metav1.ObjectMeta{
		Name:      fqdnStateConfigmapName,
		Namespace: fqdnStateNamespace,
	}

	currentCm := &v1.ConfigMap{}
	cmData := map[string]string{}
	cmData[fqdnStateConfigmapKey] = string(s)
	scm := &v1.ConfigMap{
		ObjectMeta: meta,
		Data:       cmData,
	}

	c.log.V(4).Info("DEBUG looking for configmap", "namespacedname", nn)
	err = c.shootClient.Get(c.ctx, nn, currentCm)
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	if apierrors.IsNotFound(err) {
		c.log.V(4).Info("DEBUG configmap not found, trying to create configmap", "NamespacedName", nn, "configmap to create", scm)
		err = c.shootClient.Create(c.ctx, scm)
		if err != nil {
			return err
		}
	}

	c.log.V(4).Info("DEBUG trying to updatecm", "current cm", currentCm, "cm", scm)
	if !reflect.DeepEqual(currentCm.Data, scm.Data) {
		currentCm.Data = scm.Data
		err = c.shootClient.Update(c.ctx, currentCm)
		if err != nil {
			return err
		}
	}
	return nil
}

// getSetsForFQDN returns sets for FQDN selector
func (c *DNSCache) getSetsForFQDN(fqdn firewallv1.FQDNSelector, fqdnSets []firewallv1.IPSet) (result []firewallv1.IPSet) {
	// c.restoreSets(fqdnSets)

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

	c.log.WithValues("fqdn", fqdn, "fqdnSets", fqdnSets, "sets", result).Info("sets for FQDN")
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
			if e.IPv4 != nil {
				result = append(result, createRenderIPSetFromIPEntry(IPv4, e.IPv4))
			}
			if e.IPv6 != nil {
				result = append(result, createRenderIPSetFromIPEntry(IPv6, e.IPv6))
			}
		}
	}

	return
}

func (c *DNSCache) updateDNSServerAddr(addr string) {
	c.dnsServerAddr = addr
}

// restoreSets add missing sets from FQDNSelector.Sets
// func (c *DNSCache) restoreSets(fqdnSets []firewallv1.IPSet) {
// 	for _, s := range fqdnSets {
// 		// Add cache entries from fqdn.Sets if missing
// 		c.Lock()
// 		if _, ok := c.setNames[s.SetName]; !ok {
// 			c.setNames[s.SetName] = struct{}{}
// 			entry, exists := c.fqdnToEntry[s.FQDN]
// 			if !exists {
// 				entry = CacheEntry{}
// 			}
//
// 			ipe := &IPEntry{
// 				setName: s.SetName,
// 			}
// 			for _, ip := range s.IPs {
// 				ipa, _, _ := strings.Cut(ip, ",")
// 				expirationTime := time.Now()
// 				if _, ets, found := strings.Cut(ip, ": "); found {
// 					if err := expirationTime.UnmarshalText([]byte(ets)); err != nil {
// 						expirationTime = time.Now()
// 					}
// 				}
// 				ipe.IPs[ipa] = expirationTime
// 			}
// 			switch s.Version {
// 			case firewallv1.IPv4:
// 				entry.ipv4 = ipe
// 			case firewallv1.IPv6:
// 				entry.ipv6 = ipe
// 			}
//
// 			c.fqdnToEntry[s.FQDN] = entry
// 		}
// 		c.Unlock()
// 	}
// }

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

	if entry.IPv4 != nil {
		result = append(result, createIPSetFromIPEntry(fqdn, firewallv1.IPv4, entry.IPv4))
	}
	if entry.IPv6 != nil {
		result = append(result, createIPSetFromIPEntry(fqdn, firewallv1.IPv6, entry.IPv6))
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

		if e.IPv4 != nil {
			sets = append(sets, createIPSetFromIPEntry(n, firewallv1.IPv4, e.IPv4))
		}
		if e.IPv6 != nil {
			sets = append(sets, createIPSetFromIPEntry(n, firewallv1.IPv6, e.IPv6))
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

	ipv4 := []dnsgo.RR{}
	ipv6 := []dnsgo.RR{}
	found := false

	for _, ans := range msg.Answer {
		c.log.V(4).Info("DEBUG dnscache Update function", "considering DNS answer", ans)
		if strings.ToLower(ans.Header().Name) != qname {
			c.log.V(4).Info("DEBUG dnscache Update function name does not match our query, continuing", "name", strings.ToLower(ans.Header().Name), "qname", qname)
			continue
		}

		switch rr := ans.(type) {
		case *dnsgo.A:
			ipv4 = append(ipv4, rr)
			found = true
			c.log.V(4).Info("DEBUG dnscache Update function A record found", "IPs", ipv4)
		case *dnsgo.AAAA:
			ipv6 = append(ipv6, rr)
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

	ipEntriesUpdated := false

	for _, fqdn := range fqdns {
		c.log.V(4).Info("DEBUG dnscache Update function Updating DNS cache for", "fqdn", fqdn, "ipv4", ipv4, "ipv6", ipv6)
		if c.ipv4Enabled && len(ipv4) > 0 {
			if err := c.updateIPEntry(fqdn, ipv4, lookupTime, nftables.TypeIPAddr); err != nil {
				return false, fmt.Errorf("failed to update IPv4 addresses: %w", err)
			}
			ipEntriesUpdated = true
		}
		if c.ipv6Enabled && len(ipv6) > 0 {
			if err := c.updateIPEntry(fqdn, ipv6, lookupTime, nftables.TypeIP6Addr); err != nil {
				return false, fmt.Errorf("failed to update IPv6 addresses: %w", err)
			}
			ipEntriesUpdated = true
		}
	}

	if ipEntriesUpdated {
		if err := c.writeStateToConfigmap(); err != nil {
			c.log.V(4).Info("DEBUG could not write updated DNS cache to state configmap", "configmap", fqdnStateConfigmapName, "namespace", fqdnStateNamespace, "error", err)
		}
	}

	return found, nil
}

func (c *DNSCache) updateIPEntry(qname string, rrs []dnsgo.RR, lookupTime time.Time, dtype nftables.SetDatatype) error {
	scopedLog := c.log.WithValues(
		"fqdn", qname,
		"ip_len", len(rrs),
		"dtype", dtype.Name,
	)

	c.Lock()
	defer c.Unlock()

	entry, exists := c.fqdnToEntry[qname]
	if !exists {
		entry = CacheEntry{}
	}

	var ipe *IPEntry
	switch dtype {
	case nftables.TypeIPAddr:
		if entry.IPv4 == nil {
			setName := c.createSetName(qname, dtype.Name, 0)
			ipe = newIPEntry(setName)
			entry.IPv4 = ipe
		}
		ipe = entry.IPv4
	case nftables.TypeIP6Addr:
		if entry.IPv6 == nil {
			setName := c.createSetName(qname, dtype.Name, 0)
			ipe = newIPEntry(setName)
			entry.IPv6 = ipe
		}
		ipe = entry.IPv6
	}

	setName := ipe.SetName
	scopedLog.WithValues("set", setName, "lookupTime", lookupTime, "rrs", rrs).Info("updating ip entry")
	if err := ipe.update(scopedLog, setName, rrs, lookupTime, dtype); err != nil {
		return fmt.Errorf("failed to update IPEntry: %w", err)
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

func createIPSetFromIPEntry(fqdn string, version firewallv1.IPVersion, entry *IPEntry) firewallv1.IPSet {
	ips := firewallv1.IPSet{
		FQDN:    fqdn,
		SetName: entry.SetName,
		IPs:     []string{},
		Version: version,
	}
	for ip, expirationTime := range entry.IPs {
		if et, err := expirationTime.MarshalText(); err == nil {
			ip = ip + ", expiration time: " + string(et)
		}
		ips.IPs = append(ips.IPs, ip)
	}
	return ips
}

func createRenderIPSetFromIPEntry(version IPVersion, entry *IPEntry) RenderIPSet {
	var ips []string
	for ip, _ := range entry.IPs {
		ips = append(ips, ip)
	}
	return RenderIPSet{
		SetName: entry.SetName,
		IPs:     ips,
		Version: version,
	}
}
