package dns

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-logr/logr"
	dnsgo "github.com/miekg/dns"
)

const (
	queryLogField      = "query"
	clientAddrLogField = "client-addr"
	reqIdLogField      = "req-id"

	// dnsTimeout is the maximum time to wait for DNS responses to forwarded DNS requests
	dnsTimeout           = 10 * time.Second
	defaultDNSServerAddr = "8.8.8.8:53"
	testDNSRecord        = "*."
)

type DNSProxyHandler struct {
	log           logr.Logger
	udpClient     *dnsgo.Client
	tcpClient     *dnsgo.Client
	dnsServerAddr string
	updateCache   func(lookupTime time.Time, response *dnsgo.Msg)
}

func NewDNSProxyHandler(log logr.Logger, cache *DNSCache) *DNSProxyHandler {
	// Init DNS clients
	udpClient := &dnsgo.Client{Net: "udp", Timeout: dnsTimeout, SingleInflight: false}
	tcpClient := &dnsgo.Client{Net: "tcp", Timeout: dnsTimeout, SingleInflight: false}

	return &DNSProxyHandler{
		log:           log.WithName("DNS handler"),
		udpClient:     udpClient,
		tcpClient:     tcpClient,
		dnsServerAddr: defaultDNSServerAddr,
		updateCache:   getUpdateCacheFunc(log, cache),
	}
}

func (h *DNSProxyHandler) ServeDNS(w dnsgo.ResponseWriter, request *dnsgo.Msg) {
	scopedLog := h.log.WithValues(
		queryLogField, request.Question[0].Name,
		clientAddrLogField, w.RemoteAddr(),
		reqIdLogField, request.Id,
	)

	var err error
	defer func() {
		if err != nil {
			scopedLog.Error(err, "failed to send response")
		}
	}()

	scopedLog.Info("started processing request")
	response, err := h.getDataFromDNS(w.LocalAddr(), request)
	if err != nil {
		scopedLog.Error(err, "failed to get DNS response")
		err = w.WriteMsg(refusedMsg(request))
		return
	}

	go h.updateCache(time.Now(), response)
	err = w.WriteMsg(response)
}

// UpdateDNSServerAddr validates and if successfull updates DNS server address
func (h *DNSProxyHandler) UpdateDNSServerAddr(addr string) error {
	m := new(dnsgo.Msg)
	m.Id = dnsgo.Id()
	m.SetQuestion(testDNSRecord, dnsgo.TypeA)

	c := new(dnsgo.Client)
	_, _, err := c.Exchange(m, addr)
	if err != nil {
		return fmt.Errorf("new DNS server address not valid: %w", err)
	}

	h.dnsServerAddr = addr
	return nil
}

func (h *DNSProxyHandler) getDataFromDNS(addr net.Addr, request *dnsgo.Msg) (*dnsgo.Msg, error) {
	// Keep the same transport protocol
	var client *dnsgo.Client
	protocol := addr.Network()
	switch protocol {
	case "udp":
		client = h.udpClient
	case "tcp":
		client = h.tcpClient
	default:
		return nil, fmt.Errorf("failed to determine transport protocol: %s", protocol)
	}

	response, _, err := client.Exchange(request, h.dnsServerAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to call target DNS: %w", err)
	}

	return response, nil
}

func getUpdateCacheFunc(log logr.Logger, cache *DNSCache) func(lookupTime time.Time, response *dnsgo.Msg) {
	return func(lookupTime time.Time, response *dnsgo.Msg) {
		if response.Response && response.Rcode == dnsgo.RcodeSuccess {
			scopedLog := log.WithValues(reqIdLogField, response.Id)
			qname := strings.ToLower(response.Question[0].Name)
			log.Info("DEBUG dnsproxyhandler function getUpdateCacheFunc updating DNS cache", "queried name", qname, "dns response", response)
			if _, err := cache.Update(lookupTime, qname, response); err != nil {
				scopedLog.Error(err, "failed to update DNS cache")
			}
		}
	}
}

func refusedMsg(req *dnsgo.Msg) (msg *dnsgo.Msg) {
	msg = new(dnsgo.Msg)
	msg.SetRcode(req, dnsgo.RcodeRefused)
	return
}
