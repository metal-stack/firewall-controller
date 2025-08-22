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
		dnsServerAddr: cache.dnsServerAddr,
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

	serverAddress := w.LocalAddr()
	bufsize := getBufSize(serverAddress.Network(), request)
	scopedLog.Info("started processing request", "server", serverAddress, "bufsize", bufsize, "request", request)

	response, err := h.getDataFromDNS(serverAddress, request)
	if err != nil {
		scopedLog.Error(err, "failed to get DNS response")
		err = w.WriteMsg(refusedMsg(request))
		return
	}

	originalResponse := response.Copy()
	/*
		Why are we truncating the answer?
		DNS has a feature where a DNS server can "compress" the names in a message, and will usually do this if the reply will not fit in the maximum payload length for a DNS packet; for more explanation see here: https://datatracker.ietf.org/doc/html/rfc1035#autoid-44
		Unfortunately, in dnsgo the compression status of a message is apparently not retained, so if you take a compressed message and write it out again your wind up with a bigger message, without any checks whether the resulting message is too big for the receiver. If this happens, it breaks name resolution.
		Therefore we find out the buffer size of the client from the request (with UDP it's 512 bytes by default) and limit the reply to this buffer size before we send it out. The Truncate method will try compression first to fit the message into the buffer size and will truncate the message if necessary.
	*/
	response.Truncate(bufsize)
	scopedLog.Info("processing response", "buffer size", bufsize, "original response", originalResponse, "truncated response", response)

	go h.updateCache(time.Now(), response)

	err = w.WriteMsg(response)
}

func getBufSize(protocol string, request *dnsgo.Msg) int {
	if request.Extra != nil {
		for _, rr := range request.Extra {
			switch r := rr.(type) {
			case *dnsgo.OPT:
				return int(r.UDPSize())
			}
		}
	}

	if protocol == "tcp" {
		return dnsgo.MaxMsgSize
	}
	return dnsgo.MinMsgSize
}

// UpdateDNSServerAddr validates and if successful updates DNS server address
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
			var qname string
			if len(response.Question) > 0 {
				qname = strings.ToLower(response.Question[0].Name)
			}
			log.V(4).Info("DEBUG dnsproxyhandler function getUpdateCacheFunc updating DNS cache", "queried name", qname, "dns response", response)
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
