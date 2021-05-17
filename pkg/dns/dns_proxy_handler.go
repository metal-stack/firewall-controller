package dns

import (
	"fmt"
	"net"
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

		scopedLog.Info("finished processing request")
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

func (h *DNSProxyHandler) UpdateDNSServerAddr(addr string) {
	h.dnsServerAddr = addr
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
			if err := cache.Update(lookupTime, response); err != nil {
				scopedLog.Error(err, "failed to update DNS cache")
			} else {
				scopedLog.Info("cache updated")
			}
		}
	}
}

func refusedMsg(req *dnsgo.Msg) (msg *dnsgo.Msg) {
	msg = new(dnsgo.Msg)
	msg.SetRcode(req, dnsgo.RcodeRefused)
	return
}
