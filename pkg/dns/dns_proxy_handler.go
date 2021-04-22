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
)

type DNSProxyHandler struct {
	log         logr.Logger
	udpClient   *dnsgo.Client
	tcpClient   *dnsgo.Client
	updateCache func(lookupTime time.Time, response *dnsgo.Msg)
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
	response, err := h.getFromTargetDNS(w.LocalAddr(), request)
	if err != nil {
		scopedLog.Error(err, "failed to get DNS response")
		err = w.WriteMsg(refusedMsg(request))
		return
	}

	go h.updateCache(time.Now(), response)
	err = w.WriteMsg(response)
}

func (h *DNSProxyHandler) getFromTargetDNS(addr net.Addr, request *dnsgo.Msg) (*dnsgo.Msg, error) {
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

	// targetDNSAddr, err := getTargetDNSAddr(addr)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to get target DNS address: %w", err)
	// }

	response, _, err := client.Exchange(request, "8.8.8.8:53") //targetDNSAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to call target DNS: %w", err)
	}

	return response, nil
}

// getTargetDNSAddr returns address of target DNS server
func getTargetDNSAddr(addr net.Addr) (string, error) {
	switch addr := (addr).(type) {
	case *net.UDPAddr, *net.TCPAddr:
		return addr.String(), nil
	default:
		return "", fmt.Errorf("unknown DNS address type %T: %+v", addr, addr)
	}
}

func refusedMsg(req *dnsgo.Msg) (msg *dnsgo.Msg) {
	msg = new(dnsgo.Msg)
	msg.SetRcode(req, dnsgo.RcodeRefused)
	return
}
