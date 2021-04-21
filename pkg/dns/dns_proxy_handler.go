package dns

import (
	"fmt"

	"github.com/miekg/dns"
	dnsgo "github.com/miekg/dns"
)

type DNSProxyHandler struct {
	udpClient *dnsgo.Client
	tcpClient *dnsgo.Client
}

func (h *DNSProxyHandler) ServeDNS(w dns.ResponseWriter, request *dns.Msg) {
	// Keep the same transport protocol
	var client *dns.Client
	protocol := w.LocalAddr().Network()
	switch protocol {
	case "udp":
		client = h.udpClient
	case "tcp":
		client = h.tcpClient
	default:
		fmt.Println("Failed to determine transport protocol")
		return
	}

	response, _, err := client.Exchange(request, "8.8.8.8:53")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(response.Answer[0])

	w.WriteMsg(response)
}
