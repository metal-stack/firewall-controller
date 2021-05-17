package dns

import (
	"fmt"
	"net"
	"strconv"

	"github.com/go-logr/logr"
	dnsgo "github.com/miekg/dns"
)

const ()

type DNSHandler interface {
	ServeDNS(w dnsgo.ResponseWriter, r *dnsgo.Msg)
	UpdateDNSServerAddr(addr string)
}

type DNSProxy struct {
	log   logr.Logger
	cache *DNSCache

	udpServer *dnsgo.Server
	tcpServer *dnsgo.Server

	handler DNSHandler
}

func NewDNSProxy(host string, port uint, log logr.Logger, cache *DNSCache) (*DNSProxy, error) {
	handler := NewDNSProxyHandler(log, cache)
	udpConn, tcpListener, err := bindToPort(host, port, log)
	if err != nil {
		return nil, fmt.Errorf("failed to bind to port: %w", err)
	}

	udpServer := &dnsgo.Server{PacketConn: udpConn, Addr: udpConn.LocalAddr().String(), Net: "udp", Handler: handler}
	tcpServer := &dnsgo.Server{Listener: tcpListener, Addr: udpConn.LocalAddr().String(), Net: "tcp", Handler: handler}

	return &DNSProxy{
		log:   log,
		cache: cache,

		udpServer: udpServer,
		tcpServer: tcpServer,

		handler: handler,
	}, nil
}

// Run starts TCP/UDP servers
func (p *DNSProxy) Run(stopCh <-chan struct{}) {
	go func() {
		p.log.Info("starting UDP server")
		if err := p.udpServer.ActivateAndServe(); err != nil {
			p.log.Error(err, "failed to start UDP server")
		}
	}()

	go func() {
		p.log.Info("starting TCP server")
		if err := p.tcpServer.ActivateAndServe(); err != nil {
			p.log.Error(err, "failed to start TCP server")
		}
	}()

	<-stopCh

	if err := p.udpServer.Shutdown(); err != nil {
		p.log.Error(err, "failed to shut down UDP server")
	}
	if err := p.tcpServer.Shutdown(); err != nil {
		p.log.Error(err, "failed to shut down TCP server")
	}
}

func (p *DNSProxy) UpdateDNSServerAddr(addr string) {
	p.handler.UpdateDNSServerAddr(addr)
	p.cache.UpdateDNSServerAddr(addr)
}

// bindToPort attempts to bind to port for both UDP and TCP
func bindToPort(host string, port uint, log logr.Logger) (*net.UDPConn, *net.TCPListener, error) {
	var err error
	var listener net.Listener
	var conn net.PacketConn

	bindAddr := net.JoinHostPort(host, strconv.Itoa(int(port)))

	defer func() {
		if err != nil {
			if listener != nil {
				listener.Close()
			}
			if conn != nil {
				conn.Close()
			}
		}
	}()

	listener, err = net.Listen("tcp", bindAddr)
	if err != nil {
		return nil, nil, err
	}

	conn, err = net.ListenPacket("udp", listener.Addr().String())
	if err != nil {
		return nil, nil, err
	}

	log.Info("DNS proxy bound to address", "address", bindAddr)

	return conn.(*net.UDPConn), listener.(*net.TCPListener), nil
}
