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
	UpdateDNSAddr(addr string)
}

type DNSProxy struct {
	log     logr.Logger
	host    string
	port    uint
	cache   *DNSCache
	handler DNSHandler
}

func NewDNSProxy(host string, port uint, log logr.Logger, cache *DNSCache) *DNSProxy {
	return &DNSProxy{
		log:     log,
		host:    host,
		port:    port,
		cache:   cache,
		handler: NewDNSProxyHandler(log, cache),
	}
}

func (p *DNSProxy) Run(stopCh <-chan struct{}) error {
	// Start DNS servers
	udpConn, tcpListener, err := p.bindToPort()
	if err != nil {
		return fmt.Errorf("failed to bind to port: %w", err)
	}

	udpServer := &dnsgo.Server{PacketConn: udpConn, Addr: udpConn.LocalAddr().String(), Net: "udp", Handler: p.handler}
	go func() {
		p.log.Info("starting UDP server")
		if err := udpServer.ActivateAndServe(); err != nil {
			p.log.Error(err, "failed to start UDP server")
		}
	}()

	tcpServer := &dnsgo.Server{Listener: tcpListener, Addr: udpConn.LocalAddr().String(), Net: "tcp", Handler: p.handler}
	go func() {
		p.log.Info("starting TCP server")
		if err := tcpServer.ActivateAndServe(); err != nil {
			p.log.Error(err, "failed to start TCP server")
		}
	}()

	<-stopCh

	udpServer.Shutdown()
	tcpServer.Shutdown()

	return nil
}

func (p *DNSProxy) UpdateDNSAddr(addr string) {
	p.handler.UpdateDNSAddr(addr)
}

// bindToPort attempts to bind to port for both UDP and TCP
func (p *DNSProxy) bindToPort() (*net.UDPConn, *net.TCPListener, error) {
	var err error
	var listener net.Listener
	var conn net.PacketConn

	bindAddr := net.JoinHostPort(p.host, strconv.Itoa(int(p.port)))

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

	p.log.Info("DNS proxy bound to address", "address", bindAddr)

	return conn.(*net.UDPConn), listener.(*net.TCPListener), nil
}
