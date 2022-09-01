package dns

import (
	"fmt"
	"net"
	"strconv"

	firewallv1 "github.com/metal-stack/firewall-controller/api/v1"

	"github.com/go-logr/logr"
	dnsgo "github.com/miekg/dns"

	"github.com/metal-stack/firewall-controller/pkg/network"
)

const (
	defaultDNSPort uint = 53
)

type DNSHandler interface {
	ServeDNS(w dnsgo.ResponseWriter, r *dnsgo.Msg)
	UpdateDNSServerAddr(addr string) error
}

type DNSProxy struct {
	log    logr.Logger
	cache  *DNSCache
	stopCh chan struct{}

	udpServer *dnsgo.Server
	tcpServer *dnsgo.Server

	handler DNSHandler
}

func NewDNSProxy(port *uint, log logr.Logger) (*DNSProxy, error) {
	cache := newDNSCache(true, false, log.WithName("DNS cache"))
	handler := NewDNSProxyHandler(log, cache)

	host, err := getHost()
	if err != nil {
		return nil, err
	}

	p := defaultDNSPort
	if port != nil {
		p = *port
	}
	udpConn, tcpListener, err := bindToPort(host, p, log)
	if err != nil {
		return nil, fmt.Errorf("failed to bind to port: %w", err)
	}

	udpServer := &dnsgo.Server{PacketConn: udpConn, Addr: udpConn.LocalAddr().String(), Net: "udp", Handler: handler}
	tcpServer := &dnsgo.Server{Listener: tcpListener, Addr: udpConn.LocalAddr().String(), Net: "tcp", Handler: handler}

	return &DNSProxy{
		log:    log,
		cache:  cache,
		stopCh: make(chan struct{}),

		udpServer: udpServer,
		tcpServer: tcpServer,

		handler: handler,
	}, nil
}

// Run starts TCP/UDP servers
func (p *DNSProxy) Run() {
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

	<-p.stopCh

	if err := p.udpServer.Shutdown(); err != nil {
		p.log.Error(err, "failed to shut down UDP server")
	}
	if err := p.tcpServer.Shutdown(); err != nil {
		p.log.Error(err, "failed to shut down TCP server")
	}
}

// Stop starts TCP/UDP servers
func (p *DNSProxy) Stop() {
	close(p.stopCh)
}

func (p *DNSProxy) UpdateDNSServerAddr(addr string) error {
	if err := p.handler.UpdateDNSServerAddr(addr); err != nil {
		return fmt.Errorf("failed to update DNS server address: %w", err)
	}
	p.cache.updateDNSServerAddr(addr)

	return nil
}

func (p *DNSProxy) GetSetsForRendering(fqdns []firewallv1.FQDNSelector) (result []RenderIPSet) {
	return p.cache.getSetsForRendering(fqdns)
}

func (p *DNSProxy) GetSetsForFQDN(fqdn firewallv1.FQDNSelector, update bool) (result []firewallv1.IPSet) {
	return p.cache.getSetsForFQDN(fqdn, update)
}

func getHost() (string, error) {
	kb := network.GetKnowledgeBase()
	defaultNetwork := kb.GetDefaultRouteNetwork()

	if defaultNetwork == nil || len(defaultNetwork.Ips) < 1 {
		return "", fmt.Errorf("failed to retrieve host IP for DNS Proxy")
	}

	return defaultNetwork.Ips[0], nil
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
