package dns

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/metal-stack/metal-networker/pkg/netconf"

	firewallv1 "github.com/metal-stack/firewall-controller/v2/api/v1"

	"github.com/go-logr/logr"
	dnsgo "github.com/miekg/dns"

	"github.com/metal-stack/firewall-controller/v2/pkg/network"
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

func NewDNSProxy(dns string, port *uint, log logr.Logger) (*DNSProxy, error) {
	if dns == "" {
		dns = defaultDNSServerAddr
	}
	cache := newDNSCache(dns, true, false, log.WithName("DNS cache"))
	handler := NewDNSProxyHandler(log, cache)

	host, err := getHost()
	if err != nil {
		return nil, err
	}

	p := defaultDNSPort
	if port != nil {
		p = *port
	}
	udpConn, tcpListener, err := bindToPort(host, int(p), log) // nolint:gosec
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
func (p *DNSProxy) Run(ctx context.Context) {
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

	if err := p.udpServer.ShutdownContext(ctx); err != nil {
		p.log.Error(err, "failed to shut down UDP server")
	}
	if err := p.tcpServer.ShutdownContext(ctx); err != nil {
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

func (p *DNSProxy) GetSetsForFQDN(fqdn firewallv1.FQDNSelector, fqdnSets []firewallv1.IPSet) (result []firewallv1.IPSet) {
	return p.cache.getSetsForFQDN(fqdn, fqdnSets)
}

func (p *DNSProxy) IsInitialized() bool {
	return p != nil
}

func (p *DNSProxy) CacheAddr() (string, error) {
	return getHost()
}

func getHost() (string, error) {
	c, err := netconf.New(network.GetLogger(), network.MetalNetworkerConfig)
	if err != nil || c == nil {
		return "", fmt.Errorf("failed to init networker config: %w", err)
	}

	defaultNetwork := c.GetDefaultRouteNetwork()
	if defaultNetwork == nil || len(defaultNetwork.Ips) < 1 {
		return "", fmt.Errorf("failed to retrieve host IP for DNS Proxy")
	}

	return defaultNetwork.Ips[0], nil
}

// bindToPort attempts to bind to port for both UDP and TCP
func bindToPort(host string, port int, log logr.Logger) (*net.UDPConn, *net.TCPListener, error) {
	var (
		err      error
		listener net.Listener
		conn     net.PacketConn
	)

	bindAddr := net.JoinHostPort(host, strconv.Itoa(port))

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
