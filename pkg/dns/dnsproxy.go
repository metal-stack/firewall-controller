package dns

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	firewallv1 "github.com/metal-stack/firewall-controller/v2/api/v1"

	"github.com/go-logr/logr"
	dnsgo "github.com/miekg/dns"
)

const (
	defaultDNSPort uint = 53
)

type (
	DNSHandler interface {
		ServeDNS(w dnsgo.ResponseWriter, r *dnsgo.Msg)
		UpdateDNSServerAddr(addr string) error
	}

	DNSProxy struct {
		log        logr.Logger
		ctx        context.Context
		cancelFunc context.CancelFunc
		cache      *DNSCache

		udpServer *dnsgo.Server
		tcpServer *dnsgo.Server

		handler DNSHandler

		bindAddress string
	}

	DNSProxyConfig struct {
		DNSServer   string
		Port        *uint
		ShootClient client.Client
		Log         logr.Logger
		// BindAddress is the first ip of the defaultRouteNetwork
		BindAddress string
	}
)

func NewDNSProxy(ctx context.Context, cfg *DNSProxyConfig) (*DNSProxy, error) {
	if cfg.DNSServer == "" {
		cfg.DNSServer = defaultDNSServerAddr
	}

	p := defaultDNSPort
	if cfg.Port != nil {
		p = *cfg.Port
	}
	udpConn, tcpListener, err := bindToPort(cfg.BindAddress, int(p), cfg.Log) // nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("failed to bind to port: %w", err)
	}

	backgroundCtx, cancel := context.WithCancel(ctx)
	cache, err := newDNSCache(backgroundCtx, cfg.DNSServer, true, false, cfg.ShootClient, cfg.Log.WithName("DNS cache"))
	if err != nil {
		cancel()
		return nil, err
	}
	handler := NewDNSProxyHandler(cfg.Log, cache)

	udpServer := &dnsgo.Server{PacketConn: udpConn, Addr: udpConn.LocalAddr().String(), Net: "udp", Handler: handler}
	tcpServer := &dnsgo.Server{Listener: tcpListener, Addr: udpConn.LocalAddr().String(), Net: "tcp", Handler: handler}

	return &DNSProxy{
		log:        cfg.Log,
		ctx:        backgroundCtx,
		cancelFunc: cancel,
		cache:      cache,

		udpServer: udpServer,
		tcpServer: tcpServer,

		handler: handler,

		bindAddress: cfg.BindAddress,
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

	<-p.ctx.Done()
	ctx, cancel := context.WithTimeout(p.ctx, time.Second*5)
	defer cancel()

	if err := p.udpServer.ShutdownContext(ctx); err != nil {
		p.log.Error(err, "failed to shut down UDP server")
	}
	if err := p.tcpServer.ShutdownContext(ctx); err != nil {
		p.log.Error(err, "failed to shut down TCP server")
	}
}

// Stop starts TCP/UDP servers
func (p *DNSProxy) Stop() {
	p.cancelFunc()
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

func (p *DNSProxy) GetSetsForFQDN(fqdn firewallv1.FQDNSelector) (result []firewallv1.IPSet) {
	return p.cache.getSetsForFQDN(fqdn)
}

func (p *DNSProxy) IsInitialized() bool {
	return p != nil
}

func (p *DNSProxy) CacheAddr() string {
	return p.bindAddress
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
				_ = listener.Close()
			}
			if conn != nil {
				_ = conn.Close()
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
