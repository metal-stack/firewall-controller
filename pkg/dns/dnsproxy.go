package dns

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"syscall"

	"github.com/go-logr/logr"
	dnsgo "github.com/miekg/dns"
	"golang.org/x/sys/unix"
)

const ()

type DNSHandler interface {
	ServeDNS(w dnsgo.ResponseWriter, r *dnsgo.Msg)
	UpdateDNSAddr(addr string)
}

type DNSProxy struct {
	log     logr.Logger
	port    uint
	cache   *DNSCache
	handler DNSHandler
}

func NewDNSProxy(port uint, log logr.Logger, cache *DNSCache) *DNSProxy {
	return &DNSProxy{
		log:     log,
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
	bindAddr := net.JoinHostPort("100.255.254.1", strconv.Itoa(int(p.port)))

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

	listener, err = listenConfig().Listen(context.Background(), "tcp", bindAddr)
	if err != nil {
		return nil, nil, err
	}

	conn, err = listenConfig().ListenPacket(context.Background(), "udp", listener.Addr().String())
	if err != nil {
		return nil, nil, err
	}

	p.log.Info("DNS proxy bound to address", "address", bindAddr)

	return conn.(*net.UDPConn), listener.(*net.TCPListener), nil
}

func listenConfig() *net.ListenConfig {
	return &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				// Set SO_REUSEADDR option to avoid possible wait time before reusing local address
				// More on that: https://stackoverflow.com/questions/3229860/what-is-the-meaning-of-so-reuseaddr-setsockopt-option-linux
				if opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); opErr == nil {
					// SO_REUSEPORT serves same purpose as SO_REUSEADDR.
					// Added for portability reason.
					// More on that: https://stackoverflow.com/questions/14388706/how-do-so-reuseaddr-and-so-reuseport-differ
					opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
				}
			})
			if err != nil {
				return err
			}

			return opErr
		}}
}
