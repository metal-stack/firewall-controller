package dns

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/go-logr/logr"
	"github.com/miekg/dns"
	dnsgo "github.com/miekg/dns"
	"golang.org/x/sys/unix"
)

const (
	// DNSTimeout is the maximum time to wait for DNS responses to forwarded DNS requests.
	DNSTimeout = 10 * time.Second
)

type DNSProxy struct {
	log     logr.Logger
	port    uint
	cache   *DNSCache
	handler dnsgo.Handler
}

func NewDNSProxy(port uint, log logr.Logger, cache *DNSCache) DNSProxy {
	// Init DNS clients
	// SingleInflight is enabled, otherwise it suppressing retries
	udpClient := &dns.Client{Net: "udp", Timeout: DNSTimeout, SingleInflight: false}
	tcpClient := &dns.Client{Net: "tcp", Timeout: DNSTimeout, SingleInflight: false}
	handler := &DNSProxyHandler{
		log:         log.WithName("DNS handler"),
		udpClient:   udpClient,
		tcpClient:   tcpClient,
		updateCache: getUpdateCacheFunc(log, cache),
	}

	return DNSProxy{
		log:     log,
		port:    port,
		cache:   cache,
		handler: handler,
	}
}

func (p DNSProxy) Run() error {
	// Start DNS servers
	udpConn, tcpListener, err := p.bindToPort()
	if err != nil {
		return fmt.Errorf("failed to bind to port: %w", err)
	}

	udpServer := &dns.Server{PacketConn: udpConn, Addr: udpConn.LocalAddr().String(), Net: "udp", Handler: p.handler}
	go func() {
		p.log.Info("starting UDP server")
		if err := udpServer.ActivateAndServe(); err != nil {
			p.log.Error(err, "failed to start UDP server")
		}
	}()

	tcpServer := &dns.Server{Listener: tcpListener, Addr: udpConn.LocalAddr().String(), Net: "tcp", Handler: p.handler}
	go func() {
		p.log.Info("starting TCP server")
		if err := tcpServer.ActivateAndServe(); err != nil {
			p.log.Error(err, "failed to start TCP server")
		}
	}()

	// Watch for termination signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	<-sigChan

	udpServer.Shutdown()
	tcpServer.Shutdown()

	return nil
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

// bindToPort attempts to bind to port for both UDP and TCP
func (p DNSProxy) bindToPort() (*net.UDPConn, *net.TCPListener, error) {
	var err error
	var listener net.Listener
	var conn net.PacketConn
	bindAddr := net.JoinHostPort("", strconv.Itoa(int(p.port)))

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
				opErr = transparentSetsockopt(int(fd))
				if opErr == nil {
					opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, 0x0B00)
				}
				if opErr == nil {
					opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
				}
				if opErr == nil {
					opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
				}
			})
			if err != nil {
				return err
			}

			return opErr
		}}
}

func transparentSetsockopt(fd int) error {
	var err4, err6 error

	err6 = unix.SetsockoptInt(fd, unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
	if err6 == nil {
		err6 = unix.SetsockoptInt(fd, unix.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, 1)
	}
	if err6 != nil {
		return err6
	}

	err4 = unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_TRANSPARENT, 1)
	if err4 == nil {
		err4 = unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1)
	}
	if err4 != nil {
		return err4
	}

	return nil
}
