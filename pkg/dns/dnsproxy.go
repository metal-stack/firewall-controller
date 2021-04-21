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

	"github.com/miekg/dns"
	dnsgo "github.com/miekg/dns"
	"golang.org/x/sys/unix"
)

const (
	// DNSTimeout is the maximum time to wait for DNS responses to forwarded DNS requests.
	DNSTimeout = 10 * time.Second
)

type DNSProxy struct {
	cache   *DNSCache
	handler dnsgo.Handler
}

func NewDNSProxy(cache *DNSCache) DNSProxy {
	// Init DNS clients
	// SingleInflight is enabled, otherwise it suppressing retries
	udpClient := &dns.Client{Net: "udp", Timeout: DNSTimeout, SingleInflight: false}
	tcpClient := &dns.Client{Net: "tcp", Timeout: DNSTimeout, SingleInflight: false}
	handler := &DNSProxyHandler{
		udpClient: udpClient,
		tcpClient: tcpClient,
	}

	return DNSProxy{
		cache:   cache,
		handler: handler,
	}
}

func (p DNSProxy) Run() {
	// Start DNS servers
	udpConn, tcpListener, err := bindToAddr("", 8882, true, true)
	if err != nil {
		fmt.Println(err)
	}
	udpServer := &dns.Server{PacketConn: udpConn, Addr: udpConn.LocalAddr().String(), Net: "udp", Handler: handler}
	tcpServer := &dns.Server{Listener: tcpListener, Addr: udpConn.LocalAddr().String(), Net: "tcp", Handler: handler}

	go func() {
		fmt.Println("Starting UDP server")
		if err := udpServer.ActivateAndServe(); err != nil {
			fmt.Printf("Failed to start UDP server: %s\n", err)
		}
	}()

	go func() {
		fmt.Println("Starting TCP server")
		if err := tcpServer.ActivateAndServe(); err != nil {
			fmt.Println("Failed to start TCP server: %s\n", err)
		}
	}()

	fmt.Println("Server started")
	// Watch for termination signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	<-sigChan

	udpServer.Shutdown()
	tcpServer.Shutdown()
}

// bindToAddr attempts to bind to address and port for both UDP and TCP. If
// port is 0 a random open port is assigned and the same one is used for UDP
// and TCP.
func bindToAddr(address string, port uint16, ipv4, ipv6 bool) (*net.UDPConn, *net.TCPListener, error) {
	var err error
	var listener net.Listener
	var conn net.PacketConn
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

	bindAddr := net.JoinHostPort(address, strconv.Itoa(int(port)))

	listener, err = listenConfig(0x0B00, ipv4, ipv6).Listen(context.Background(),
		"tcp", bindAddr)
	if err != nil {
		return nil, nil, err
	}

	conn, err = listenConfig(0x0B00, ipv4, ipv6).ListenPacket(context.Background(),
		"udp", listener.Addr().String())
	if err != nil {
		return nil, nil, err
	}

	return conn.(*net.UDPConn), listener.(*net.TCPListener), nil
}

func listenConfig(mark int, ipv4, ipv6 bool) *net.ListenConfig {
	return &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				opErr = transparentSetsockopt(int(fd), ipv4, ipv6)
				if opErr == nil && mark != 0 {
					opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark)
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

func transparentSetsockopt(fd int, ipv4, ipv6 bool) error {
	var err4, err6 error
	if ipv6 {
		err6 = unix.SetsockoptInt(fd, unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
		if err6 == nil {
			err6 = unix.SetsockoptInt(fd, unix.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, 1)
		}
		if err6 != nil {
			return err6
		}
	}
	if ipv4 {
		err4 = unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_TRANSPARENT, 1)
		if err4 == nil {
			err4 = unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1)
		}
		if err4 != nil {
			return err4
		}
	}
	return nil
}
