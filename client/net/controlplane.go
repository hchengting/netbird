package net

import (
	"context"
	"errors"
	"fmt"
	stdnet "net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

const controlPlaneFallbackDelay = 250 * time.Millisecond

type hostResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

type contextDialer interface {
	DialContext(ctx context.Context, network, address string) (stdnet.Conn, error)
}

// ControlPlaneDialer resolves and dials control-plane endpoints. On Android it
// uses the selected underlying Network without changing the VPN DNS settings.
type ControlPlaneDialer struct {
	dialer        contextDialer
	resolver      hostResolver
	fallbackDelay time.Duration
}

// NewControlPlaneDialer creates a dialer for management, signal, and relay
// endpoints. Platforms other than Android retain the default resolver path.
func NewControlPlaneDialer() *ControlPlaneDialer {
	return newControlPlaneDialer(NewDialer(), newPlatformControlPlaneResolver())
}

func newControlPlaneDialer(dialer contextDialer, resolver hostResolver) *ControlPlaneDialer {
	return &ControlPlaneDialer{
		dialer:        dialer,
		resolver:      resolver,
		fallbackDelay: controlPlaneFallbackDelay,
	}
}

// LookupNetIP resolves a control-plane host without changing the platform's
// global or VPN DNS configuration.
func (d *ControlPlaneDialer) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	lookupNetwork, err := lookupNetworkForDial(network)
	if err != nil {
		return nil, err
	}

	if addr, err := netip.ParseAddr(host); err == nil {
		addresses := filterAddresses(lookupNetwork, []netip.Addr{addr})
		if len(addresses) == 0 {
			return nil, fmt.Errorf("control-plane address does not match network %s", network)
		}
		return addresses, nil
	}

	resolver := d.resolver
	if resolver == nil {
		resolver = stdnet.DefaultResolver
	}

	addresses, err := resolver.LookupNetIP(ctx, lookupNetwork, host)
	if err != nil {
		return nil, fmt.Errorf("resolve control-plane address: %w", err)
	}

	addresses = filterAddresses(lookupNetwork, addresses)
	if len(addresses) == 0 {
		return nil, fmt.Errorf("resolve control-plane address: no usable addresses")
	}
	return addresses, nil
}

// DialContext connects to an endpoint using the control-plane resolver when it
// is enabled for the current platform.
func (d *ControlPlaneDialer) DialContext(ctx context.Context, network, address string) (stdnet.Conn, error) {
	if d.resolver == nil {
		return d.dialer.DialContext(ctx, network, address)
	}

	host, port, err := stdnet.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("split control-plane address: %w", err)
	}

	addresses, err := d.LookupNetIP(ctx, network, host)
	if err != nil {
		return nil, err
	}

	return d.dialResolved(ctx, network, port, addresses)
}

// ResolveUDPAddr resolves a UDP endpoint using the control-plane resolver when
// it is enabled for the current platform.
func (d *ControlPlaneDialer) ResolveUDPAddr(ctx context.Context, network, address string) (*stdnet.UDPAddr, error) {
	if d.resolver == nil {
		return stdnet.ResolveUDPAddr(network, address)
	}

	host, portText, err := stdnet.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("split control-plane UDP address: %w", err)
	}

	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("parse control-plane UDP port: %w", err)
	}

	addresses, err := d.LookupNetIP(ctx, network, host)
	if err != nil {
		return nil, err
	}

	addrPort := netip.AddrPortFrom(addresses[0], uint16(port))
	return stdnet.UDPAddrFromAddrPort(addrPort), nil
}

func (d *ControlPlaneDialer) dialResolved(ctx context.Context, network, port string, addresses []netip.Addr) (stdnet.Conn, error) {
	primary, fallback := splitAddressFamilies(addresses)
	if len(fallback) == 0 {
		return d.dialSerial(ctx, network, port, primary)
	}

	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan dialResult, 2)
	var wg sync.WaitGroup
	start := func(delay time.Duration, candidates []netip.Addr) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-dialCtx.Done():
					results <- dialResult{err: context.Cause(dialCtx)}
					return
				}
			}
			conn, err := d.dialSerial(dialCtx, network, port, candidates)
			results <- dialResult{conn: conn, err: err}
		}()
	}

	start(0, primary)
	start(d.fallbackDelay, fallback)
	go func() {
		wg.Wait()
		close(results)
	}()

	var winner stdnet.Conn
	var dialErrors []error
	for result := range results {
		if result.err == nil {
			if winner == nil {
				winner = result.conn
				cancel()
			} else {
				_ = result.conn.Close()
			}
			continue
		}
		if winner == nil && !errors.Is(result.err, context.Canceled) {
			dialErrors = append(dialErrors, result.err)
		}
	}

	if winner != nil {
		return winner, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, errors.Join(dialErrors...)
}

func (d *ControlPlaneDialer) dialSerial(ctx context.Context, network, port string, addresses []netip.Addr) (stdnet.Conn, error) {
	var dialErrors []error
	for _, address := range addresses {
		endpoint := stdnet.JoinHostPort(address.String(), port)
		conn, err := d.dialer.DialContext(ctx, network, endpoint)
		if err == nil {
			return conn, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		dialErrors = append(dialErrors, err)
	}
	return nil, errors.Join(dialErrors...)
}

type dialResult struct {
	conn stdnet.Conn
	err  error
}

func lookupNetworkForDial(network string) (string, error) {
	switch network {
	case "tcp", "udp", "ip":
		return "ip", nil
	case "tcp4", "udp4", "ip4":
		return "ip4", nil
	case "tcp6", "udp6", "ip6":
		return "ip6", nil
	default:
		return "", fmt.Errorf("unsupported control-plane network %q", network)
	}
}

func filterAddresses(network string, addresses []netip.Addr) []netip.Addr {
	filtered := make([]netip.Addr, 0, len(addresses))
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		if !address.IsValid() {
			continue
		}
		address = address.Unmap()
		if network == "ip4" && !address.Is4() {
			continue
		}
		if network == "ip6" && !address.Is6() {
			continue
		}
		if _, ok := seen[address]; ok {
			continue
		}
		seen[address] = struct{}{}
		filtered = append(filtered, address)
	}
	return filtered
}

func splitAddressFamilies(addresses []netip.Addr) ([]netip.Addr, []netip.Addr) {
	if len(addresses) == 0 {
		return nil, nil
	}

	primaryIPv4 := addresses[0].Is4()
	primary := make([]netip.Addr, 0, len(addresses))
	fallback := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		if address.Is4() == primaryIPv4 {
			primary = append(primary, address)
		} else {
			fallback = append(fallback, address)
		}
	}
	return primary, fallback
}
