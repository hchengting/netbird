package net

import (
	"context"
	"errors"
	stdnet "net"
	"net/netip"
	"reflect"
	"sync"
	"testing"
)

type recordingDialer struct {
	mu        sync.Mutex
	addresses []string
	dial      func(address string) (stdnet.Conn, error)
}

func (d *recordingDialer) DialContext(_ context.Context, _, address string) (stdnet.Conn, error) {
	d.mu.Lock()
	d.addresses = append(d.addresses, address)
	d.mu.Unlock()
	return d.dial(address)
}

func (d *recordingDialer) calledAddresses() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.addresses...)
}

func TestControlPlaneDialerResolvesBeforeDial(t *testing.T) {
	resolver := resolverFunc(func(_ context.Context, network, host string) ([]netip.Addr, error) {
		if network != "ip" {
			t.Fatalf("LookupNetIP() network = %q, want ip", network)
		}
		if host != "management.example.com" {
			t.Fatalf("LookupNetIP() host = %q", host)
		}
		return []netip.Addr{netip.MustParseAddr("192.0.2.20")}, nil
	})
	dialer := &recordingDialer{dial: func(string) (stdnet.Conn, error) {
		client, server := stdnet.Pipe()
		t.Cleanup(func() {
			_ = client.Close()
			_ = server.Close()
		})
		return client, nil
	}}

	controlDialer := newControlPlaneDialer(dialer, resolver)
	conn, err := controlDialer.DialContext(context.Background(), "tcp", "management.example.com:443")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	_ = conn.Close()

	if got := dialer.calledAddresses(); !reflect.DeepEqual(got, []string{"192.0.2.20:443"}) {
		t.Fatalf("dialed addresses = %v", got)
	}
}

func TestControlPlaneDialerBypassesResolverForIPAddress(t *testing.T) {
	resolver := resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		t.Fatal("resolver called for an IP address")
		return nil, nil
	})
	dialer := &recordingDialer{dial: func(string) (stdnet.Conn, error) {
		client, server := stdnet.Pipe()
		t.Cleanup(func() {
			_ = client.Close()
			_ = server.Close()
		})
		return client, nil
	}}

	controlDialer := newControlPlaneDialer(dialer, resolver)
	conn, err := controlDialer.DialContext(context.Background(), "tcp", "192.0.2.30:443")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	_ = conn.Close()

	if got := dialer.calledAddresses(); !reflect.DeepEqual(got, []string{"192.0.2.30:443"}) {
		t.Fatalf("dialed addresses = %v", got)
	}
}

func TestControlPlaneDialerFallsBackToOtherAddressFamily(t *testing.T) {
	resolver := resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{
			netip.MustParseAddr("2001:db8::20"),
			netip.MustParseAddr("192.0.2.40"),
		}, nil
	})
	dialer := &recordingDialer{dial: func(address string) (stdnet.Conn, error) {
		if address == "[2001:db8::20]:443" {
			return nil, errors.New("IPv6 unavailable")
		}
		client, server := stdnet.Pipe()
		t.Cleanup(func() {
			_ = client.Close()
			_ = server.Close()
		})
		return client, nil
	}}

	controlDialer := newControlPlaneDialer(dialer, resolver)
	controlDialer.fallbackDelay = 0
	conn, err := controlDialer.DialContext(context.Background(), "tcp", "relay.example.com:443")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	_ = conn.Close()

	got := dialer.calledAddresses()
	if len(got) != 2 {
		t.Fatalf("dialed addresses = %v, want both address families", got)
	}
}

func TestControlPlaneDialerResolveUDPAddr(t *testing.T) {
	resolver := resolverFunc(func(_ context.Context, network, host string) ([]netip.Addr, error) {
		if network != "ip4" {
			t.Fatalf("LookupNetIP() network = %q, want ip4", network)
		}
		if host != "relay.example.com" {
			t.Fatalf("LookupNetIP() host = %q", host)
		}
		return []netip.Addr{netip.MustParseAddr("192.0.2.50")}, nil
	})

	controlDialer := newControlPlaneDialer(&recordingDialer{}, resolver)
	got, err := controlDialer.ResolveUDPAddr(context.Background(), "udp4", "relay.example.com:33080")
	if err != nil {
		t.Fatalf("ResolveUDPAddr() error = %v", err)
	}
	if got.String() != "192.0.2.50:33080" {
		t.Fatalf("ResolveUDPAddr() = %s", got)
	}
}

func TestControlPlaneDialerLookupNetIPUsesControlResolver(t *testing.T) {
	resolver := resolverFunc(func(_ context.Context, network, host string) ([]netip.Addr, error) {
		if network != "ip4" {
			t.Fatalf("LookupNetIP() network = %q, want ip4", network)
		}
		if host != "management.example.com" {
			t.Fatalf("LookupNetIP() host = %q", host)
		}
		return []netip.Addr{
			netip.MustParseAddr("::ffff:192.0.2.70"),
			netip.MustParseAddr("192.0.2.70"),
			netip.MustParseAddr("2001:db8::70"),
		}, nil
	})

	controlDialer := newControlPlaneDialer(&recordingDialer{}, resolver)
	got, err := controlDialer.LookupNetIP(context.Background(), "ip4", "management.example.com")
	if err != nil {
		t.Fatalf("LookupNetIP() error = %v", err)
	}
	want := []netip.Addr{netip.MustParseAddr("192.0.2.70")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("LookupNetIP() = %v, want %v", got, want)
	}
}
