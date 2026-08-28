package net

import (
	"context"
	"errors"
	stdnet "net"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

type resolverFunc func(ctx context.Context, network, host string) ([]netip.Addr, error)

func (f resolverFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

func TestCallbackResolverUsesPlatformLookupAndFiltersAddresses(t *testing.T) {
	want := []netip.Addr{
		netip.MustParseAddr("192.0.2.10"),
		netip.MustParseAddr("2001:db8::10"),
	}
	var gotHost string
	resolver := newCallbackControlPlaneResolver(func(host string) ([]netip.Addr, error) {
		gotHost = host
		return []netip.Addr{
			netip.MustParseAddr("::ffff:192.0.2.10"),
			netip.MustParseAddr("2001:db8::10"),
			netip.MustParseAddr("192.0.2.10"),
		}, nil
	})

	got, err := resolver.LookupNetIP(context.Background(), "ip", "management.example.com")
	if err != nil {
		t.Fatalf("LookupNetIP() error = %v", err)
	}
	if gotHost != "management.example.com" {
		t.Fatalf("lookup host = %q", gotHost)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("LookupNetIP() = %v, want %v", got, want)
	}
}

func TestCallbackResolverFiltersRequestedFamily(t *testing.T) {
	resolver := newCallbackControlPlaneResolver(func(string) ([]netip.Addr, error) {
		return []netip.Addr{
			netip.MustParseAddr("192.0.2.20"),
			netip.MustParseAddr("2001:db8::20"),
		}, nil
	})

	want := []netip.Addr{netip.MustParseAddr("192.0.2.20")}
	got, err := resolver.LookupNetIP(context.Background(), "ip4", "signal.example.com")
	if err != nil {
		t.Fatalf("LookupNetIP() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("LookupNetIP() = %v, want %v", got, want)
	}
}

func TestCallbackResolverReturnsNoDataForMissingFamily(t *testing.T) {
	resolver := newCallbackControlPlaneResolver(func(string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.0.2.30")}, nil
	})

	_, err := resolver.LookupNetIP(context.Background(), "ip6", "relay.example.com")
	var addrErr *stdnet.AddrError
	if !errors.As(err, &addrErr) {
		t.Fatalf("LookupNetIP() error = %v, want *net.AddrError", err)
	}
	if addrErr.Err != errNoSuitableAddress {
		t.Fatalf("AddrError.Err = %q", addrErr.Err)
	}
}

func TestCallbackResolverPropagatesPlatformError(t *testing.T) {
	wantErr := errors.New("no non-VPN network")
	resolver := newCallbackControlPlaneResolver(func(string) ([]netip.Addr, error) {
		return nil, wantErr
	})

	_, err := resolver.LookupNetIP(context.Background(), "ip", "management.example.com")
	if !errors.Is(err, wantErr) {
		t.Fatalf("LookupNetIP() error = %v, want %v", err, wantErr)
	}
}

func TestCallbackResolverHonorsContextCancellation(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	resolver := newCallbackControlPlaneResolver(func(string) ([]netip.Addr, error) {
		close(started)
		<-release
		return []netip.Addr{netip.MustParseAddr("192.0.2.40")}, nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	resultCh := make(chan error, 1)
	go func() {
		_, err := resolver.LookupNetIP(ctx, "ip", "management.example.com")
		resultCh <- err
	}()

	<-started
	cancel()
	select {
	case err := <-resultCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("LookupNetIP() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("LookupNetIP() did not return after context cancellation")
	}
	close(release)
}

func TestCallbackResolverRejectsEmptyResult(t *testing.T) {
	resolver := newCallbackControlPlaneResolver(func(string) ([]netip.Addr, error) {
		return nil, nil
	})

	if _, err := resolver.LookupNetIP(context.Background(), "ip", "management.example.com"); err == nil {
		t.Fatal("LookupNetIP() error = nil")
	}
}

func TestCallbackResolverRejectsMissingCallback(t *testing.T) {
	resolver := newCallbackControlPlaneResolver(nil)

	if _, err := resolver.LookupNetIP(context.Background(), "ip", "management.example.com"); err == nil {
		t.Fatal("LookupNetIP() error = nil")
	}
}
