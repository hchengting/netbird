package net

import (
	"context"
	"errors"
	stdnet "net"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"
)

type resolverFunc func(ctx context.Context, network, host string) ([]netip.Addr, error)

func (f resolverFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

type dialerFunc func(ctx context.Context, network, address string) (stdnet.Conn, error)

func (f dialerFunc) DialContext(ctx context.Context, network, address string) (stdnet.Conn, error) {
	return f(ctx, network, address)
}

func TestFallbackResolverUsesNextResolver(t *testing.T) {
	want := []netip.Addr{netip.MustParseAddr("192.0.2.10")}
	resolver := &fallbackResolver{
		attempts: []resolverAttempt{
			{
				name: "primary",
				resolver: resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
					return nil, &stdnet.DNSError{Err: "temporary failure", IsTemporary: true}
				}),
			},
			{
				name: "fallback",
				resolver: resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
					return want, nil
				}),
			},
		},
		timeout: time.Second,
	}

	got, err := resolver.LookupNetIP(context.Background(), "ip", "management.example.com")
	if err != nil {
		t.Fatalf("LookupNetIP() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("LookupNetIP() = %v, want %v", got, want)
	}
}

func TestFallbackResolverQueriesProvidersConcurrently(t *testing.T) {
	firstStarted := make(chan struct{})
	secondStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() { close(releaseFirst) })
	}
	defer release()

	want := []netip.Addr{netip.MustParseAddr("192.0.2.11")}
	resolver := &fallbackResolver{
		attempts: []resolverAttempt{
			{
				name: "first",
				resolver: resolverFunc(func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
					close(firstStarted)
					select {
					case <-releaseFirst:
						return nil, errors.New("first failed")
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}),
			},
			{
				name: "second",
				resolver: resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
					close(secondStarted)
					return want, nil
				}),
			},
		},
		timeout: time.Second,
	}

	type lookupResult struct {
		addresses []netip.Addr
		err       error
	}
	resultCh := make(chan lookupResult, 1)
	go func() {
		addresses, err := resolver.LookupNetIP(context.Background(), "ip", "management.example.com")
		resultCh <- lookupResult{addresses: addresses, err: err}
	}()

	<-firstStarted
	concurrent := true
	select {
	case <-secondStarted:
	case <-time.After(100 * time.Millisecond):
		concurrent = false
		release()
	}

	result := <-resultCh
	if result.err != nil {
		t.Fatalf("LookupNetIP() error = %v", result.err)
	}
	if !reflect.DeepEqual(result.addresses, want) {
		t.Fatalf("LookupNetIP() = %v, want %v", result.addresses, want)
	}
	if !concurrent {
		t.Fatal("DNS providers were queried sequentially")
	}
}

func TestFallbackResolverUsesSuccessfulAnswerDespiteAuthoritativeNotFound(t *testing.T) {
	var fallbackCalled bool
	want := []netip.Addr{netip.MustParseAddr("192.0.2.10")}
	resolver := &fallbackResolver{
		attempts: []resolverAttempt{
			{
				name: "primary",
				resolver: resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
					return nil, &stdnet.DNSError{Err: "no such host", IsNotFound: true}
				}),
			},
			{
				name: "fallback",
				resolver: resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
					fallbackCalled = true
					return want, nil
				}),
			},
		},
		timeout: time.Second,
	}

	got, err := resolver.LookupNetIP(context.Background(), "ip", "management.example.com")
	if err != nil {
		t.Fatalf("LookupNetIP() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("LookupNetIP() = %v, want %v", got, want)
	}
	if !fallbackCalled {
		t.Fatal("successful resolver was not called")
	}
}

func TestFallbackResolverFallsBackAfterTimeout(t *testing.T) {
	want := []netip.Addr{netip.MustParseAddr("2001:db8::10")}
	resolver := &fallbackResolver{
		attempts: []resolverAttempt{
			{
				name: "primary",
				resolver: resolverFunc(func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
					<-ctx.Done()
					return nil, ctx.Err()
				}),
			},
			{
				name: "fallback",
				resolver: resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
					return want, nil
				}),
			},
		},
		timeout: 10 * time.Millisecond,
	}

	got, err := resolver.LookupNetIP(context.Background(), "ip", "signal.example.com")
	if err != nil {
		t.Fatalf("LookupNetIP() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("LookupNetIP() = %v, want %v", got, want)
	}
}

func TestFallbackResolverUsesNextResolverForEmptyAnswer(t *testing.T) {
	want := []netip.Addr{netip.MustParseAddr("192.0.2.60")}
	resolver := &fallbackResolver{
		attempts: []resolverAttempt{
			{
				name: "primary",
				resolver: resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
					return nil, nil
				}),
			},
			{
				name: "fallback",
				resolver: resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
					return want, nil
				}),
			},
		},
		timeout: time.Second,
	}

	got, err := resolver.LookupNetIP(context.Background(), "ip", "relay.example.com")
	if err != nil {
		t.Fatalf("LookupNetIP() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("LookupNetIP() = %v, want %v", got, want)
	}
}

func TestPublicFallbackResolverProviders(t *testing.T) {
	wantErr := errors.New("stop before DNS exchange")
	var gotNetworks, gotAddresses []string
	dialer := dialerFunc(func(_ context.Context, network, address string) (stdnet.Conn, error) {
		gotNetworks = append(gotNetworks, network)
		gotAddresses = append(gotAddresses, address)
		return nil, wantErr
	})

	resolver, ok := newPublicFallbackResolver(dialer).(*fallbackResolver)
	if !ok {
		t.Fatal("newPublicFallbackResolver() did not return a fallbackResolver")
	}
	if len(resolver.attempts) != 4 {
		t.Fatalf("resolver attempts = %d, want 4", len(resolver.attempts))
	}
	if resolver.timeout != 5*time.Second {
		t.Fatalf("resolver timeout = %s, want 5s", resolver.timeout)
	}
	gotNames := make([]string, 0, len(resolver.attempts))
	for _, attempt := range resolver.attempts {
		gotNames = append(gotNames, attempt.name)
	}
	wantNames := []string{"Cloudflare IPv4", "Cloudflare IPv6", "Google IPv4", "Google IPv6"}
	if !reflect.DeepEqual(gotNames, wantNames) {
		t.Fatalf("resolver names = %v, want %v", gotNames, wantNames)
	}

	for _, attempt := range resolver.attempts {
		fixedResolver, ok := attempt.resolver.(*stdnet.Resolver)
		if !ok {
			t.Fatalf("%s resolver has type %T", attempt.name, attempt.resolver)
		}
		_, err := fixedResolver.Dial(context.Background(), "udp", "ignored:53")
		if !errors.Is(err, wantErr) {
			t.Fatalf("%s Dial() error = %v, want %v", attempt.name, err, wantErr)
		}
	}

	if !reflect.DeepEqual(gotNetworks, []string{"udp", "udp", "udp", "udp"}) {
		t.Fatalf("Dial() networks = %v", gotNetworks)
	}
	wantAddresses := []string{
		"1.1.1.1:53",
		"[2606:4700:4700::1111]:53",
		"8.8.8.8:53",
		"[2001:4860:4860::8888]:53",
	}
	if !reflect.DeepEqual(gotAddresses, wantAddresses) {
		t.Fatalf("Dial() addresses = %v, want %v", gotAddresses, wantAddresses)
	}
}
