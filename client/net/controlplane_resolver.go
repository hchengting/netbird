package net

import (
	"context"
	"errors"
	"fmt"
	stdnet "net"
	"net/netip"
	"time"
)

const (
	cloudflareDNSIPv4Address  = "1.1.1.1:53"
	cloudflareDNSIPv6Address  = "[2606:4700:4700::1111]:53"
	googleDNSIPv4Address      = "8.8.8.8:53"
	googleDNSIPv6Address      = "[2001:4860:4860::8888]:53"
	controlPlaneLookupTimeout = 5 * time.Second
)

type resolverAttempt struct {
	name     string
	resolver hostResolver
}

type fallbackResolver struct {
	attempts []resolverAttempt
	timeout  time.Duration
}

type lookupAttemptResult struct {
	name      string
	addresses []netip.Addr
	err       error
}

func newPublicFallbackResolver(dialer contextDialer) hostResolver {
	return &fallbackResolver{
		attempts: []resolverAttempt{
			{name: "Cloudflare IPv4", resolver: newFixedDNSResolver(dialer, cloudflareDNSIPv4Address)},
			{name: "Cloudflare IPv6", resolver: newFixedDNSResolver(dialer, cloudflareDNSIPv6Address)},
			{name: "Google IPv4", resolver: newFixedDNSResolver(dialer, googleDNSIPv4Address)},
			{name: "Google IPv6", resolver: newFixedDNSResolver(dialer, googleDNSIPv6Address)},
		},
		timeout: controlPlaneLookupTimeout,
	}
}

func newFixedDNSResolver(dialer contextDialer, address string) *stdnet.Resolver {
	return &stdnet.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (stdnet.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		},
	}
}

func (r *fallbackResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if len(r.attempts) == 0 {
		return nil, errors.New("no control-plane DNS resolvers configured")
	}

	lookupCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	results := make(chan lookupAttemptResult, len(r.attempts))
	for _, attempt := range r.attempts {
		go func() {
			addresses, err := attempt.resolver.LookupNetIP(lookupCtx, network, host)
			results <- lookupAttemptResult{name: attempt.name, addresses: addresses, err: err}
		}()
	}

	lookupErrors := make([]error, 0, len(r.attempts)+1)
	for range r.attempts {
		select {
		case result := <-results:
			if result.err == nil && len(result.addresses) > 0 {
				return result.addresses, nil
			}
			if result.err == nil {
				result.err = errors.New("no usable addresses")
			}
			lookupErrors = append(lookupErrors, fmt.Errorf("%s DNS resolver: %w", result.name, result.err))
		case <-lookupCtx.Done():
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			lookupErrors = append(lookupErrors, fmt.Errorf("control-plane DNS lookup: %w", lookupCtx.Err()))
			return nil, errors.Join(lookupErrors...)
		}
	}

	return nil, errors.Join(lookupErrors...)
}
