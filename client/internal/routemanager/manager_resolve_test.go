package routemanager

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

type hostResolverFunc func(ctx context.Context, network, host string) ([]netip.Addr, error)

func (f hostResolverFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

func TestResolveURLsToIPsDeduplicatesHosts(t *testing.T) {
	urls := []string{
		"https://192.0.2.1:443",
		"https://192.0.2.1:443",
		"rels://192.0.2.1:443",
	}

	var calls int
	resolver := hostResolverFunc(func(_ context.Context, network, host string) ([]netip.Addr, error) {
		require.Equal(t, "ip", network)
		require.Equal(t, "192.0.2.1", host)
		calls++
		return []netip.Addr{netip.MustParseAddr(host)}, nil
	})

	ips := resolveURLsToIPs(context.Background(), resolver, urls)

	require.Len(t, ips, 1)
	require.Equal(t, "192.0.2.1", ips[0].String())
	require.Equal(t, 1, calls)
}
