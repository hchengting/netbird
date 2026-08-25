package net

import (
	"context"
	"errors"
	stdnet "net"
	"net/netip"
)

const errNoSuitableAddress = "no suitable address found"

type controlPlaneLookupFunc func(host string) ([]netip.Addr, error)

type callbackResolver struct {
	lookup controlPlaneLookupFunc
}

type callbackLookupResult struct {
	addresses []netip.Addr
	err       error
}

func newCallbackControlPlaneResolver(lookup controlPlaneLookupFunc) hostResolver {
	return &callbackResolver{lookup: lookup}
}

// LookupNetIP adapts a platform hostname lookup callback to hostResolver. The
// callback itself may not support cancellation (Android Network.getAllByName
// does not), so it runs outside the caller goroutine and the result channel is
// buffered to let a late result exit after the context has been cancelled.
func (r *callbackResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if r.lookup == nil {
		return nil, errors.New("control-plane DNS resolver callback is not configured")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	resultCh := make(chan callbackLookupResult, 1)
	go func() {
		addresses, err := r.lookup(host)
		resultCh <- callbackLookupResult{addresses: addresses, err: err}
	}()

	var result callbackLookupResult
	select {
	case result = <-resultCh:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if result.err != nil {
		return nil, result.err
	}
	if len(result.addresses) == 0 {
		return nil, errors.New("platform resolver returned no control-plane addresses")
	}

	addresses := filterAddresses(network, result.addresses)
	if len(addresses) == 0 {
		// Match net.Resolver's wrong-family behavior. The management DNS cache
		// recognizes this value as NODATA instead of turning a valid hostname
		// with only A or only AAAA records into SERVFAIL/NXDOMAIN.
		return nil, &stdnet.AddrError{Err: errNoSuitableAddress, Addr: host}
	}
	return addresses, nil
}
