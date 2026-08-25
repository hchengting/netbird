//go:build android

package net

import (
	"errors"
	"net/netip"
	"sync"
)

var (
	androidControlPlaneResolverMu sync.RWMutex
	androidControlPlaneResolver   controlPlaneLookupFunc
)

// SetAndroidControlPlaneResolverFn sets the per-host resolver backed by
// Android's selected non-VPN Network.
func SetAndroidControlPlaneResolverFn(fn func(host string) ([]netip.Addr, error)) {
	androidControlPlaneResolverMu.Lock()
	androidControlPlaneResolver = fn
	androidControlPlaneResolverMu.Unlock()
}

func newPlatformControlPlaneResolver() hostResolver {
	return newCallbackControlPlaneResolver(lookupAndroidControlPlaneHost)
}

func lookupAndroidControlPlaneHost(host string) ([]netip.Addr, error) {
	androidControlPlaneResolverMu.RLock()
	resolver := androidControlPlaneResolver
	androidControlPlaneResolverMu.RUnlock()
	if resolver == nil {
		return nil, errors.New("Android control-plane DNS resolver is not configured")
	}
	return resolver(host)
}
