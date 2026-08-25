//go:build android

package android

import (
	"fmt"
	"net/netip"
)

// IPList is a gomobile-compatible collection of IP addresses.
type IPList struct {
	items []netip.Addr
}

// Add appends an IP address to the collection.
func (array *IPList) Add(s string) error {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return fmt.Errorf("invalid IP address %q: %w", s, err)
	}
	array.items = append(array.items, addr)
	return nil
}
