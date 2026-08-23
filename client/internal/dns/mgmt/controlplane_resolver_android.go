//go:build android

package mgmt

import nbnet "github.com/netbirdio/netbird/client/net"

func newPlatformControlPlaneResolver() hostResolver {
	return nbnet.NewControlPlaneDialer()
}
