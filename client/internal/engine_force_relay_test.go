package internal

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/peerstore"
)

func TestEngineSetForceRelayUpdatesClosedPeersWithoutRestart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	engine := &Engine{
		ctx:        ctx,
		syncMsgMux: &sync.Mutex{},
		config:     &EngineConfig{},
		peerStore:  peerstore.NewConnStore(),
	}
	conn, err := peer.NewConn(peer.ConnConfig{
		Key:        "remote-peer",
		LocalKey:   "local-peer",
		ForceRelay: false,
		WgConfig: peer.WgConfig{
			RemoteKey:  "remote-peer",
			AllowedIps: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
		},
	}, peer.ServiceDependencies{})
	require.NoError(t, err)
	require.True(t, engine.peerStore.AddPeerConn("remote-peer", conn))

	require.NoError(t, engine.SetForceRelay(true))
	require.True(t, engine.ForceRelayEnabled())
	require.True(t, conn.ForceRelayEnabled())

	require.NoError(t, engine.SetForceRelay(true), "idempotent update must be a no-op")
}
