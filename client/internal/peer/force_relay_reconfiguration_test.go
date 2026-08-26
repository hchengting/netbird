package peer

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/iface/wgproxy"
	"github.com/netbirdio/netbird/client/internal/peer/guard"
	"github.com/netbirdio/netbird/client/internal/peer/ice"
	"github.com/netbirdio/netbird/client/internal/peer/worker"
	relayClient "github.com/netbirdio/netbird/shared/relay/client"
	signalClient "github.com/netbirdio/netbird/shared/signal/client"
	signalProto "github.com/netbirdio/netbird/shared/signal/proto"
)

type forceRelayTestWGIface struct{}

type forceRelayTestSignalClient struct{}

func (forceRelayTestSignalClient) Close() error { return nil }

func (forceRelayTestSignalClient) StreamConnected() bool { return false }

func (forceRelayTestSignalClient) GetStatus() signalClient.Status {
	return signalClient.StreamDisconnected
}

func (forceRelayTestSignalClient) Receive(ctx context.Context, _ func(*signalProto.Message) error) error {
	<-ctx.Done()
	return ctx.Err()
}

func (forceRelayTestSignalClient) Ready() bool { return false }

func (forceRelayTestSignalClient) IsHealthy() bool { return false }

func (forceRelayTestSignalClient) WaitStreamConnected(context.Context) {}

func (forceRelayTestSignalClient) SendToStream(*signalProto.EncryptedMessage) error { return nil }

func (forceRelayTestSignalClient) Send(*signalProto.Message) error { return nil }

func (forceRelayTestSignalClient) SetOnReconnectedListener(func()) {}

func (forceRelayTestWGIface) UpdatePeer(string, []netip.Prefix, time.Duration, *net.UDPAddr, *wgtypes.Key) error {
	return nil
}

func (forceRelayTestWGIface) RemovePeer(string) error {
	return nil
}

func (forceRelayTestWGIface) GetStats() (map[string]configurer.WGStats, error) {
	return nil, nil
}

func (forceRelayTestWGIface) GetProxy() wgproxy.Proxy {
	return nil
}

func (forceRelayTestWGIface) Address() wgaddr.Address {
	return wgaddr.Address{}
}

func (forceRelayTestWGIface) RemoveEndpointAddress(string) error {
	return nil
}

func TestConnReconfigureForceRelayRebuildsOnlyOpenTransports(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	conn := newForceRelayTestConn(t, ctx, true)
	require.NoError(t, conn.Open(ctx))
	t.Cleanup(func() { conn.Close(false) })

	require.True(t, conn.ForceRelayEnabled())
	require.Nil(t, conn.workerICE, "force-relay connection must not create an ICE worker")
	staleRelayWorker := conn.workerRelay

	restarted, err := conn.ReconfigureForceRelay(ctx, false)
	require.NoError(t, err)
	require.True(t, restarted, "an open peer must recycle its transports")
	require.False(t, conn.ForceRelayEnabled())
	require.NotNil(t, conn.workerICE, "disabling force relay must create a fresh ICE worker")
	offer := conn.handshaker.buildOfferAnswer()
	require.True(t, offer.hasICECredentials(),
		"the replacement handshaker must advertise ICE capability")
	conn.statusRelay.SetConnected()
	conn.onRelayDisconnected(staleRelayWorker)
	require.Equal(t, worker.StatusConnected, conn.statusRelay.Get(),
		"a callback from the previous run must not mutate the replacement run")

	restarted, err = conn.ReconfigureForceRelay(ctx, true)
	require.NoError(t, err)
	require.True(t, restarted, "an open peer must recycle its transports")
	require.True(t, conn.ForceRelayEnabled())
	require.Nil(t, conn.workerICE, "the previous run's ICE worker must not leak into force-relay mode")
	offer = conn.handshaker.buildOfferAnswer()
	require.False(t, offer.hasICECredentials(),
		"force-relay offers must not contain stale ICE credentials")
}

func TestConnReconfigureForceRelayDoesNotOpenLazyPeer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	conn := newForceRelayTestConn(t, ctx, true)
	restarted, err := conn.ReconfigureForceRelay(ctx, false)
	require.NoError(t, err)
	require.False(t, restarted, "a closed lazy peer must remain closed")
	require.False(t, conn.opened)
	require.Nil(t, conn.workerICE)

	require.NoError(t, conn.Open(ctx))
	t.Cleanup(func() { conn.Close(false) })
	require.NotNil(t, conn.workerICE, "the next activation must use the latest force-relay mode")
}

func newForceRelayTestConn(t *testing.T, ctx context.Context, forceRelay bool) *Conn {
	t.Helper()

	config := ConnConfig{
		Key:         "remote-peer",
		LocalKey:    "local-peer",
		Timeout:     time.Minute,
		LocalWgPort: 51820,
		ForceRelay:  forceRelay,
		WgConfig: WgConfig{
			RemoteKey:   "remote-peer",
			AllowedIps:  []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
			WgInterface: forceRelayTestWGIface{},
		},
		ICEConfig: ice.Config{},
	}
	relayManager := relayClient.NewManager(ctx, nil, "local-peer", 1280)
	srWatcher := guard.NewSRWatcher(nil, nil, nil, config.ICEConfig)
	conn, err := NewConn(config, ServiceDependencies{
		StatusRecorder: NewRecorder("https://management.example"),
		Signaler:       NewSignaler(forceRelayTestSignalClient{}, wgtypes.Key{}),
		RelayManager:   relayManager,
		SrWatcher:      srWatcher,
	})
	require.NoError(t, err)
	return conn
}
