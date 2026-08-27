package peer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/iface/wgproxy"
	"github.com/netbirdio/netbird/client/internal/peer/conntype"
	"github.com/netbirdio/netbird/client/internal/peer/guard"
	"github.com/netbirdio/netbird/client/internal/peer/ice"
	relayClient "github.com/netbirdio/netbird/shared/relay/client"
	signalClient "github.com/netbirdio/netbird/shared/signal/client"
	signalProto "github.com/netbirdio/netbird/shared/signal/proto"
)

type forceRelayTestWGIface struct{}

type recordingForceRelayTestWGIface struct {
	forceRelayTestWGIface
	mu           sync.Mutex
	endpoints    []*net.UDPAddr
	removedPeers int
	updateErr    error
}

type forceRelayTestProxy struct {
	mu         sync.Mutex
	endpoint   *net.UDPAddr
	workCount  int
	pauseCount int
	closeCount int
}

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

func (f *recordingForceRelayTestWGIface) UpdatePeer(
	_ string,
	_ []netip.Prefix,
	_ time.Duration,
	endpoint *net.UDPAddr,
	_ *wgtypes.Key,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.endpoints = append(f.endpoints, endpoint)
	return f.updateErr
}

func (f *recordingForceRelayTestWGIface) recordedEndpoints() []*net.UDPAddr {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*net.UDPAddr(nil), f.endpoints...)
}

func (f *recordingForceRelayTestWGIface) RemovePeer(string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removedPeers++
	return nil
}

func (f *recordingForceRelayTestWGIface) removePeerCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.removedPeers
}

func (f *recordingForceRelayTestWGIface) setUpdateError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updateErr = err
}

func (p *forceRelayTestProxy) AddRelayedConn(context.Context, *net.UDPAddr, net.Conn) error {
	return nil
}

func (p *forceRelayTestProxy) EndpointAddr() *net.UDPAddr {
	return p.endpoint
}

func (p *forceRelayTestProxy) Work() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.workCount++
}

func (p *forceRelayTestProxy) Pause() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pauseCount++
}

func (*forceRelayTestProxy) RedirectAs(*net.UDPAddr) {}

func (p *forceRelayTestProxy) CloseConn() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closeCount++
	return nil
}

func (*forceRelayTestProxy) SetDisconnectListener(func()) {}

func (*forceRelayTestProxy) InjectPacket([]byte) error { return nil }

func (p *forceRelayTestProxy) counts() (work, pause, close int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.workCount, p.pauseCount, p.closeCount
}

func TestConnReconfigureForceRelayKeepsOpenTransportRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	wgIface := &recordingForceRelayTestWGIface{}
	conn := newForceRelayTestConnWithIface(t, ctx, true, wgIface)
	require.NoError(t, conn.Open(ctx))
	t.Cleanup(func() { conn.Close(false) })

	require.True(t, conn.ForceRelayEnabled())
	require.Nil(t, conn.workerICE, "force-relay connection must not create an ICE worker")
	originalRelayWorker := conn.workerRelay
	originalHandshaker := conn.handshaker
	originalRunContext := conn.ctx

	reconfigured, err := conn.ReconfigureForceRelay(ctx, false)
	require.NoError(t, err)
	require.True(t, reconfigured, "an open peer must apply the policy in place")
	require.False(t, conn.ForceRelayEnabled())
	require.NotNil(t, conn.workerICE, "disabling force relay must create a fresh ICE worker")
	require.Same(t, originalRelayWorker, conn.workerRelay,
		"the established relay worker must survive ICE enablement")
	require.Same(t, originalHandshaker, conn.handshaker,
		"the live handshaker must gain ICE without replacement")
	require.Equal(t, originalRunContext, conn.ctx,
		"runtime policy changes must not cancel the peer run")
	require.Zero(t, wgIface.removePeerCount(),
		"runtime policy changes must not remove the WireGuard peer")
	offer := conn.handshaker.buildOfferAnswer()
	require.True(t, offer.hasICECredentials(),
		"the live handshaker must advertise the new ICE capability")
	assertForceRelayTestTransportCounts(t, wgIface, 0)
}

func TestConnReconfigureForceRelayUsesReadyRelayBeforeRetiringICE(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	wgIface := &recordingForceRelayTestWGIface{}
	conn := newForceRelayTestConnWithIface(t, ctx, false, wgIface)
	require.NoError(t, conn.Open(ctx))
	t.Cleanup(func() { conn.Close(false) })

	relayEndpoint := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 10001}
	relayProxy := &forceRelayTestProxy{endpoint: relayEndpoint}
	iceProxy := &forceRelayTestProxy{
		endpoint: &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 51820},
	}
	conn.mu.Lock()
	conn.wgProxyRelay = relayProxy
	conn.wgProxyICE = iceProxy
	conn.currentConnPriority = conntype.ICEP2P
	conn.statusRelay.SetConnected()
	conn.statusICE.SetConnected()
	conn.mu.Unlock()

	originalRelayWorker := conn.workerRelay
	originalHandshaker := conn.handshaker
	originalRunContext := conn.ctx

	reconfigured, err := conn.ReconfigureForceRelay(ctx, true)
	require.NoError(t, err)
	require.True(t, reconfigured, "an open peer must apply the relay policy in place")
	require.True(t, conn.ForceRelayEnabled())
	require.Nil(t, conn.workerICE,
		"ICE must retire only after the relay endpoint is active")
	require.Same(t, originalRelayWorker, conn.workerRelay,
		"switching to an established relay must not replace its worker")
	require.Same(t, originalHandshaker, conn.handshaker,
		"switching to an established relay must not replace the handshaker")
	require.Equal(t, originalRunContext, conn.ctx,
		"switching to relay must not cancel the peer run")
	require.Equal(t, conntype.Relay, conn.currentConnPriority,
		"relay must become the active transport before ICE retires")
	offer := conn.handshaker.buildOfferAnswer()
	require.False(t, offer.hasICECredentials(),
		"completed force-relay transitions must stop advertising ICE")

	endpoints := wgIface.recordedEndpoints()
	require.Equal(t, []*net.UDPAddr{relayEndpoint}, endpoints,
		"the existing WireGuard peer must switch directly to relay")
	assertForceRelayTestTransportCounts(t, wgIface, 0)
	work, pause, _ := relayProxy.counts()
	require.Equal(t, 1, work, "the relay proxy must resume before ICE is retired")
	require.Zero(t, pause, "a successful relay switch must leave the proxy active")
	_, _, iceClose := iceProxy.counts()
	require.Equal(t, 1, iceClose, "the old ICE proxy must close after the relay switch")
}

func TestConnReconfigureForceRelayKeepsICEWhenRelayEndpointUpdateFails(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	wgIface := &recordingForceRelayTestWGIface{}
	conn := newForceRelayTestConnWithIface(t, ctx, false, wgIface)
	require.NoError(t, conn.Open(ctx))
	t.Cleanup(func() { conn.Close(false) })

	relayProxy := &forceRelayTestProxy{
		endpoint: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 10001},
	}
	iceProxy := &forceRelayTestProxy{
		endpoint: &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 51820},
	}
	conn.mu.Lock()
	conn.wgProxyRelay = relayProxy
	conn.wgProxyICE = iceProxy
	conn.currentConnPriority = conntype.ICEP2P
	conn.statusRelay.SetConnected()
	conn.statusICE.SetConnected()
	originalICEWorker := conn.workerICE
	conn.mu.Unlock()
	wgIface.setUpdateError(errors.New("update rejected"))

	reconfigured, err := conn.ReconfigureForceRelay(ctx, true)
	require.ErrorContains(t, err, "switch to relay endpoint")
	require.True(t, reconfigured, "the open peer must report the attempted policy change")
	require.False(t, conn.ForceRelayEnabled(),
		"a failed relay switch must preserve the applied ICE policy")
	require.Same(t, originalICEWorker, conn.workerICE,
		"a failed relay switch must keep the active ICE worker")
	require.Equal(t, conntype.ICEP2P, conn.currentConnPriority,
		"a failed relay switch must keep ICE active")
	offer := conn.handshaker.buildOfferAnswer()
	require.True(t, offer.hasICECredentials(),
		"a failed relay switch must keep advertising ICE")
	work, pause, _ := relayProxy.counts()
	require.Equal(t, 1, work, "the relay proxy must be tried before the endpoint update")
	require.Equal(t, 1, pause, "the failed relay proxy must be paused again")
	_, _, iceClose := iceProxy.counts()
	require.Zero(t, iceClose, "the active ICE proxy must survive a failed relay switch")
	assertForceRelayTestTransportCounts(t, wgIface, 0)
}

func assertForceRelayTestTransportCounts(
	t *testing.T,
	wgIface *recordingForceRelayTestWGIface,
	wantRemovedPeers int,
) {
	t.Helper()
	require.Equal(t, wantRemovedPeers, wgIface.removePeerCount(),
		"runtime policy transition removed an unexpected WireGuard peer")
}

func TestConnReconfigureForceRelayDoesNotOpenLazyPeer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	conn := newForceRelayTestConn(t, ctx, true)
	reconfigured, err := conn.ReconfigureForceRelay(ctx, false)
	require.NoError(t, err)
	require.False(t, reconfigured, "a closed lazy peer must remain closed")
	require.False(t, conn.opened)
	require.Nil(t, conn.workerICE)

	require.NoError(t, conn.Open(ctx))
	t.Cleanup(func() { conn.Close(false) })
	require.NotNil(t, conn.workerICE, "the next activation must use the latest force-relay mode")
}

func TestConnReconfigureForceRelayProgramsFirstICEEndpointImmediately(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	wgIface := &recordingForceRelayTestWGIface{}
	conn := newForceRelayTestConnWithIface(t, ctx, true, wgIface)
	require.NoError(t, conn.Open(ctx))
	t.Cleanup(func() { conn.Close(false) })

	reconfigured, err := conn.ReconfigureForceRelay(ctx, false)
	require.NoError(t, err)
	require.True(t, reconfigured, "an open peer must add ICE in place")

	iceEndpoint := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 51820}

	require.NoError(t, configureForceRelayTestEndpoint(conn, iceEndpoint, immediateEndpointICE))
	require.NoError(t, configureForceRelayTestEndpoint(conn, iceEndpoint, immediateEndpointICE))

	endpoints := wgIface.recordedEndpoints()
	require.Len(t, endpoints, 2, "each endpoint update must reach the interface")
	require.Equal(t, iceEndpoint, endpoints[0], "the new ICE endpoint must bypass responder fallback")
	require.Nil(t, endpoints[1], "later ICE updates must restore responder fallback")
}

func TestConnReconfigureForceRelayKeepsRelayFallbackWhileArmingICE(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	wgIface := &recordingForceRelayTestWGIface{}
	conn := newForceRelayTestConnWithIface(t, ctx, true, wgIface)
	require.NoError(t, conn.Open(ctx))
	t.Cleanup(func() { conn.Close(false) })

	reconfigured, err := conn.ReconfigureForceRelay(ctx, false)
	require.NoError(t, err)
	require.True(t, reconfigured, "an open peer must add ICE in place")

	iceEndpoint := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 51820}
	relayEndpoint := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 10001}

	require.NoError(t, configureForceRelayTestEndpoint(conn, relayEndpoint, immediateEndpointRelay))
	require.NoError(t, configureForceRelayTestEndpoint(conn, iceEndpoint, immediateEndpointICE))

	endpoints := wgIface.recordedEndpoints()
	require.Len(t, endpoints, 2, "each endpoint update must reach the interface")
	require.Nil(t, endpoints[0], "the retained relay must keep normal responder fallback")
	require.Equal(t, iceEndpoint, endpoints[1], "the new ICE endpoint must bypass responder fallback")
}

func TestConnReconfigureForceRelayProgramsRelayImmediatelyWhenEnabled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	wgIface := &recordingForceRelayTestWGIface{}
	conn := newForceRelayTestConnWithIface(t, ctx, false, wgIface)
	require.NoError(t, conn.Open(ctx))
	t.Cleanup(func() { conn.Close(false) })

	reconfigured, err := conn.ReconfigureForceRelay(ctx, true)
	require.NoError(t, err)
	require.True(t, reconfigured, "an open peer without a ready relay must use fallback replacement")
	require.Nil(t, conn.workerICE,
		"the fallback replacement must apply relay-only mode")
	assertForceRelayTestTransportCounts(t, wgIface, 1)

	relayEndpoint := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 10001}
	require.NoError(t, configureForceRelayTestEndpoint(conn, relayEndpoint, immediateEndpointRelay))
	require.NoError(t, configureForceRelayTestEndpoint(conn, relayEndpoint, immediateEndpointRelay))

	endpoints := wgIface.recordedEndpoints()
	require.Len(t, endpoints, 2, "each endpoint update must reach the interface")
	require.Equal(t, relayEndpoint, endpoints[0], "relay endpoint must bypass responder fallback")
	require.Nil(t, endpoints[1], "later relay updates must restore responder fallback")
}

func configureForceRelayTestEndpoint(
	conn *Conn,
	endpoint *net.UDPAddr,
	target immediateEndpointUpdate,
) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.configureWGEndpoint(endpoint, nil, target)
}

func newForceRelayTestConn(t *testing.T, ctx context.Context, forceRelay bool) *Conn {
	t.Helper()
	return newForceRelayTestConnWithIface(t, ctx, forceRelay, forceRelayTestWGIface{})
}

func newForceRelayTestConnWithIface(
	t *testing.T,
	ctx context.Context,
	forceRelay bool,
	wgIface WGIface,
) *Conn {
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
			WgInterface: wgIface,
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
