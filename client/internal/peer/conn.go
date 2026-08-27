package peer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/ice/v4"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/iface/wgproxy"
	"github.com/netbirdio/netbird/client/internal/metrics"
	"github.com/netbirdio/netbird/client/internal/peer/conntype"
	"github.com/netbirdio/netbird/client/internal/peer/dispatcher"
	"github.com/netbirdio/netbird/client/internal/peer/guard"
	icemaker "github.com/netbirdio/netbird/client/internal/peer/ice"
	"github.com/netbirdio/netbird/client/internal/peer/id"
	"github.com/netbirdio/netbird/client/internal/peer/worker"
	"github.com/netbirdio/netbird/client/internal/portforward"
	"github.com/netbirdio/netbird/client/internal/rosenpass"
	"github.com/netbirdio/netbird/client/internal/stdnet"
	"github.com/netbirdio/netbird/client/netevents"
	"github.com/netbirdio/netbird/route"
	relayClient "github.com/netbirdio/netbird/shared/relay/client"
)

// wgTimeoutEscalationThreshold is the number of consecutive WireGuard
// handshake timeouts after which the rosenpass state for the peer is
// considered desynced and gets reset.
const wgTimeoutEscalationThreshold = 3

type immediateEndpointUpdate uint8

const (
	immediateEndpointRelay immediateEndpointUpdate = 1 << iota
	immediateEndpointICE
)

// MetricsRecorder is an interface for recording peer connection metrics
type MetricsRecorder interface {
	RecordConnectionStages(
		ctx context.Context,
		remotePubKey string,
		connectionType metrics.ConnectionType,
		isReconnection bool,
		timestamps metrics.ConnectionStageTimestamps,
	)
}

type ServiceDependencies struct {
	StatusRecorder     *Status
	Signaler           *Signaler
	IFaceDiscover      stdnet.ExternalIFaceDiscover
	RelayManager       *relayClient.Manager
	SrWatcher          *guard.SRWatcher
	PeerConnDispatcher *dispatcher.ConnectionDispatcher
	PortForwardManager *portforward.Manager
	MetricsRecorder    MetricsRecorder
}

type WgConfig struct {
	WgListenPort int
	RemoteKey    string
	WgInterface  WGIface
	AllowedIps   []netip.Prefix
	PreSharedKey *wgtypes.Key
}

type RosenpassConfig struct {
	// RosenpassPubKey is this peer's Rosenpass public key
	PubKey []byte
	// RosenpassPubKey is this peer's RosenpassAddr server address (IP:port)
	Addr string

	PermissiveMode bool
}

// ConnConfig is a peer Connection configuration
type ConnConfig struct {
	// Key is a public key of a remote peer
	Key string
	// LocalKey is a public key of a local peer
	LocalKey string

	AgentVersion string

	Timeout time.Duration

	WgConfig WgConfig

	LocalWgPort int

	RosenpassConfig RosenpassConfig

	// ICEConfig ICE protocol configuration
	ICEConfig icemaker.Config

	// ForceRelay disables ICE for this connection run. The engine updates it
	// through ReconfigureForceRelay instead of mutating process environment.
	ForceRelay bool

	// NetMgr gates the reconnection guard on OS-reported network
	// availability; nil disables gating.
	NetMgr *netevents.Manager
}

type Conn struct {
	Log                *log.Entry
	lifecycleMu        sync.Mutex
	mu                 sync.Mutex
	ctx                context.Context
	ctxCancel          context.CancelFunc
	config             ConnConfig
	statusRecorder     *Status
	signaler           *Signaler
	iFaceDiscover      stdnet.ExternalIFaceDiscover
	relayManager       *relayClient.Manager
	srWatcher          *guard.SRWatcher
	portForwardManager *portforward.Manager

	onConnected                               func(remoteWireGuardKey string, remoteRosenpassPubKey []byte, wireGuardIP string, remoteRosenpassAddr string)
	onDisconnected                            func(remotePeer string)
	rosenpassInitializedPresharedKeyValidator func(peerKey string) bool

	statusRelay         *worker.AtomicWorkerStatus
	statusICE           *worker.AtomicWorkerStatus
	currentConnPriority conntype.ConnPriority
	opened              bool // this flag is used to prevent close in case of not opened connection

	workerICE       *WorkerICE
	workerRelay     *WorkerRelay
	forceRelayState atomic.Uint32
	// workerICESnapshot lets the guard inspect the optional worker without
	// taking mu while Close waits for the guard to stop.
	workerICESnapshot atomic.Pointer[WorkerICE]
	// immediateEndpointUpdates is a one-shot mask for the first relay and ICE
	// endpoint configurations in a runtime policy transition. Guarded by mu.
	immediateEndpointUpdates immediateEndpointUpdate

	wgWatcher       *WGWatcher
	wgWatcherWg     sync.WaitGroup
	wgWatcherCancel context.CancelFunc
	// wgTimeouts counts consecutive WireGuard handshake timeouts without a
	// successful handshake in between. Guarded by mu.
	wgTimeouts int

	// used to store the remote Rosenpass key for Relayed connection in case of connection update from ice
	rosenpassRemoteKey []byte

	wgProxyICE   wgproxy.Proxy
	wgProxyRelay wgproxy.Proxy
	handshaker   *Handshaker

	guard *guard.Guard
	wg    sync.WaitGroup

	// debug purpose
	dumpState *stateDump

	endpointUpdater *EndpointUpdater

	// Connection stage timestamps for metrics
	metricsRecorder MetricsRecorder
	metricsStages   *MetricsStages

	// pendingFirstPacket is the lazyconn-captured handshake init, replayed once the real
	// transport is up.
	pendingFirstPacket []byte
}

type forceRelayState uint32

const (
	forceRelayStateDisabled forceRelayState = iota
	forceRelayStatePending
	forceRelayStateEnabled
)

func (s forceRelayState) desired() bool {
	return s != forceRelayStateDisabled
}

func (s forceRelayState) applied() bool {
	return s == forceRelayStateEnabled
}

func (s forceRelayState) pending() bool {
	return s == forceRelayStatePending
}

// injectPendingFirstPacket replays the captured handshake through the proxy if present, else
// directly through the ICE conn. The packet is cleared only after a successful write, so a failed
// or transport-less attempt leaves it available for a later reinjection. Caller must hold conn.mu.
func (conn *Conn) injectPendingFirstPacket(proxy wgproxy.Proxy, directConn net.Conn) {
	pkt := conn.pendingFirstPacket
	if len(pkt) == 0 {
		return
	}

	switch {
	case proxy != nil:
		if err := proxy.InjectPacket(pkt); err != nil {
			conn.Log.Debugf("failed to reinject captured first packet via proxy: %v", err)
			return
		}
	case directConn != nil:
		if _, err := directConn.Write(pkt); err != nil {
			conn.Log.Debugf("failed to reinject captured first packet via direct conn: %v", err)
			return
		}
	default:
		conn.Log.Debugf("no transport available to reinject captured first packet")
		return
	}

	conn.pendingFirstPacket = nil
	conn.Log.Debugf("reinjected captured first packet (%d bytes)", len(pkt))
}

// NewConn creates a new not opened Conn to the remote peer.
// To establish a connection run Conn.Open
func NewConn(config ConnConfig, services ServiceDependencies) (*Conn, error) {
	if len(config.WgConfig.AllowedIps) == 0 {
		return nil, fmt.Errorf("allowed IPs is empty")
	}

	connLog := log.WithField("peer", config.Key)

	dumpState := newStateDump(config.Key, connLog, services.StatusRecorder)
	var conn = &Conn{
		Log:                connLog,
		config:             config,
		statusRecorder:     services.StatusRecorder,
		signaler:           services.Signaler,
		iFaceDiscover:      services.IFaceDiscover,
		relayManager:       services.RelayManager,
		srWatcher:          services.SrWatcher,
		portForwardManager: services.PortForwardManager,
		statusRelay:        worker.NewAtomicStatus(),
		statusICE:          worker.NewAtomicStatus(),
		dumpState:          dumpState,
		endpointUpdater:    NewEndpointUpdater(connLog, config.WgConfig, isController(config)),
		metricsRecorder:    services.MetricsRecorder,
	}
	if config.ForceRelay {
		conn.forceRelayState.Store(uint32(forceRelayStateEnabled))
	}

	return conn, nil
}

// Open opens connection to the remote peer
// It will try to establish a connection using ICE and in parallel with relay. The higher priority connection type will
// be used.
func (conn *Conn) Open(engineCtx context.Context) error {
	conn.lifecycleMu.Lock()
	defer conn.lifecycleMu.Unlock()
	return conn.open(engineCtx, nil, 0)
}

// OpenWithFirstPacket opens the connection like Open and stashes firstPacket to be replayed once
// the real transport is established. The packet is retained only on a successful open.
func (conn *Conn) OpenWithFirstPacket(engineCtx context.Context, firstPacket []byte) error {
	conn.lifecycleMu.Lock()
	defer conn.lifecycleMu.Unlock()
	return conn.open(engineCtx, firstPacket, 0)
}

func (conn *Conn) open(
	engineCtx context.Context,
	firstPacket []byte,
	immediateUpdates immediateEndpointUpdate,
) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.opened {
		return nil
	}

	metricsStages := &MetricsStages{}
	peerCtx, peerCtxCancel := context.WithCancel(engineCtx)
	forceRelay := conn.loadForceRelayState().desired()
	runConfig := conn.config
	runConfig.ForceRelay = forceRelay
	workerRelay := NewWorkerRelay(peerCtx, conn.Log, isController(runConfig), runConfig, conn, conn.relayManager)

	var workerICE *WorkerICE
	if !forceRelay {
		relayIsSupportedLocally := workerRelay.RelayIsSupportedLocally()
		var err error
		workerICE, err = NewWorkerICE(peerCtx, conn.Log, runConfig, conn, conn.signaler, conn.iFaceDiscover, conn.statusRecorder, relayIsSupportedLocally)
		if err != nil {
			peerCtxCancel()
			workerRelay.CloseConn()
			return err
		}
	}

	handshaker := NewHandshaker(conn.Log, runConfig, conn.signaler, workerICE, workerRelay, metricsStages)

	handshaker.AddRelayListener(workerRelay.OnNewOffer)
	if !forceRelay {
		handshaker.AddICEListener(workerICE.OnNewOffer)
	}

	connectionGuard := guard.NewGuard(conn.Log, conn.isConnectedOnAllWay, conn.config.Timeout, conn.srWatcher, conn.config.NetMgr)

	conn.ctx = peerCtx
	conn.ctxCancel = peerCtxCancel
	conn.metricsStages = metricsStages
	conn.workerRelay = workerRelay
	conn.workerICE = workerICE
	conn.workerICESnapshot.Store(workerICE)
	conn.handshaker = handshaker
	conn.guard = connectionGuard
	conn.immediateEndpointUpdates = immediateUpdates
	if forceRelay {
		conn.setForceRelayState(forceRelayStateEnabled)
	} else {
		conn.setForceRelayState(forceRelayStateDisabled)
	}

	conn.wg.Add(1)
	go func(handshaker *Handshaker, peerCtx context.Context) {
		defer conn.wg.Done()
		handshaker.Listen(peerCtx)
	}(handshaker, peerCtx)
	go conn.dumpState.Start(peerCtx)

	peerState := State{
		PubKey:           conn.config.Key,
		ConnStatusUpdate: time.Now(),
		ConnStatus:       StatusConnecting,
		Mux:              new(sync.RWMutex),
	}
	if err := conn.statusRecorder.UpdatePeerState(peerState); err != nil {
		conn.Log.Warnf("error while updating the state err: %v", err)
	}

	conn.wg.Add(1)
	go func(connectionGuard *guard.Guard, peerCtx context.Context) {
		defer conn.wg.Done()
		connectionGuard.Start(peerCtx, conn.onGuardEvent)
	}(connectionGuard, peerCtx)
	if len(firstPacket) > 0 {
		conn.pendingFirstPacket = slices.Clone(firstPacket)
	}
	conn.opened = true
	return nil
}

// Close closes this peer Conn issuing a close event to the Conn closeCh
func (conn *Conn) Close(signalToRemote bool) {
	conn.lifecycleMu.Lock()
	defer conn.lifecycleMu.Unlock()
	conn.close(signalToRemote)
}

func (conn *Conn) close(signalToRemote bool) {
	conn.mu.Lock()
	defer conn.wgWatcherWg.Wait()
	defer conn.mu.Unlock()
	conn.setPendingICEMonitorRequired(false)

	if !conn.opened {
		conn.Log.Debugf("ignore close connection to peer")
		return
	}

	if signalToRemote {
		if err := conn.signaler.SignalIdle(conn.config.Key); err != nil {
			conn.Log.Errorf("failed to signal idle state to peer: %v", err)
		}
	}

	conn.Log.Infof("close peer connection")
	conn.ctxCancel()

	if conn.wgWatcherCancel != nil {
		conn.wgWatcherCancel()
		conn.wgWatcher = nil
		conn.wgWatcherCancel = nil
	}
	conn.workerRelay.CloseConn()
	if conn.workerICE != nil {
		conn.workerICE.Close()
	}

	if conn.wgProxyRelay != nil {
		err := conn.wgProxyRelay.CloseConn()
		if err != nil {
			conn.Log.Errorf("failed to close wg proxy for relay: %v", err)
		}
		conn.wgProxyRelay = nil
	}

	if conn.wgProxyICE != nil {
		err := conn.wgProxyICE.CloseConn()
		if err != nil {
			conn.Log.Errorf("failed to close wg proxy for ice: %v", err)
		}
		conn.wgProxyICE = nil
	}

	if err := conn.endpointUpdater.RemoveWgPeer(); err != nil {
		conn.Log.Errorf("failed to remove wg endpoint: %v", err)
	}

	if conn.evalStatus() == StatusConnected && conn.onDisconnected != nil {
		conn.onDisconnected(conn.config.WgConfig.RemoteKey)
	}

	conn.setStatusToDisconnected()
	conn.opened = false
	conn.wg.Wait()
	conn.ctx = nil
	conn.ctxCancel = nil
	conn.workerRelay = nil
	conn.workerICE = nil
	conn.workerICESnapshot.Store(nil)
	conn.handshaker = nil
	conn.guard = nil
	conn.immediateEndpointUpdates = 0
	conn.Log.Infof("peer connection closed")
}

// ReconfigureForceRelay applies a transport policy change to an open peer while
// preserving an available relay or ICE path. Closed lazy peers remain idle and
// use the new mode on the next activation.
func (conn *Conn) ReconfigureForceRelay(_ context.Context, enabled bool) (bool, error) {
	conn.lifecycleMu.Lock()
	defer conn.lifecycleMu.Unlock()

	conn.mu.Lock()
	state := conn.loadForceRelayState()
	if !conn.opened {
		if enabled {
			conn.setForceRelayState(forceRelayStateEnabled)
		} else {
			conn.setForceRelayState(forceRelayStateDisabled)
		}
		conn.mu.Unlock()
		return false, nil
	}

	if !enabled {
		if state == forceRelayStateDisabled {
			conn.mu.Unlock()
			return false, nil
		}
		handshaker, err := conn.enableICELocked()
		conn.mu.Unlock()
		if err != nil {
			return true, err
		}
		if state.pending() {
			conn.Log.Infof("cancelled pending force-relay transition; keep ICE active")
		}
		conn.signalForceRelayUpdate(handshaker)
		return true, nil
	}

	if state == forceRelayStateEnabled {
		conn.mu.Unlock()
		return false, nil
	}
	wasPending := state.pending()
	conn.setForceRelayState(forceRelayStatePending)
	conn.immediateEndpointUpdates |= immediateEndpointRelay
	retiredICE, applied, err := conn.enableForceRelayLocked()
	handshaker := conn.handshaker
	conn.mu.Unlock()
	if err != nil {
		conn.Log.Warnf("force-relay transition remains pending after relay switch failed: %v", err)
		return !wasPending, err
	}
	if applied {
		conn.Log.Infof("force-relay transition applied using ready relay")
		conn.signalForceRelayUpdate(handshaker)
		retiredICE.close(conn.Log)
		return true, nil
	}

	if !wasPending {
		conn.Log.Infof("force-relay transition pending; keep ICE active until relay is ready")
	}
	conn.signalForceRelayUpdate(handshaker)
	return !wasPending, nil
}

type retiredICETransport struct {
	worker *WorkerICE
	proxy  wgproxy.Proxy
}

func (r retiredICETransport) close(log *log.Entry) {
	if r.worker != nil {
		r.worker.Close()
	}
	if r.proxy != nil {
		if err := r.proxy.CloseConn(); err != nil {
			log.Warnf("failed to close retired ICE proxy: %v", err)
		}
	}
}

// enableICELocked adds ICE to the live handshaker without disturbing relay.
// Caller must hold conn.mu.
func (conn *Conn) enableICELocked() (*Handshaker, error) {
	if conn.workerICE == nil {
		runConfig := conn.config
		runConfig.ForceRelay = false
		workerICE, err := NewWorkerICE(
			conn.ctx,
			conn.Log,
			runConfig,
			conn,
			conn.signaler,
			conn.iFaceDiscover,
			conn.statusRecorder,
			conn.workerRelay.RelayIsSupportedLocally(),
		)
		if err != nil {
			return nil, err
		}
		conn.workerICE = workerICE
		conn.workerICESnapshot.Store(workerICE)
		conn.handshaker.setICEWorker(workerICE)
	}

	conn.immediateEndpointUpdates &^= immediateEndpointRelay
	conn.immediateEndpointUpdates |= immediateEndpointICE
	conn.setForceRelayState(forceRelayStateDisabled)
	return conn.handshaker, nil
}

// enableForceRelayLocked switches to an established relay before detaching ICE.
// Caller must hold conn.mu.
func (conn *Conn) enableForceRelayLocked() (retiredICETransport, bool, error) {
	if conn.workerICE == nil {
		conn.setForceRelayState(forceRelayStateEnabled)
		return retiredICETransport{}, true, nil
	}
	if conn.wgProxyRelay == nil || conn.statusRelay.Get() != worker.StatusConnected {
		return retiredICETransport{}, false, nil
	}

	if conn.currentConnPriority != conntype.Relay {
		relayEndpoint := conn.wgProxyRelay.EndpointAddr()
		if relayEndpoint == nil {
			return retiredICETransport{}, false, errors.New("relay endpoint is unavailable")
		}
		conn.wgProxyRelay.Work()
		presharedKey := conn.presharedKey(conn.rosenpassRemoteKey)
		if err := conn.endpointUpdater.SwitchWGEndpoint(relayEndpoint, presharedKey); err != nil {
			conn.wgProxyRelay.Pause()
			return retiredICETransport{}, false, fmt.Errorf("switch to relay endpoint: %w", err)
		}
		wgConfigWorkaround()
		conn.currentConnPriority = conntype.Relay
	}

	conn.handshaker.setICEWorker(nil)
	retired := retiredICETransport{
		worker: conn.workerICE,
		proxy:  conn.wgProxyICE,
	}
	conn.workerICE = nil
	conn.workerICESnapshot.Store(nil)
	conn.wgProxyICE = nil
	conn.statusICE.SetDisconnected()
	conn.immediateEndpointUpdates = 0
	conn.setForceRelayState(forceRelayStateEnabled)
	conn.recordForceRelayTransitionLocked()
	return retired, true, nil
}

// recordForceRelayTransitionLocked records the transport change without
// reporting the peer disconnected. Caller must hold conn.mu.
func (conn *Conn) recordForceRelayTransitionLocked() {
	peerState := State{
		PubKey:           conn.config.Key,
		ConnStatus:       conn.evalStatus(),
		Relayed:          true,
		ConnStatusUpdate: time.Now(),
	}
	if err := conn.statusRecorder.UpdatePeerICEStateToDisconnected(peerState); err != nil {
		conn.Log.Warnf("unable to record force-relay transition: %v", err)
	}
}

func (conn *Conn) signalForceRelayUpdate(handshaker *Handshaker) {
	if err := handshaker.SendOffer(); err != nil {
		if errors.Is(err, ErrSignalIsNotReady) {
			conn.Log.Debugf("defer force-relay transport signaling: %v", err)
			return
		}
		conn.Log.Warnf("failed to signal force-relay transport update: %v", err)
	}
}

// ForceRelayEnabled reports whether relay-only mode is applied to the current
// connection run, or selected for the next closed lazy-peer run.
func (conn *Conn) ForceRelayEnabled() bool {
	return conn.loadForceRelayState().applied()
}

// ForceRelayDesired reports whether relay-only mode is requested, including a
// pending transition that is still using ICE.
func (conn *Conn) ForceRelayDesired() bool {
	return conn.loadForceRelayState().desired()
}

// ForceRelayPending reports that relay-only mode is requested but the peer is
// preserving ICE until a relay connection becomes ready.
func (conn *Conn) ForceRelayPending() bool {
	return conn.loadForceRelayState().pending()
}

func (conn *Conn) loadForceRelayState() forceRelayState {
	return forceRelayState(conn.forceRelayState.Load())
}

// setForceRelayState publishes a consistent desired/applied/pending snapshot
// and keeps the shared ICE monitor alive for the pending peer.
func (conn *Conn) setForceRelayState(state forceRelayState) {
	conn.forceRelayState.Store(uint32(state))
	conn.setPendingICEMonitorRequired(state.pending())
}

func (conn *Conn) setPendingICEMonitorRequired(required bool) {
	if conn.srWatcher != nil {
		conn.srWatcher.SetPeerICEMonitorRequired(conn.config.Key, required)
	}
}

// OnNetworkChange drops the ICE session bound to the transport the OS just
// left. A handover silently invalidates ICE sockets, but the agent only
// notices after its timeouts; closing it here collapses that wait and hands
// the peer back to the relay immediately.
func (conn *Conn) OnNetworkChange() {
	conn.lifecycleMu.Lock()
	defer conn.lifecycleMu.Unlock()

	conn.mu.Lock()

	if !conn.opened || conn.ctx.Err() != nil || conn.workerICE == nil {
		conn.mu.Unlock()
		return
	}

	workerICE := conn.workerICE
	iceWasConnected := conn.statusICE.Get() == worker.StatusConnected
	conn.mu.Unlock()

	// Close outside the lock: agent.Close() delivers a final state change
	// whose handler re-takes conn.mu.
	workerICE.OnNetworkChange()

	// Still negotiating — nothing to unwind; the guard wakes on its own.
	if !iceWasConnected {
		return
	}

	conn.mu.Lock()
	defer conn.mu.Unlock()

	// Re-check: the connection may have been closed or reopened while unlocked.
	if !conn.opened || conn.workerICE != workerICE {
		return
	}

	// sessionChanged: the worker rotated its session ID on close.
	conn.handleICEDisconnectedLocked(true)
}

// OnRemoteAnswer handles an offer from the remote peer and returns true if the message was accepted, false otherwise
// doesn't block, discards the message if connection wasn't ready
func (conn *Conn) OnRemoteAnswer(answer OfferAnswer) {
	conn.lifecycleMu.Lock()
	defer conn.lifecycleMu.Unlock()

	conn.dumpState.RemoteAnswer()
	conn.mu.Lock()
	handshaker := conn.handshaker
	priority := conn.currentConnPriority
	conn.mu.Unlock()
	conn.Log.Infof("OnRemoteAnswer, priority: %s, status ICE: %s, status relay: %s", priority, conn.statusICE, conn.statusRelay)
	if handshaker != nil {
		handshaker.OnRemoteAnswer(answer)
	}
}

// OnRemoteCandidate Handles ICE connection Candidate provided by the remote peer.
func (conn *Conn) OnRemoteCandidate(candidate ice.Candidate, haRoutes route.HAMap) {
	conn.lifecycleMu.Lock()
	defer conn.lifecycleMu.Unlock()

	conn.dumpState.RemoteCandidate()
	conn.mu.Lock()
	workerICE := conn.workerICE
	conn.mu.Unlock()
	if workerICE != nil {
		workerICE.OnRemoteCandidate(candidate, haRoutes)
	}
}

// SetOnConnected sets a handler function to be triggered by Conn when a new connection to a remote peer established
func (conn *Conn) SetOnConnected(handler func(remoteWireGuardKey string, remoteRosenpassPubKey []byte, wireGuardIP string, remoteRosenpassAddr string)) {
	conn.onConnected = handler
}

// SetOnDisconnected sets a handler function to be triggered by Conn when a connection to a remote disconnected
func (conn *Conn) SetOnDisconnected(handler func(remotePeer string)) {
	conn.onDisconnected = handler
}

// SetRosenpassInitializedPresharedKeyValidator sets a function to check if Rosenpass has taken over
// PSK management for a peer. When this returns true, presharedKey() returns nil
// to prevent UpdatePeer from overwriting the Rosenpass-managed PSK.
func (conn *Conn) SetRosenpassInitializedPresharedKeyValidator(handler func(peerKey string) bool) {
	conn.rosenpassInitializedPresharedKeyValidator = handler
}

func (conn *Conn) OnRemoteOffer(offer OfferAnswer) {
	conn.lifecycleMu.Lock()
	defer conn.lifecycleMu.Unlock()

	conn.dumpState.RemoteOffer()
	conn.Log.Infof("OnRemoteOffer, on status ICE: %s, status Relay: %s", conn.statusICE, conn.statusRelay)
	conn.mu.Lock()
	handshaker := conn.handshaker
	conn.mu.Unlock()
	if handshaker != nil {
		handshaker.OnRemoteOffer(offer)
	}
}

// WgConfig returns the WireGuard config
func (conn *Conn) WgConfig() WgConfig {
	return conn.config.WgConfig
}

// IsConnected returns true if the peer is connected
func (conn *Conn) IsConnected() bool {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	return conn.evalStatus() == StatusConnected
}

func (conn *Conn) GetKey() string {
	return conn.config.Key
}

func (conn *Conn) ConnID() id.ConnID {
	return id.ConnID(conn)
}

// configureConnection starts proxying traffic from/to local Wireguard and sets connection status to StatusConnected
func (conn *Conn) onICEConnectionIsReady(workerICE *WorkerICE, priority conntype.ConnPriority, iceConnInfo ICEConnInfo) {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.workerICE != workerICE || workerICE.ctx.Err() != nil {
		if iceConnInfo.RemoteConn != nil {
			if err := iceConnInfo.RemoteConn.Close(); err != nil {
				conn.Log.Debugf("close connection from stale ICE worker: %v", err)
			}
		}
		return
	}

	if remoteConnNil(conn.Log, iceConnInfo.RemoteConn) {
		conn.Log.Errorf("remote ICE connection is nil")
		return
	}

	// this never should happen, because Relay is the lower priority and ICE always close the deprecated connection before upgrade
	// todo consider to remove this check
	if conn.currentConnPriority > priority {
		conn.Log.Infof("current connection priority (%s) is higher than the new one (%s), do not upgrade connection", conn.currentConnPriority, priority)
		conn.statusICE.SetConnected()
		conn.updateIceState(iceConnInfo, time.Now())
		return
	}

	conn.Log.Infof("set ICE to active connection")
	conn.dumpState.P2PConnected()

	var (
		ep      *net.UDPAddr
		wgProxy wgproxy.Proxy
		err     error
	)
	if iceConnInfo.RelayedOnLocal {
		conn.dumpState.NewLocalProxy()
		wgProxy, err = conn.newProxy(iceConnInfo.RemoteConn)
		if err != nil {
			conn.Log.Errorf("failed to add relayed net.Conn to local proxy: %v", err)
			return
		}
		ep = wgProxy.EndpointAddr()
		conn.wgProxyICE = wgProxy
	} else {
		directEp, err := net.ResolveUDPAddr("udp", iceConnInfo.RemoteConn.RemoteAddr().String())
		if err != nil {
			log.Errorf("failed to resolveUDPaddr")
			conn.handleConfigurationFailure(err, nil)
			return
		}
		ep = directEp
	}

	if conn.wgProxyRelay != nil {
		conn.wgProxyRelay.Pause()
	}

	if wgProxy != nil {
		wgProxy.Work()
	}

	conn.Log.Infof("configure WireGuard endpoint to: %s", ep.String())
	updateTime := time.Now()
	conn.enableWgWatcherIfNeeded(updateTime)

	presharedKey := conn.presharedKey(iceConnInfo.RosenpassPubKey)
	if err = conn.configureWGEndpoint(ep, presharedKey, immediateEndpointICE); err != nil {
		conn.handleConfigurationFailure(err, wgProxy)
		return
	}
	wgConfigWorkaround()

	if conn.wgProxyRelay != nil {
		conn.Log.Debugf("redirect packets from relayed conn to WireGuard")
		conn.wgProxyRelay.RedirectAs(ep)
	}

	conn.injectPendingFirstPacket(wgProxy, iceConnInfo.RemoteConn)

	conn.currentConnPriority = priority
	conn.statusICE.SetConnected()
	conn.updateIceState(iceConnInfo, updateTime)
	conn.doOnConnected(iceConnInfo.RosenpassPubKey, iceConnInfo.RosenpassAddr, updateTime)
}

func (conn *Conn) onICEStateDisconnected(workerICE *WorkerICE, sessionChanged bool) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.workerICE != workerICE {
		return
	}
	conn.handleICEDisconnectedLocked(sessionChanged)
}

// handleICEDisconnectedLocked handles ICE disconnection. Caller must hold conn.mu.
func (conn *Conn) handleICEDisconnectedLocked(sessionChanged bool) {
	if conn.ctx.Err() != nil {
		return
	}

	conn.Log.Tracef("ICE connection state changed to disconnected")

	if conn.wgProxyICE != nil {
		if err := conn.wgProxyICE.CloseConn(); err != nil {
			conn.Log.Warnf("failed to close deprecated wg proxy conn: %v", err)
		}
	}

	// switch back to relay connection
	if conn.isReadyToUpgrade() {
		conn.Log.Infof("ICE disconnected, set Relay to active connection")
		conn.dumpState.SwitchToRelay()
		if sessionChanged {
			conn.resetEndpoint()
		}

		// todo consider to move after the ConfigureWGEndpoint
		conn.wgProxyRelay.Work()

		presharedKey := conn.presharedKey(conn.rosenpassRemoteKey)
		if err := conn.endpointUpdater.SwitchWGEndpoint(conn.wgProxyRelay.EndpointAddr(), presharedKey); err != nil {
			conn.Log.Errorf("failed to switch to relay conn: %v", err)
		}

		conn.currentConnPriority = conntype.Relay
	} else {
		conn.Log.Infof("ICE disconnected, do not switch to Relay. Reset priority to: %s", conntype.None.String())
		conn.currentConnPriority = conntype.None
		if err := conn.config.WgConfig.WgInterface.RemoveEndpointAddress(conn.config.WgConfig.RemoteKey); err != nil {
			conn.Log.Errorf("failed to remove wg endpoint: %v", err)
		}
	}

	changed := conn.statusICE.Get() != worker.StatusDisconnected
	if changed {
		conn.guard.SetICEConnDisconnected()
	}
	conn.statusICE.SetDisconnected()

	conn.disableWgWatcherIfNeeded()

	if conn.currentConnPriority == conntype.None {
		conn.metricsStages.Disconnected()
	}

	peerState := State{
		PubKey:           conn.config.Key,
		ConnStatus:       conn.evalStatus(),
		Relayed:          conn.isRelayed(),
		ConnStatusUpdate: time.Now(),
	}
	if err := conn.statusRecorder.UpdatePeerICEStateToDisconnected(peerState); err != nil {
		conn.Log.Warnf("unable to set peer's state to disconnected ice, got error: %v", err)
	}
}

func (conn *Conn) onRelayConnectionIsReady(workerRelay *WorkerRelay, rci RelayConnInfo) {
	conn.mu.Lock()
	var retiredICE retiredICETransport
	var signalHandshaker *Handshaker
	defer func() {
		conn.mu.Unlock()
		if signalHandshaker != nil {
			conn.signalForceRelayUpdate(signalHandshaker)
		}
		retiredICE.close(conn.Log)
	}()

	if conn.workerRelay != workerRelay || workerRelay.peerCtx.Err() != nil {
		if err := rci.relayedConn.Close(); err != nil {
			conn.Log.Warnf("failed to close unnecessary relayed connection: %v", err)
		}
		return
	}

	conn.dumpState.RelayConnected()
	conn.Log.Debugf("Relay connection has been established, setup the WireGuard")

	wgProxy, err := conn.newProxy(rci.relayedConn)
	if err != nil {
		conn.Log.Errorf("failed to add relayed net.Conn to local proxy: %v", err)
		return
	}
	wgProxy.SetDisconnectListener(func() { conn.onRelayDisconnected(workerRelay) })

	conn.dumpState.NewLocalProxy()

	conn.Log.Infof("created new wgProxy for relay connection: %s", wgProxy.EndpointAddr().String())
	conn.rosenpassRemoteKey = rci.rosenpassPubKey

	if conn.isICEActive() {
		conn.Log.Debugf("do not switch to relay because current priority is: %s", conn.currentConnPriority.String())
		conn.setRelayedProxy(wgProxy)
		conn.statusRelay.SetConnected()
		conn.updateRelayStatus(rci.relayedConn.RemoteAddr().String(), rci.rosenpassPubKey, time.Now())
		retiredICE, signalHandshaker = conn.completePendingForceRelayLocked()
		return
	}

	controller := isController(conn.config)

	if controller {
		wgProxy.Work()
	}
	updateTime := time.Now()
	conn.enableWgWatcherIfNeeded(updateTime)
	if err := conn.configureWGEndpoint(
		wgProxy.EndpointAddr(),
		conn.presharedKey(rci.rosenpassPubKey),
		immediateEndpointRelay,
	); err != nil {
		if err := wgProxy.CloseConn(); err != nil {
			conn.Log.Warnf("Failed to close relay connection: %v", err)
		}
		conn.Log.Errorf("Failed to update WireGuard peer configuration: %v", err)
		return
	}
	if !controller {
		wgProxy.Work()
	}

	wgConfigWorkaround()

	conn.injectPendingFirstPacket(wgProxy, nil)

	conn.currentConnPriority = conntype.Relay
	conn.statusRelay.SetConnected()
	conn.setRelayedProxy(wgProxy)
	conn.updateRelayStatus(rci.relayedConn.RemoteAddr().String(), rci.rosenpassPubKey, updateTime)
	conn.Log.Infof("start to communicate with peer via relay")
	conn.doOnConnected(rci.rosenpassPubKey, rci.rosenpassAddr, updateTime)
	retiredICE, signalHandshaker = conn.completePendingForceRelayLocked()
}

// completePendingForceRelayLocked finalizes a pending request after the relay
// callback has published a connected proxy. Caller must hold conn.mu.
func (conn *Conn) completePendingForceRelayLocked() (retiredICETransport, *Handshaker) {
	if !conn.loadForceRelayState().pending() {
		return retiredICETransport{}, nil
	}

	retiredICE, applied, err := conn.enableForceRelayLocked()
	if err != nil {
		conn.Log.Errorf("failed to apply pending force-relay transition: %v", err)
		conn.handleRelayDisconnectedLocked()
		return retiredICETransport{}, nil
	}
	if !applied {
		return retiredICETransport{}, nil
	}

	conn.Log.Infof("pending force-relay transition applied after relay became ready")
	return retiredICE, conn.handshaker
}

// configureWGEndpoint programs the endpoint selected by a ready transport.
// Caller must hold conn.mu.
func (conn *Conn) configureWGEndpoint(
	endpoint *net.UDPAddr,
	presharedKey *wgtypes.Key,
	target immediateEndpointUpdate,
) error {
	if conn.immediateEndpointUpdates&target != 0 {
		if err := conn.endpointUpdater.SwitchWGEndpoint(endpoint, presharedKey); err != nil {
			return err
		}
		if target == immediateEndpointICE {
			conn.immediateEndpointUpdates = 0
		} else {
			conn.immediateEndpointUpdates &^= target
		}
		return nil
	}
	return conn.endpointUpdater.ConfigureWGEndpoint(endpoint, presharedKey)
}

func (conn *Conn) onRelayDisconnected(workerRelay *WorkerRelay) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.workerRelay != workerRelay {
		return
	}
	conn.handleRelayDisconnectedLocked()
}

// handleRelayDisconnectedLocked handles relay disconnection. Caller must hold conn.mu.
func (conn *Conn) handleRelayDisconnectedLocked() {
	if conn.ctx.Err() != nil {
		return
	}

	conn.Log.Debugf("relay connection is disconnected")

	if conn.currentConnPriority == conntype.Relay {
		conn.Log.Debugf("clean up WireGuard config")
		conn.currentConnPriority = conntype.None
		if err := conn.config.WgConfig.WgInterface.RemoveEndpointAddress(conn.config.WgConfig.RemoteKey); err != nil {
			conn.Log.Errorf("failed to remove wg endpoint: %v", err)
		}
	}

	if conn.wgProxyRelay != nil {
		_ = conn.wgProxyRelay.CloseConn()
		conn.wgProxyRelay = nil
	}

	changed := conn.statusRelay.Get() != worker.StatusDisconnected
	if changed {
		conn.guard.SetRelayedConnDisconnected()
	}
	conn.statusRelay.SetDisconnected()

	conn.disableWgWatcherIfNeeded()

	if conn.currentConnPriority == conntype.None {
		conn.metricsStages.Disconnected()
	}

	peerState := State{
		PubKey:           conn.config.Key,
		ConnStatus:       conn.evalStatus(),
		Relayed:          conn.isRelayed(),
		ConnStatusUpdate: time.Now(),
	}
	if err := conn.statusRecorder.UpdatePeerRelayedStateToDisconnected(peerState); err != nil {
		conn.Log.Warnf("unable to save peer's state to Relay disconnected, got error: %v", err)
	}
}

func (conn *Conn) onGuardEvent() {
	conn.dumpState.SendOffer()
	if err := conn.handshaker.SendOffer(); err != nil {
		conn.Log.Errorf("failed to send offer: %v", err)
	}
}

func (conn *Conn) onWGDisconnected(watcherCtx context.Context) {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	// watcherCtx guards against a stale watcher tearing down a connection that already superseded it.
	if conn.ctx.Err() != nil || watcherCtx.Err() != nil {
		return
	}

	conn.Log.Warnf("WireGuard handshake timeout detected, closing current connection")

	// Close the active connection based on current priority
	switch conn.currentConnPriority {
	case conntype.Relay:
		conn.workerRelay.CloseConn()
		conn.handleRelayDisconnectedLocked()
	case conntype.ICEP2P, conntype.ICETurn:
		conn.workerICE.Close()
	default:
		conn.Log.Debugf("No active connection to close on WG timeout")
	}

	conn.escalateWGTimeoutLocked()
}

// escalateWGTimeoutLocked resets the peer's rosenpass state after repeated
// handshake timeouts. With rosenpass enabled, persistent timeouts mean the
// preshared keys have desynced; the renewal exchange runs over the dead
// tunnel and cannot resync them. Reporting the peer disconnected drops its
// rosenpass state, so the next connection configuration programs the
// rendezvous key and the tunnel can bootstrap again. Callers must hold mu.
func (conn *Conn) escalateWGTimeoutLocked() {
	if conn.config.RosenpassConfig.PubKey == nil {
		return
	}

	conn.wgTimeouts++
	if conn.wgTimeouts < wgTimeoutEscalationThreshold || conn.onDisconnected == nil {
		return
	}
	conn.wgTimeouts = 0

	conn.Log.Warnf("%d consecutive WireGuard handshake timeouts, resetting rosenpass state for peer", wgTimeoutEscalationThreshold)
	conn.onDisconnected(conn.config.WgConfig.RemoteKey)
}

func (conn *Conn) updateRelayStatus(relayServerAddr string, rosenpassPubKey []byte, updateTime time.Time) {
	peerState := State{
		PubKey:             conn.config.Key,
		ConnStatusUpdate:   updateTime,
		ConnStatus:         conn.evalStatus(),
		Relayed:            conn.isRelayed(),
		RelayServerAddress: relayServerAddr,
		RosenpassEnabled:   isRosenpassEnabled(rosenpassPubKey),
	}

	err := conn.statusRecorder.UpdatePeerRelayedState(peerState)
	if err != nil {
		conn.Log.Warnf("unable to save peer's Relay state, got error: %v", err)
	}
}

func (conn *Conn) updateIceState(iceConnInfo ICEConnInfo, updateTime time.Time) {
	peerState := State{
		PubKey:                     conn.config.Key,
		ConnStatusUpdate:           updateTime,
		ConnStatus:                 conn.evalStatus(),
		Relayed:                    iceConnInfo.Relayed,
		LocalIceCandidateType:      iceConnInfo.LocalIceCandidateType,
		RemoteIceCandidateType:     iceConnInfo.RemoteIceCandidateType,
		LocalIceCandidateEndpoint:  iceConnInfo.LocalIceCandidateEndpoint,
		RemoteIceCandidateEndpoint: iceConnInfo.RemoteIceCandidateEndpoint,
		RosenpassEnabled:           isRosenpassEnabled(iceConnInfo.RosenpassPubKey),
	}

	err := conn.statusRecorder.UpdatePeerICEState(peerState)
	if err != nil {
		conn.Log.Warnf("unable to save peer's ICE state, got error: %v", err)
	}
}

func (conn *Conn) setStatusToDisconnected() {
	conn.statusRelay.SetDisconnected()
	conn.statusICE.SetDisconnected()
	conn.currentConnPriority = conntype.None

	peerState := State{
		PubKey:           conn.config.Key,
		ConnStatus:       StatusIdle,
		ConnStatusUpdate: time.Now(),
		Mux:              new(sync.RWMutex),
	}
	err := conn.statusRecorder.UpdatePeerState(peerState)
	if err != nil {
		// pretty common error because by that time Engine can already remove the peer and status won't be available.
		// todo rethink status updates
		conn.Log.Debugf("error while updating peer's state, err: %v", err)
	}
	if err := conn.statusRecorder.UpdateWireGuardPeerState(conn.config.Key, configurer.WGStats{}); err != nil {
		conn.Log.Debugf("failed to reset wireguard stats for peer: %s", err)
	}
}

func (conn *Conn) doOnConnected(remoteRosenpassPubKey []byte, remoteRosenpassAddr string, updateTime time.Time) {
	if runtime.GOOS == "ios" {
		runtime.GC()
	}

	conn.metricsStages.RecordConnectionReady(updateTime)

	if conn.onConnected != nil {
		conn.onConnected(conn.config.Key, remoteRosenpassPubKey, conn.config.WgConfig.AllowedIps[0].Addr().String(), remoteRosenpassAddr)
	}
}

func (conn *Conn) isRelayed() bool {
	switch conn.currentConnPriority {
	case conntype.Relay, conntype.ICETurn:
		return true
	default:
		return false
	}
}

func (conn *Conn) evalStatus() ConnStatus {
	if conn.statusRelay.Get() == worker.StatusConnected || conn.statusICE.Get() == worker.StatusConnected {
		return StatusConnected
	}

	return StatusConnecting
}

// isConnectedOnAllWay evaluates the overall connection status based on ICE and Relay transports.
//
// The result is a tri-state:
//   - ConnStatusConnected:          all available transports are up
//   - ConnStatusPartiallyConnected: one usable path exists while another is pending
//   - ConnStatusDisconnected:       no working transport
func (conn *Conn) isConnectedOnAllWay() (status guard.ConnStatus) {
	defer func() {
		if status == guard.ConnStatusDisconnected {
			conn.logTraceConnState()
		}
	}()

	workerICE := conn.workerICESnapshot.Load()
	iceWorkerCreated := workerICE != nil

	var iceInProgress bool
	if iceWorkerCreated {
		iceInProgress = workerICE.InProgress()
	}

	forceRelayState := conn.loadForceRelayState()
	return evalConnStatus(connStatusInputs{
		forceRelayApplied:   forceRelayState.applied(),
		forceRelayPending:   forceRelayState.pending(),
		peerUsesRelay:       conn.workerRelay.IsRelayConnectionSupportedWithPeer(),
		relayConnected:      conn.statusRelay.Get() == worker.StatusConnected,
		remoteSupportsICE:   conn.handshaker.RemoteICESupported(),
		iceWorkerCreated:    iceWorkerCreated,
		iceConnected:        conn.statusICE.Get() == worker.StatusConnected,
		iceStatusConnecting: conn.statusICE.Get() != worker.StatusDisconnected,
		iceInProgress:       iceInProgress,
	})
}

// enableWgWatcherIfNeeded starts a fresh watcher instance per connection attempt, so its
// lifecycle stays bound to conn.mu and enable/disable can't race an old goroutine's shutdown.
// Caller must hold conn.mu.
func (conn *Conn) enableWgWatcherIfNeeded(enabledTime time.Time) {
	if conn.wgWatcher != nil {
		return
	}

	watcher := NewWGWatcher(conn.Log, conn.config.WgConfig.WgInterface, conn.config.Key, conn.dumpState)
	watcher.PrepareInitialHandshake()

	wgWatcherCtx, wgWatcherCancel := context.WithCancel(conn.ctx)
	conn.wgWatcher = watcher
	conn.wgWatcherCancel = wgWatcherCancel

	conn.wgWatcherWg.Add(1)
	go func() {
		defer conn.wgWatcherWg.Done()
		onDisconnected := func() { conn.onWGDisconnected(wgWatcherCtx) }
		watcher.EnableWgWatcher(wgWatcherCtx, enabledTime, onDisconnected, conn.onWGHandshakeSuccess, conn.onWGCheckSuccess)
	}()
}

// disableWgWatcherIfNeeded cancels and drops the watcher once no transport is active. It never
// waits for the goroutine: the timeout path reentrantly calls back here under conn.mu, so
// blocking would deadlock. Caller must hold conn.mu.
func (conn *Conn) disableWgWatcherIfNeeded() {
	if conn.currentConnPriority != conntype.None || conn.wgWatcher == nil {
		return
	}
	conn.wgWatcherCancel()
	conn.wgWatcher = nil
	conn.wgWatcherCancel = nil
}

func (conn *Conn) newProxy(remoteConn net.Conn) (wgproxy.Proxy, error) {
	conn.Log.Debugf("setup proxied WireGuard connection")
	udpAddr := &net.UDPAddr{
		IP:   conn.config.WgConfig.AllowedIps[0].Addr().AsSlice(),
		Port: conn.config.WgConfig.WgListenPort,
	}

	wgProxy := conn.config.WgConfig.WgInterface.GetProxy()
	if err := wgProxy.AddRelayedConn(conn.ctx, udpAddr, remoteConn); err != nil {
		return nil, fmt.Errorf("add relayed conn to proxy: %w", err)
	}
	return wgProxy, nil
}

func (conn *Conn) resetEndpoint() {
	if !isController(conn.config) {
		return
	}
	conn.Log.Infof("reset wg endpoint")
	if conn.wgWatcher != nil {
		conn.wgWatcher.Reset()
	}
	if err := conn.endpointUpdater.RemoveEndpointAddress(); err != nil {
		conn.Log.Warnf("failed to remove endpoint address before update: %v", err)
	}
}

func (conn *Conn) isReadyToUpgrade() bool {
	return conn.wgProxyRelay != nil && conn.currentConnPriority != conntype.Relay
}

func (conn *Conn) isICEActive() bool {
	return (conn.currentConnPriority == conntype.ICEP2P || conn.currentConnPriority == conntype.ICETurn) && conn.statusICE.Get() == worker.StatusConnected
}

func (conn *Conn) handleConfigurationFailure(err error, wgProxy wgproxy.Proxy) {
	conn.Log.Warnf("Failed to update wg peer configuration: %v", err)
	if wgProxy != nil {
		if ierr := wgProxy.CloseConn(); ierr != nil {
			conn.Log.Warnf("Failed to close wg proxy: %v", ierr)
		}
	}
	if conn.wgProxyRelay != nil {
		conn.wgProxyRelay.Work()
	}
}

func (conn *Conn) logTraceConnState() {
	if conn.workerRelay.IsRelayConnectionSupportedWithPeer() {
		conn.Log.Tracef("connectivity guard check, relay state: %s, ice state: %s", conn.statusRelay, conn.statusICE)
	} else {
		conn.Log.Tracef("connectivity guard check, ice state: %s", conn.statusICE)
	}
}

func (conn *Conn) setRelayedProxy(proxy wgproxy.Proxy) {
	if conn.wgProxyRelay != nil {
		if err := conn.wgProxyRelay.CloseConn(); err != nil {
			conn.Log.Warnf("failed to close deprecated wg proxy conn: %v", err)
		}
	}
	conn.wgProxyRelay = proxy
}

// onWGHandshakeSuccess is called when the first WireGuard handshake is detected
func (conn *Conn) onWGHandshakeSuccess(when time.Time) {
	conn.metricsStages.RecordWGHandshakeSuccess(when)
	conn.recordConnectionMetrics()
}

// onWGCheckSuccess is called for every watcher check that observed a fresh
// handshake, including handshakes of connections that were already up when
// the watcher started.
func (conn *Conn) onWGCheckSuccess() {
	conn.mu.Lock()
	conn.wgTimeouts = 0
	conn.mu.Unlock()
}

// recordConnectionMetrics records connection stage timestamps as metrics
func (conn *Conn) recordConnectionMetrics() {
	if conn.metricsRecorder == nil {
		return
	}

	// Determine connection type based on current priority
	conn.mu.Lock()
	priority := conn.currentConnPriority
	conn.mu.Unlock()

	connType := metricsConnType(priority)
	if connType == metrics.ConnectionTypeUnknown {
		return
	}

	// Record metrics with timestamps - duration calculation happens in metrics package
	conn.metricsRecorder.RecordConnectionStages(
		context.Background(),
		conn.config.Key,
		connType,
		conn.metricsStages.IsReconnection(),
		conn.metricsStages.GetTimestamps(),
	)
}

// AllowedIP returns the allowed IP of the remote peer
func (conn *Conn) AllowedIP() netip.Addr {
	return conn.config.WgConfig.AllowedIps[0].Addr()
}

func (conn *Conn) AgentVersionString() string {
	return conn.config.AgentVersion
}

func (conn *Conn) presharedKey(remoteRosenpassKey []byte) *wgtypes.Key {
	if conn.config.RosenpassConfig.PubKey == nil {
		return conn.config.WgConfig.PreSharedKey
	}

	if remoteRosenpassKey == nil && conn.config.RosenpassConfig.PermissiveMode {
		return conn.config.WgConfig.PreSharedKey
	}

	// If Rosenpass has already set a PSK for this peer, return nil to prevent
	// UpdatePeer from overwriting the Rosenpass-managed key.
	if conn.rosenpassInitializedPresharedKeyValidator != nil && conn.rosenpassInitializedPresharedKeyValidator(conn.config.Key) {
		return nil
	}

	// Use NetBird PSK as the seed for Rosenpass. This same PSK is passed to
	// Rosenpass as PeerConfig.PresharedKey, ensuring the derived post-quantum
	// key is cryptographically bound to the original secret.
	if conn.config.WgConfig.PreSharedKey != nil {
		return conn.config.WgConfig.PreSharedKey
	}

	// Fallback to deterministic key if no NetBird PSK is configured
	determKey, err := rosenpass.DeterministicSeedKey(conn.config.LocalKey, conn.config.Key)
	if err != nil {
		conn.Log.Errorf("failed to generate Rosenpass initial key: %v", err)
		return nil
	}

	return determKey
}

func isController(config ConnConfig) bool {
	return config.LocalKey > config.Key
}

func isRosenpassEnabled(remoteRosenpassPubKey []byte) bool {
	return remoteRosenpassPubKey != nil
}

func evalConnStatus(in connStatusInputs) guard.ConnStatus {
	// "Relay up and needed" — the peer uses relay and the transport is connected.
	relayUsedAndUp := in.peerUsesRelay && in.relayConnected

	// A pending force-relay transition deliberately keeps the old ICE data path
	// alive. Report it as partial so the guard sends bounded relay probes without
	// treating the still-usable peer as fully disconnected.
	if in.forceRelayPending {
		if in.iceConnected {
			return guard.ConnStatusPartiallyConnected
		}
		return guard.ConnStatusDisconnected
	}

	// Force-relay mode: ICE never runs. Relay is the only transport and must be up.
	if in.forceRelayApplied {
		return boolToConnStatus(relayUsedAndUp)
	}

	// Without a local ICE worker, relay is the only possible transport.
	if !in.iceWorkerCreated {
		return boolToConnStatus(relayUsedAndUp)
	}

	// A missing remote ICE advertisement can be transient after force-relay is disabled. Keep a working
	// relay connection partially connected so the guard sends its bounded capability probes. Our offers
	// advertise local ICE independently of this flag, allowing an unchanged remote peer to reply with its
	// own credentials and break the relay-only capability latch.
	if !in.remoteSupportsICE {
		if relayUsedAndUp {
			return guard.ConnStatusPartiallyConnected
		}
		return guard.ConnStatusDisconnected
	}

	// ICE counts as "up" when the status is anything other than Disconnected, OR
	// when a negotiation is currently in progress (so we don't spam offers while one is in flight).
	iceUp := in.iceStatusConnecting || in.iceInProgress

	// Relay side is acceptable if the peer doesn't rely on relay, or relay is connected.
	relayOK := !in.peerUsesRelay || in.relayConnected

	switch {
	case iceUp && relayOK:
		return guard.ConnStatusConnected
	case relayUsedAndUp:
		// Relay is up but ICE is down — partially connected.
		return guard.ConnStatusPartiallyConnected
	default:
		return guard.ConnStatusDisconnected
	}
}

func boolToConnStatus(connected bool) guard.ConnStatus {
	if connected {
		return guard.ConnStatusConnected
	}
	return guard.ConnStatusDisconnected
}

func metricsConnType(priority conntype.ConnPriority) metrics.ConnectionType {
	switch priority {
	case conntype.Relay:
		return metrics.ConnectionTypeRelay
	case conntype.ICETurn:
		return metrics.ConnectionTypeICETurn
	case conntype.ICEP2P:
		return metrics.ConnectionTypeICEP2P
	default:
		return metrics.ConnectionTypeUnknown
	}
}
