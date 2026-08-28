package peer

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/version"
)

var (
	ErrSignalIsNotReady = errors.New("signal is not ready")
)

// IceCredentials ICE protocol credentials struct
type IceCredentials struct {
	UFrag string
	Pwd   string
}

// OfferAnswer represents a session establishment offer or answer
type OfferAnswer struct {
	IceCredentials IceCredentials
	// WgListenPort is a remote WireGuard listen port.
	// This field is used when establishing a direct WireGuard connection without any proxy.
	// We can set the remote peer's endpoint with this port.
	WgListenPort int

	// Version of NetBird Agent
	Version string
	// RosenpassPubKey is the Rosenpass public key of the remote peer when receiving this message
	// This value is the local Rosenpass server public key when sending the message
	RosenpassPubKey []byte
	// RosenpassAddr is the Rosenpass server address (IP:port) of the remote peer when receiving this message
	// This value is the local Rosenpass server address when sending the message
	RosenpassAddr string

	// relay server address
	RelaySrvAddress string
	// RelaySrvIP is the IP the remote peer is connected to on its
	// relay server. Used as a dial target if DNS for RelaySrvAddress
	// fails. Zero value if the peer did not advertise an IP.
	RelaySrvIP netip.Addr
	// SessionID is the unique identifier of the session, used to discard old messages
	SessionID *ICESessionID
}

func (o *OfferAnswer) hasICECredentials() bool {
	return o.IceCredentials.UFrag != "" && o.IceCredentials.Pwd != ""
}

type Handshaker struct {
	mu            sync.Mutex
	log           *log.Entry
	config        ConnConfig
	signaler      *Signaler
	ice           *WorkerICE
	relay         *WorkerRelay
	metricsStages *MetricsStages
	// relayListener is not blocking because the listener is using a goroutine to process the messages
	// and it will only keep the latest message if multiple offers are received in a short time
	// this is to avoid blocking the handshaker if the listener is doing some heavy processing
	// and also to avoid processing old offers if multiple offers are received in a short time
	// the listener will always process the latest offer
	relayListener *AsyncOfferListener
	iceListener   func(remoteOfferAnswer *OfferAnswer)

	// remoteICESupported tracks whether the remote peer includes ICE credentials in its offers/answers.
	// When false, the local side skips ICE listener dispatch. Local ICE capability is still advertised so
	// a peer that previously observed force-relay mode can discover that ICE is available again.
	remoteICESupported atomic.Bool

	// remoteOffersCh is a channel used to wait for remote credentials to proceed with the connection
	remoteOffersCh chan OfferAnswer
	// remoteAnswerCh is a channel used to wait for remote credentials answer (confirmation of our offer) to proceed with the connection
	remoteAnswerCh chan OfferAnswer
}

func NewHandshaker(log *log.Entry, config ConnConfig, signaler *Signaler, ice *WorkerICE, relay *WorkerRelay, metricsStages *MetricsStages) *Handshaker {
	h := &Handshaker{
		log:           log,
		config:        config,
		signaler:      signaler,
		ice:           ice,
		relay:         relay,
		metricsStages: metricsStages,
		// Buffered by one so an offer or answer that arrives between Open launching
		// the Listen goroutine and it reaching its receive is held rather than
		// dropped. A peer activated by an incoming signal receives the remote's
		// message in that window; an unbuffered channel skips it as "receiver not
		// ready", and the connection cannot proceed until the remote re-sends.
		remoteOffersCh: make(chan OfferAnswer, 1),
		remoteAnswerCh: make(chan OfferAnswer, 1),
	}
	// assume remote supports ICE until we learn otherwise from received offers
	h.remoteICESupported.Store(ice != nil)
	return h
}

func (h *Handshaker) RemoteICESupported() bool {
	return h.remoteICESupported.Load()
}

func (h *Handshaker) AddRelayListener(offer func(remoteOfferAnswer *OfferAnswer)) {
	h.relayListener = NewAsyncOfferListener(offer)
}

func (h *Handshaker) AddICEListener(offer func(remoteOfferAnswer *OfferAnswer)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.iceListener = offer
}

func (h *Handshaker) setICEWorker(workerICE *WorkerICE) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.ice = workerICE
	if workerICE == nil {
		h.iceListener = nil
		return
	}
	h.iceListener = workerICE.OnNewOffer
}

func (h *Handshaker) Listen(ctx context.Context) {
	for {
		select {
		case remoteOfferAnswer := <-h.remoteOffersCh:
			h.log.Infof("received offer, running version %s, remote WireGuard listen port %d, session id: %s, remote ICE supported: %t", remoteOfferAnswer.Version, remoteOfferAnswer.WgListenPort, remoteOfferAnswer.SessionIDString(), remoteOfferAnswer.hasICECredentials())

			// Record signaling received for reconnection attempts
			if h.metricsStages != nil {
				h.metricsStages.RecordSignalingReceived()
			}

			h.updateRemoteICEState(&remoteOfferAnswer)

			if h.relayListener != nil {
				h.relayListener.Notify(&remoteOfferAnswer)
			}

			h.notifyICEListener(&remoteOfferAnswer)

			if err := h.sendAnswer(); err != nil {
				h.log.Errorf("failed to send remote offer confirmation: %s", err)
				continue
			}
		case remoteOfferAnswer := <-h.remoteAnswerCh:
			h.log.Infof("received answer, running version %s, remote WireGuard listen port %d, session id: %s, remote ICE supported: %t", remoteOfferAnswer.Version, remoteOfferAnswer.WgListenPort, remoteOfferAnswer.SessionIDString(), remoteOfferAnswer.hasICECredentials())

			// Record signaling received for reconnection attempts
			if h.metricsStages != nil {
				h.metricsStages.RecordSignalingReceived()
			}

			h.updateRemoteICEState(&remoteOfferAnswer)

			if h.relayListener != nil {
				h.relayListener.Notify(&remoteOfferAnswer)
			}

			h.notifyICEListener(&remoteOfferAnswer)
		case <-ctx.Done():
			h.log.Infof("stop listening for remote offers and answers")
			return
		}
	}
}

func (h *Handshaker) SendOffer() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sendOffer()
}

// OnRemoteOffer hands an offer to Listen without blocking, keeping only the most
// recent one if several arrive before Listen reads them.
func (h *Handshaker) OnRemoteOffer(offer OfferAnswer) {
	enqueueLatest(h.remoteOffersCh, offer)
}

// OnRemoteAnswer hands an answer to Listen without blocking, keeping only the most
// recent one if several arrive before Listen reads them.
func (h *Handshaker) OnRemoteAnswer(answer OfferAnswer) {
	enqueueLatest(h.remoteAnswerCh, answer)
}

// enqueueLatest delivers msg on a one-slot channel without blocking. When the slot
// already holds an unread message the older one is discarded in favor of msg, so a
// message arriving before Listen starts reading is held rather than dropped, and
// the newest wins if several arrive first. Safe because there is a single producer
// (the engine loop): after draining the stale value the send always has room.
func enqueueLatest(ch chan OfferAnswer, msg OfferAnswer) {
	select {
	case ch <- msg:
		return
	default:
	}

	select {
	case <-ch:
	default:
	}

	select {
	case ch <- msg:
	default:
	}
}

// sendOffer prepares local user credentials and signals them to the remote peer
func (h *Handshaker) sendOffer() error {
	if !h.signaler.Ready() {
		return ErrSignalIsNotReady
	}

	offer := h.buildOfferAnswerLocked()
	h.log.Debugf("sending offer with serial: %s", offer.SessionIDString())

	return h.signaler.SignalOffer(offer, h.config.Key)
}

func (h *Handshaker) sendAnswer() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	answer := h.buildOfferAnswerLocked()
	h.log.Debugf("sending answer with serial: %s", answer.SessionIDString())

	return h.signaler.SignalAnswer(answer, h.config.Key)
}

func (h *Handshaker) buildOfferAnswer() OfferAnswer {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.buildOfferAnswerLocked()
}

func (h *Handshaker) buildOfferAnswerLocked() OfferAnswer {
	answer := OfferAnswer{
		WgListenPort:    h.config.LocalWgPort,
		Version:         version.NetbirdVersion(),
		RosenpassPubKey: h.config.RosenpassConfig.PubKey,
		RosenpassAddr:   h.config.RosenpassConfig.Addr,
	}

	// Advertise local ICE capability independently of the last capability observed from the remote peer.
	// Otherwise both peers can remain latched in relay-only mode after one side disables force-relay: the
	// remote peer sends a credential-less offer first, and each side then suppresses its own credentials.
	if h.ice != nil {
		uFrag, pwd := h.ice.GetLocalUserCredentials()
		sid := h.ice.SessionID()
		answer.IceCredentials = IceCredentials{uFrag, pwd}
		answer.SessionID = &sid
	}

	if addr, ip, err := h.relay.RelayInstanceAddress(); err == nil {
		answer.RelaySrvAddress = addr
		answer.RelaySrvIP = ip
	}

	return answer
}

func (h *Handshaker) updateRemoteICEState(offer *OfferAnswer) {
	h.mu.Lock()
	hasICE := offer.hasICECredentials()
	prev := h.remoteICESupported.Swap(hasICE)
	var workerICE *WorkerICE
	if prev != hasICE {
		if hasICE {
			h.log.Infof("remote peer started sending ICE credentials")
		} else {
			h.log.Infof("remote peer stopped sending ICE credentials")
			workerICE = h.ice
		}
	}
	h.mu.Unlock()

	if workerICE != nil {
		workerICE.Close()
	}
}

func (h *Handshaker) notifyICEListener(offer *OfferAnswer) {
	h.mu.Lock()
	var listener func(*OfferAnswer)
	if h.iceListener != nil && h.RemoteICESupported() {
		listener = h.iceListener
	}
	h.mu.Unlock()

	if listener != nil {
		listener(offer)
	}
}
