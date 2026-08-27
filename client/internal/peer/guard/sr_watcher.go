package guard

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/peer/ice"
	"github.com/netbirdio/netbird/client/internal/stdnet"
)

type chNotifier interface {
	SetOnReconnectedListener(func())
	Ready() bool
}

type iceMonitor interface {
	Start(context.Context, func())
}

type SRWatcher struct {
	signalClient chNotifier
	relayManager chNotifier

	listeners              map[chan struct{}]struct{}
	mu                     sync.Mutex
	iFaceDiscover          stdnet.ExternalIFaceDiscover
	iceConfig              ice.Config
	started                bool
	cancelIceMonitor       context.CancelFunc
	iceMonitorRun          uint64
	iceMonitorEnabled      bool
	iceMonitorRequirements map[string]struct{}
	newICEMonitor          func(stdnet.ExternalIFaceDiscover, ice.Config, time.Duration) iceMonitor
}

// NewSRWatcher creates a new SRWatcher. This watcher will notify the listeners when the ICE candidates change or the
// Relay connection is reconnected or the Signal client reconnected.
func NewSRWatcher(signalClient chNotifier, relayManager chNotifier, iFaceDiscover stdnet.ExternalIFaceDiscover, iceConfig ice.Config) *SRWatcher {
	srw := &SRWatcher{
		signalClient:           signalClient,
		relayManager:           relayManager,
		iFaceDiscover:          iFaceDiscover,
		iceConfig:              iceConfig,
		listeners:              make(map[chan struct{}]struct{}),
		iceMonitorRequirements: make(map[string]struct{}),
		newICEMonitor: func(discover stdnet.ExternalIFaceDiscover, config ice.Config, period time.Duration) iceMonitor {
			return NewICEMonitor(discover, config, period)
		},
	}
	return srw
}

func (w *SRWatcher) Start(disableICEMonitor bool) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.started {
		return
	}
	w.started = true
	w.iceMonitorEnabled = !disableICEMonitor

	w.signalClient.SetOnReconnectedListener(w.onReconnected)
	w.relayManager.SetOnReconnectedListener(w.onReconnected)
	w.reconcileICEMonitorLocked()
}

// SetICEMonitorEnabled changes only ICE candidate monitoring. Signal and relay
// reconnect callbacks remain registered for the lifetime of the watcher.
func (w *SRWatcher) SetICEMonitorEnabled(enabled bool) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.iceMonitorEnabled = enabled
	if !w.started {
		return
	}
	w.reconcileICEMonitorLocked()
}

// SetPeerICEMonitorRequired keeps ICE candidate monitoring active for a peer
// whose requested transport policy is pending while its existing ICE path is
// still applied.
func (w *SRWatcher) SetPeerICEMonitorRequired(peerKey string, required bool) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if required {
		w.iceMonitorRequirements[peerKey] = struct{}{}
	} else {
		delete(w.iceMonitorRequirements, peerKey)
	}
	if w.started {
		w.reconcileICEMonitorLocked()
	}
}

func (w *SRWatcher) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()

	clear(w.iceMonitorRequirements)
	if !w.started {
		return
	}
	w.started = false
	w.stopICEMonitorLocked()
	w.signalClient.SetOnReconnectedListener(nil)
	w.relayManager.SetOnReconnectedListener(nil)
}

func (w *SRWatcher) reconcileICEMonitorLocked() {
	if w.iceMonitorEnabled || len(w.iceMonitorRequirements) > 0 {
		w.startICEMonitorLocked()
		return
	}
	w.stopICEMonitorLocked()
}

func (w *SRWatcher) startICEMonitorLocked() {
	if w.cancelIceMonitor != nil {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	w.cancelIceMonitor = cancel
	w.iceMonitorRun++
	run := w.iceMonitorRun
	iceMonitor := w.newICEMonitor(w.iFaceDiscover, w.iceConfig, GetICEMonitorPeriod())
	go iceMonitor.Start(ctx, func() { w.onICEChanged(run) })
}

func (w *SRWatcher) stopICEMonitorLocked() {
	if w.cancelIceMonitor == nil {
		return
	}
	w.iceMonitorRun++
	w.cancelIceMonitor()
	w.cancelIceMonitor = nil
}

func (w *SRWatcher) NewListener() chan struct{} {
	w.mu.Lock()
	defer w.mu.Unlock()

	listenerChan := make(chan struct{}, 1)
	w.listeners[listenerChan] = struct{}{}
	return listenerChan
}

func (w *SRWatcher) RemoveListener(listenerChan chan struct{}) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.listeners, listenerChan)
	close(listenerChan)
}

func (w *SRWatcher) onICEChanged(run uint64) {
	if !w.signalClient.Ready() {
		return
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.started || w.cancelIceMonitor == nil || w.iceMonitorRun != run {
		return
	}

	log.Infof("network changes detected by ICE agent")
	w.notifyLocked()
}

func (w *SRWatcher) onReconnected() {
	if !w.signalClient.Ready() {
		return
	}
	if !w.relayManager.Ready() {
		return
	}

	log.Infof("reconnected to Signal or Relay server")
	w.notify()
}

func (w *SRWatcher) notify() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.notifyLocked()
}

func (w *SRWatcher) notifyLocked() {
	for listener := range w.listeners {
		select {
		case listener <- struct{}{}:
		default:
		}
	}
}
