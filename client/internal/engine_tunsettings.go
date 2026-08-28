package internal

import "sync"

// NotifyNetworkChange tells every open peer connection that the OS moved to a
// different transport. A handover silently invalidates ICE sockets, so without
// this peers only recover after ICE times the dead session out — tens of
// seconds later. Notifications run in parallel because each closes an ICE agent
// that can block on the close timeout.
func (e *Engine) NotifyNetworkChange() {
	var wg sync.WaitGroup
	for _, pubKey := range e.peerStore.PeersPubKey() {
		conn, ok := e.peerStore.PeerConn(pubKey)
		if !ok {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn.OnNetworkChange()
		}()
	}
	wg.Wait()
}

func (e *Engine) TunSettings() ([]string, []string) {
	e.syncMsgMux.Lock()
	routeManager := e.routeManager
	dnsServer := e.dnsServer
	e.syncMsgMux.Unlock()

	var routes []string
	if routeManager != nil {
		routes = routeManager.CurrentRouteRange()
	}

	var searchDomains []string
	if dnsServer != nil {
		searchDomains = dnsServer.SearchDomains()
	}

	return routes, searchDomains
}
