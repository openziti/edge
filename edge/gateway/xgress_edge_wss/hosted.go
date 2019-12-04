package xgress_edge_wss

import (
	"sync"
)

type hostedServiceRegistry struct {
	services sync.Map
}

func (registry *hostedServiceRegistry) Put(hostId string, conn *localListener) {
	registry.services.Store(hostId, conn)
}

func (registry *hostedServiceRegistry) Get(hostId string) (*localListener, bool) {
	val, ok := registry.services.Load(hostId)
	if !ok {
		return nil, false
	}
	ch, ok := val.(*localListener)
	return ch, ok
}

func (registry *hostedServiceRegistry) Delete(hostId string) {
	registry.services.Delete(hostId)
}

func (registry *hostedServiceRegistry) cleanupServices(proxy *ingressProxy) (listeners []*localListener) {
	registry.services.Range(func(key, value interface{}) bool {
		listener := value.(*localListener)
		if listener.parent == proxy {
			listener.close(true, "underlying channel closing")
			registry.services.Delete(key)
			listeners = append(listeners, listener)
		}
		return true
	})
	return
}
