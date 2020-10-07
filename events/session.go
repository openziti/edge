package events

import (
	"fmt"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/edge/controller/persistence"
	"github.com/openziti/foundation/storage/boltz"
	"github.com/openziti/foundation/util/cowslice"
	"github.com/pkg/errors"
	"reflect"
)

const	SessionEventTypeCreated = "created"
const	SessionEventTypeDeleted = "deleted"

type SessionCreatedEvent struct {
	Id           string
	Token        string
	ApiSessionId string
	IdentityId   string
}

type SessionDeletedEvent struct {
	Id    string
	Token string
}

type SessionEventHandler interface {
	HandleSessionCreated(event *SessionCreatedEvent)
	HandleSessionDeleted(event *SessionDeletedEvent)
}

var sessionEventHandlerRegistry = cowslice.NewCowSlice(make([]SessionEventHandler, 0))

func getSessionEventHandlers() []SessionEventHandler {
	return sessionEventHandlerRegistry.Value().([]SessionEventHandler)
}

func Init(sessionStore persistence.SessionStore) {
	sessionStore.AddListener(boltz.EventCreate, sessionCreated)
	sessionStore.AddListener(boltz.EventDelete, sessionDeleted)
}

func sessionCreated(args ...interface{}) {
	var session *persistence.Session
	if len(args) == 1 {
		session, _ = args[0].(*persistence.Session)
	}

	if session == nil {
		log := pfxlog.Logger()
		log.Error("could not cast event args to event details")
		return
	}

	event := &SessionCreatedEvent{
		Id:           session.Id,
		Token:        session.Token,
		ApiSessionId: session.ApiSessionId,
		IdentityId:   session.ApiSession.IdentityId,
	}

	for _, handler := range getSessionEventHandlers() {
		go handler.HandleSessionCreated(event)
	}
}

func sessionDeleted(args ...interface{}) {
	var session *persistence.Session
	if len(args) == 1 {
		session, _ = args[0].(*persistence.Session)
	}

	if session == nil {
		log := pfxlog.Logger()
		log.Error("could not cast event args to event details")
		return
	}

	event := &SessionDeletedEvent{
		Id:    session.Id,
		Token: session.Token,
	}

	for _, handler := range getSessionEventHandlers() {
		go handler.HandleSessionDeleted(event)
	}
}



func registerSessionEventHandler(val interface{}, config map[interface{}]interface{}) error {

	handler, ok := val.(SessionEventHandler)

	if !ok {
		return errors.Errorf("type %v doesn't implement github.com/openziti/edge/events/SessionEventHandler interface.", reflect.TypeOf(val))
	}

	var includeList []string
	if includeVar, ok := config["include"]; ok {
		if includeStr, ok := includeVar.(string); ok {
			includeList = append(includeList, includeStr)
		} else if includeIntfList, ok := includeVar.([]interface{}); ok {
			for _, val := range includeIntfList {
				includeList = append(includeList, fmt.Sprintf("%v", val))
			}
		} else {
			return errors.Errorf("invalid type %v for edge.sessions include configuration %v", reflect.TypeOf(includeVar))
		}
	}

	if len(includeList) == 0 {
		AddSessionEventHandler(handler)
	} else {
		for _, include := range includeList {
			if include == SessionEventTypeCreated {
				AddSessionEventHandler(&edgeSessionCreatedEventAdapter{
					wrapped: handler,
				})
			} else if include == SessionEventTypeDeleted {
				AddSessionEventHandler(&edgeSessionDeletedEventAdapter{
					wrapped: handler,
				})
			} else {
				return errors.Errorf("invalid include %v for fabric.sessions. valid values are ['created', 'deleted', 'circuitUpdated']", include)
			}
		}
	}

	return nil
}


type edgeSessionCreatedEventAdapter struct {
	wrapped SessionEventHandler
}

func (adapter *edgeSessionCreatedEventAdapter) HandleSessionCreated(event *SessionCreatedEvent) {
	adapter.wrapped.HandleSessionCreated(event)

}

func (adapter *edgeSessionCreatedEventAdapter) HandleSessionDeleted(event *SessionDeletedEvent) {
}


type edgeSessionDeletedEventAdapter struct {
	wrapped SessionEventHandler
}

func (adapter *edgeSessionDeletedEventAdapter) HandleSessionCreated(event *SessionCreatedEvent) {
}

func (adapter *edgeSessionDeletedEventAdapter) HandleSessionDeleted(event *SessionDeletedEvent) {
	adapter.wrapped.HandleSessionDeleted(event)
}



