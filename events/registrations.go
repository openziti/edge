package events

import (
	"github.com/openziti/foundation/util/cowslice"
	"github.com/openziti/fabric/events"
)


func init() {

	events.RegisterEventType("edge.sessions", registerSessionEventHandler)
	events.RegisterEventType("edge.metrics", registerMetricsEventHandler)

}

func AddSessionEventHandler(handler SessionEventHandler) {
	cowslice.Append(sessionEventHandlerRegistry, handler)
}

func RemoveSessionEventHandler(handler SessionEventHandler) {
	cowslice.Delete(sessionEventHandlerRegistry, handler)
}
