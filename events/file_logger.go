package events

import (
	"encoding/json"
	"fmt"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/foundation/metrics/metrics_pb"
	"github.com/openziti/foundation/util/iomonad"
	"github.com/pkg/errors"
	"os"
)

func registerEdgeEventHandlerType(config map[interface{}]interface{}) (*EdgeHandler, bool)  {

	rep := &EdgeHandler{
		config: config,
	}

	return rep, true
}

type EdgeHandler struct {
	name   string
	config map[interface{}]interface{}
	eventsChan chan interface{}
	path string
	maxsizemb int
}


func (handler *EdgeHandler) NewEventHandler(config map[interface{}]interface{}) (interface{}, error) {

	logger := pfxlog.Logger()
	logger.Info("Registering new event handler: EdgeHandler")

	// allow config to increase the buffer size
	bufferSize := 10
	if value, found := config["bufferSize"]; found {
		if size, ok := value.(int); ok {
			bufferSize = size
		}
	}

	// allow config to override the max file size
	maxsize := 10
	if value, found := config["maxsizemb"]; found {
		if maxsizemb, ok := value.(int); ok {
			maxsize = maxsizemb
		}
	}

	// set the path or die if not specified
	filepath := ""
	if value, found := config["path"]; found {
		if testpath, ok := value.(string); ok {
			f, err := os.OpenFile(testpath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0664)
			if err != nil {
				return nil, fmt.Errorf("cannot write to log file path: %s", testpath)
			} else {
				filepath = testpath
				_ = f.Close()
			}
		} else {
			return nil, errors.New("invalid event FileLogger 'path' value")
		}
	} else {
		return nil, errors.New("missing required 'path' config for events FileLogger handler")
	}

	edgeHandler :=  &EdgeHandler{
		name: "EdgeHandler",
		config: config,
		path: filepath,
		maxsizemb: maxsize,
		eventsChan: make(chan interface{}, bufferSize),
	}

	go edgeHandler.run()
	return edgeHandler, nil

}

func (handler *EdgeHandler) HandleSessionCreated(event *SessionCreatedEvent) {
	 // handler.eventsChan <- event
	handler.Handle(event)
}

func (handler *EdgeHandler) HandleSessionDeleted(event *SessionDeletedEvent) {
	// handler.eventsChan <- event
	handler.Handle(event)
}

func (handler *EdgeHandler) AcceptMetrics(message *metrics_pb.MetricsMessage) {

	// @TODO - Will be extracting and logging the usage metrics for sessions as their own metric events


	logger := pfxlog.Logger()
	counters := message.GetIntervalCounters()

	if counters != nil {
		for name, val := range counters {

			buckets := val.GetBuckets()

			if buckets != nil {
				for _, value := range buckets {
					timestamp := value.IntervalStartUTC
					vals := value.GetValues()
					for k, v := range vals {
						logger.Infof("Edge Interval metric: %s [%v] %v - %v",name, timestamp, k, v)
					}
				}
			}
		}
	}


}


func( handler *EdgeHandler) Handle(message interface{}) {

	logger := pfxlog.Logger()

	out, err := handler.getFileHandle(handler.path, handler.maxsizemb)

	if err != nil {
		logger.Errorf("Error getting the file handle: %v", err)
		return
	}

	w := iomonad.Wrap(out)
	// json format
	marshalled, err := json.Marshal(message)
	if err != nil {
		logger.Errorf("Error marshalling JSON: %v", err)
		return
	}

	bytes := w.Write(marshalled)
	w.Println("")
	logger.Infof("Wrote %v bytes to the file....", bytes)
	defer func() { _ = out.Close() }()

}



func( handler *EdgeHandler) getFileHandle(path string, maxsize int) (*os.File, error) {
	if stat, err := os.Stat(path); err == nil {
		// get the size
		size := stat.Size()
		if size >= int64(maxsize*1024*1024) {
			if err := os.Truncate(path, 0); err != nil {
				pfxlog.Logger().WithError(err).Errorf("failure while trucating metrics log file %v to size %vM", path, maxsize)
			}
		}
	} else {
		pfxlog.Logger().WithError(err).Errorf("failure while statting metrics log file %v", path)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0664)
	if err != nil {
		pfxlog.Logger().WithError(err).Errorf("failure while opening metrics log file %v", path)
		return nil, err
	}

	return f, nil

}


func (handler *EdgeHandler) run() {
	logger := pfxlog.Logger()
	logger.Info("Edge event handler started")
	defer logger.Warn("exited")

	for {
		select {
		case msg := <-handler.eventsChan:
			handler.Handle(msg)
		}
	}
}