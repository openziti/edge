package entities

import (
	"fmt"
	"github.com/michaelquigley/pfxlog"
	"github.com/mitchellh/mapstructure"
	"github.com/netfoundry/ziti-sdk-golang/ziti/edge"
	"github.com/pkg/errors"
)

const (
	ClientConfigV1 = "ziti-tunneler-client.v1"
	ServerConfigV1 = "ziti-tunneler-server.v1"
)

type ServiceConfig struct {
	Protocol string
	Hostname string
	Port     int
}

func (s *ServiceConfig) String() string {
	return fmt.Sprintf("%v:%v:%v", s.Protocol, s.Hostname, s.Port)
}

func ExtractServiceConfig(service *edge.Service, configType string) (*ServiceConfig, error) {
	if service.Configs == nil {
		pfxlog.Logger().Debugf("no service configs defined for service %v", service.Name)
		return nil, errors.Errorf("config of type %v not found", configType)
	}
	configMap, found := service.Configs[configType]
	if !found {
		pfxlog.Logger().Debugf("no service config of type %v defined for service %v", configType, service.Name)
		return nil, errors.Errorf("config of type %v not found", configType)
	}
	config := &ServiceConfig{}
	err := mapstructure.Decode(configMap, config)
	if err != nil {
		pfxlog.Logger().WithError(err).Debugf("unable to decode service configuration for of type %v defined for service %v", configType, service.Name)
		return nil, errors.Errorf("unable to decode service config structure: %w", err)
	}
	return config, nil
}
