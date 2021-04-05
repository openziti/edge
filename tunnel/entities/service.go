package entities

import (
	"fmt"
	"github.com/openziti/edge/health"
	"github.com/openziti/edge/tunnel"
	"github.com/openziti/sdk-golang/ziti"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/pkg/errors"
	"net"
	"reflect"
	"strconv"
	"time"
)

const (
	ClientConfigV1 = "ziti-tunneler-client.v1"
	ServerConfigV1 = "ziti-tunneler-server.v1"
	HostConfigV1   = "host.v1"
	HostConfigV2   = "host.v2"
	InterceptV1    = "intercept.v1"
)

type ServiceConfig struct {
	Protocol   string
	Hostname   string
	Port       int
	PortChecks []*health.PortCheckDefinition
	HttpChecks []*health.HttpCheckDefinition
}

func (self *ServiceConfig) GetPortChecks() []*health.PortCheckDefinition {
	return self.PortChecks
}

func (self *ServiceConfig) GetHttpChecks() []*health.HttpCheckDefinition {
	return self.HttpChecks
}

func (s *ServiceConfig) String() string {
	return fmt.Sprintf("%v:%v:%v", s.Protocol, s.Hostname, s.Port)
}

func (self *ServiceConfig) ToInterceptV1Config() *InterceptV1Config {
	return &InterceptV1Config{
		Protocols:  []string{"tcp", "udp"},
		Addresses:  []string{self.Hostname},
		PortRanges: []*PortRange{{Low: uint16(self.Port), High: uint16(self.Port)}},
	}
}

func (self *ServiceConfig) ToHostV2Config() *HostV2Config {
	terminator := &HostV2Terminator{
		Protocol:   self.Protocol,
		Address:    self.Hostname,
		Port:       self.Port,
		PortChecks: self.PortChecks,
		HttpChecks: self.HttpChecks,
	}

	return &HostV2Config{
		Terminators: []*HostV2Terminator{
			terminator,
		},
	}
}

type HostV1ListenOptions struct {
	BindUsingEdgeIdentity bool
	ConnectTimeoutSeconds *int
	Identity              string
	MaxConnections        int
}

type HostV1Config struct {
	Protocol               string
	ForwardProtocol        bool
	AllowedProtocols       []string
	Address                string
	ForwardAddress         bool
	AllowedAddresses       []string
	Port                   int
	ForwardPort            bool
	AllowedPortRanges      []*PortRange
	AllowedSourceAddresses []string

	PortChecks []*health.PortCheckDefinition
	HttpChecks []*health.HttpCheckDefinition

	ListenOptions *HostV1ListenOptions
}

func (self *HostV1Config) ToHostV2Config() *HostV2Config {
	terminator := &HostV2Terminator{
		Protocol:               self.Protocol,
		ForwardProtocol:        self.ForwardProtocol,
		AllowedProtocols:       self.AllowedProtocols,
		Address:                self.Address,
		ForwardAddress:         self.ForwardAddress,
		AllowedAddresses:       self.AllowedAddresses,
		Port:                   self.Port,
		ForwardPort:            self.ForwardPort,
		AllowedPortRanges:      self.AllowedPortRanges,
		AllowedSourceAddresses: self.AllowedSourceAddresses,
		PortChecks:             self.PortChecks,
		HttpChecks:             self.HttpChecks,
	}

	if self.ListenOptions != nil {
		var timeout *time.Duration
		if self.ListenOptions.ConnectTimeoutSeconds != nil {
			val := time.Duration(*self.ListenOptions.ConnectTimeoutSeconds) * time.Second
			timeout = &val
		}
		terminator.ListenOptions = &HostV2ListenOptions{
			BindUsingEdgeIdentity: self.ListenOptions.BindUsingEdgeIdentity,
			ConnectTimeout:        timeout,
			Identity:              self.ListenOptions.Identity,
			MaxConnections:        self.ListenOptions.MaxConnections,
		}
	}

	return &HostV2Config{
		Terminators: []*HostV2Terminator{
			terminator,
		},
	}
}

type HostV2ListenOptions struct {
	BindUsingEdgeIdentity bool
	ConnectTimeout        *time.Duration
	Identity              string
	MaxConnections        int
}

type HostV2Terminator struct {
	Protocol               string
	ForwardProtocol        bool
	AllowedProtocols       []string
	Address                string
	ForwardAddress         bool
	AllowedAddresses       []string
	Port                   int
	ForwardPort            bool
	AllowedPortRanges      []*PortRange
	AllowedSourceAddresses []string

	PortChecks []*health.PortCheckDefinition
	HttpChecks []*health.HttpCheckDefinition

	ListenOptions *HostV2ListenOptions
}

func (self *HostV2Terminator) SetListenOptions(options *ziti.ListenOptions) {
}

func (self *HostV2Terminator) GetDialTimeout(defaultTimeout time.Duration) time.Duration {
	if self.ListenOptions != nil && self.ListenOptions.ConnectTimeout != nil {
		return *self.ListenOptions.ConnectTimeout
	}
	return defaultTimeout
}

func (self *HostV2Terminator) GetPortChecks() []*health.PortCheckDefinition {
	return self.PortChecks
}

func (self *HostV2Terminator) GetHttpChecks() []*health.HttpCheckDefinition {
	return self.HttpChecks
}

func (self *HostV2Terminator) getValue(options map[string]interface{}, key string) (string, error) {
	val, ok := options[key]
	if !ok {
		return "", errors.Errorf("%v required but not provided", key)
	}
	result, ok := val.(string)
	if !ok {
		return "", errors.Errorf("%v required and present but not a string. val: %v, type: %v", key, val, reflect.TypeOf(val))
	}
	return result, nil
}

func (self *HostV2Terminator) GetProtocol(options map[string]interface{}) (string, error) {
	if self.ForwardProtocol {
		return self.getValue(options, tunnel.DestinationProtocolKey)
	}
	return self.Protocol, nil
}

func (self *HostV2Terminator) GetAddress(options map[string]interface{}) (string, error) {
	if self.ForwardAddress {
		return self.getValue(options, tunnel.DestinationIpKey)
	}
	return self.Address, nil
}

func (self *HostV2Terminator) GetPort(options map[string]interface{}) (string, error) {
	if self.ForwardPort {
		return self.getValue(options, tunnel.DestinationPortKey)
	}
	return strconv.Itoa(self.Port), nil
}

type HostV2Config struct {
	Terminators []*HostV2Terminator
}

type DialOptions struct {
	ConnectTimeoutSeconds *int
	Identity              *string
}

type PortRange struct {
	Low  uint16
	High uint16
}

type InterceptV1Config struct {
	Addresses   []string
	PortRanges  []*PortRange
	Protocols   []string
	SourceIp    *string
	DialOptions *DialOptions
}

type Service struct {
	edge.Service
	InterceptV1Config *InterceptV1Config
	DialTimeout       time.Duration

	HostV2Config       *HostV2Config
	SourceAddrProvider func(sourceAddr net.Addr, destAddr net.Addr) string
	StopHostHook       func()
}

func (self *Service) GetSourceAddr(sourceAddr net.Addr, destAddr net.Addr) string {
	if self.SourceAddrProvider == nil {
		return ""
	}
	return self.SourceAddrProvider(sourceAddr, destAddr)
}

func (self *Service) GetName() string {
	return self.Name
}

func (self *Service) GetDialTimeout() time.Duration {
	return self.DialTimeout
}
