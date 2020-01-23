package entities

import "github.com/netfoundry/ziti-sdk-golang/ziti/edge"

type Service struct {
	edge.Service
	ClientConfig *ServiceConfig
	ServerConfig *ServiceConfig
}
