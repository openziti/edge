// +build apitests

/*
	Copyright 2019 Netfoundry, Inc.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package tests

import (
	"github.com/Jeffail/gabs"
	"github.com/google/uuid"
	"sort"
)

type testEntity interface {
	getId() string
	getEntityType() string
	toJson(create bool, ctx *TestContext) string
	validate(ctx *TestContext, c *gabs.Container)
}

func newTestAppwan() *testAppwan {
	return &testAppwan{
		name:       uuid.New().String(),
		identities: []string{},
		services:   []string{},
	}
}

type testAppwan struct {
	id         string
	name       string
	identities []string
	services   []string
	tags       map[string]interface{}
}

func (entity *testAppwan) getId() string {
	return entity.id
}

func (entity *testAppwan) getEntityType() string {
	return "app-wans"
}

func (entity *testAppwan) toJson(_ bool, ctx *TestContext) string {
	entityData := gabs.New()
	ctx.setJsonValue(entityData, entity.name, "name")
	ctx.setJsonValue(entityData, entity.identities, "identities")
	ctx.setJsonValue(entityData, entity.services, "services")
	if len(entity.tags) > 0 {
		ctx.setJsonValue(entityData, entity.tags, "tags")
	}
	return entityData.String()
}

func (entity *testAppwan) validate(ctx *TestContext, c *gabs.Container) {
	if entity.tags == nil {
		entity.tags = map[string]interface{}{}
	}
	ctx.pathEquals(c, entity.name, path("name"))
	ctx.pathEquals(c, entity.tags, path("tags"))

}

type testService struct {
	id              string
	name            string
	dnsHostname     string
	dnsPort         int
	egressRouter    string
	endpointAddress string
	hostIds         []string
	edgeRouterRoles []string
	tags            map[string]interface{}
}

func (entity *testService) getId() string {
	return entity.id
}

func (entity *testService) getEntityType() string {
	return "services"
}

func (entity *testService) toJson(create bool, ctx *TestContext) string {
	entityData := gabs.New()
	ctx.setJsonValue(entityData, entity.name, "name")
	ctx.setJsonValue(entityData, entity.egressRouter, "egressRouter")
	ctx.setJsonValue(entityData, entity.endpointAddress, "endpointAddress")
	ctx.setJsonValue(entityData, entity.dnsHostname, "dns", "hostname")
	ctx.setJsonValue(entityData, entity.dnsPort, "dns", "port")
	ctx.setJsonValue(entityData, entity.edgeRouterRoles, "edgeRouterRoles")
	if create {
		if len(entity.hostIds) > 0 {
			ctx.setJsonValue(entityData, entity.hostIds, "hostIds")
		}
	}

	if len(entity.tags) > 0 {
		ctx.setJsonValue(entityData, entity.tags, "tags")
	}

	return entityData.String()
}

func (entity *testService) validate(ctx *TestContext, c *gabs.Container) {
	if entity.tags == nil {
		entity.tags = map[string]interface{}{}
	}
	ctx.pathEquals(c, entity.name, path("name"))
	ctx.pathEquals(c, entity.egressRouter, path("egressRouter"))
	ctx.pathEquals(c, entity.endpointAddress, path("endpointAddress"))
	ctx.pathEquals(c, entity.dnsHostname, path("dns.hostname"))
	ctx.pathEquals(c, float64(entity.dnsPort), path("dns.port"))
	ctx.pathEquals(c, entity.tags, path("tags"))

	sort.Strings(entity.edgeRouterRoles)
	ctx.pathEqualsStringSlice(c, entity.edgeRouterRoles, path("edgeRouterRoles"))
}

func newTestIdentity(isAdmin bool, roleAttributes ...string) *testIdentity {
	return &testIdentity{
		name:           uuid.New().String(),
		identityType:   "User",
		isAdmin:        isAdmin,
		roleAttributes: roleAttributes,
	}
}

type testIdentity struct {
	id             string
	name           string
	identityType   string
	isAdmin        bool
	roleAttributes []string
	tags           map[string]interface{}
}

func (entity *testIdentity) getId() string {
	return entity.id
}

func (entity *testIdentity) getEntityType() string {
	return "identities"
}

func (entity *testIdentity) toJson(_ bool, ctx *TestContext) string {
	entityData := gabs.New()
	ctx.setJsonValue(entityData, entity.name, "name")
	ctx.setJsonValue(entityData, entity.identityType, "type")
	ctx.setJsonValue(entityData, entity.isAdmin, "isAdmin")
	ctx.setJsonValue(entityData, entity.roleAttributes, "roleAttributes")

	enrollments := map[string]interface{}{
		"updb": entity.name,
	}
	ctx.setJsonValue(entityData, enrollments, "enrollment")

	if len(entity.tags) > 0 {
		ctx.setJsonValue(entityData, entity.tags, "tags")
	}
	return entityData.String()
}

func (entity *testIdentity) validate(ctx *TestContext, c *gabs.Container) {
	if entity.tags == nil {
		entity.tags = map[string]interface{}{}
	}
	ctx.pathEquals(c, entity.name, path("name"))
	sort.Strings(entity.roleAttributes)
	ctx.pathEqualsStringSlice(c, entity.roleAttributes, path("roleAttributes"))
	ctx.pathEquals(c, entity.tags, path("tags"))
}

func newTestEdgeRouter(roleAttributes ...string) *testEdgeRouter {
	return &testEdgeRouter{
		name:           uuid.New().String(),
		roleAttributes: roleAttributes,
	}
}

type testEdgeRouter struct {
	id             string
	name           string
	roleAttributes []string
	tags           map[string]interface{}
}

func (entity *testEdgeRouter) getId() string {
	return entity.id
}

func (entity *testEdgeRouter) getEntityType() string {
	return "edge-routers"
}

func (entity *testEdgeRouter) toJson(_ bool, ctx *TestContext) string {
	entityData := gabs.New()
	ctx.setJsonValue(entityData, entity.name, "name")
	ctx.setJsonValue(entityData, entity.roleAttributes, "roleAttributes")

	if len(entity.tags) > 0 {
		ctx.setJsonValue(entityData, entity.tags, "tags")
	}
	return entityData.String()
}

func (entity *testEdgeRouter) validate(ctx *TestContext, c *gabs.Container) {
	if entity.tags == nil {
		entity.tags = map[string]interface{}{}
	}
	ctx.pathEquals(c, entity.name, path("name"))
	sort.Strings(entity.roleAttributes)
	ctx.pathEqualsStringSlice(c, entity.roleAttributes, path("roleAttributes"))
	ctx.pathEquals(c, entity.tags, path("tags"))
}
