/*
	Copyright 2020 NetFoundry, Inc.

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

package persistence

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/michaelquigley/pfxlog"
	"github.com/netfoundry/ziti-fabric/controller/db"
	"github.com/netfoundry/ziti-fabric/controller/network"
	"github.com/netfoundry/ziti-foundation/storage/boltz"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"go.etcd.io/bbolt"
)

type TestDbProvider struct {
	db           *db.Db
	fabricStores *db.Stores
	controllers  *network.Controllers
}

func (p *TestDbProvider) GetDb() boltz.Db {
	return p.db
}

func (p *TestDbProvider) GetStores() *db.Stores {
	return p.fabricStores
}

func (p *TestDbProvider) GetServiceCache() network.Cache {
	return p
}

func (p *TestDbProvider) RemoveFromCache(_ string) {
}

func (p *TestDbProvider) GetControllers() *network.Controllers {
	return p.controllers
}

type TestContext struct {
	require.Assertions
	t             *testing.T
	dbFile        *os.File
	DbProvider    *TestDbProvider
	stores        *Stores
	ReferenceTime time.Time
}

func NewTestContext(t *testing.T) *TestContext {
	return &TestContext{
		Assertions:    *require.New(t),
		t:             t,
		dbFile:        nil,
		DbProvider:    &TestDbProvider{},
		stores:        nil,
		ReferenceTime: time.Now(),
	}
}

func (ctx *TestContext) GetDb() boltz.Db {
	return ctx.DbProvider.db
}

func (ctx *TestContext) GetStores() *Stores {
	return ctx.stores
}

func (ctx *TestContext) Init() {
	var err error
	ctx.dbFile, err = ioutil.TempFile("", "query-bolt-ctx-db")
	ctx.NoError(err)

	err = ctx.dbFile.Close()
	ctx.NoError(err)

	ctx.DbProvider.db, err = db.Open(ctx.dbFile.Name())
	ctx.NoError(err)

	ctx.DbProvider.fabricStores = db.InitStores()
	ctx.DbProvider.controllers = network.NewControllers(ctx.DbProvider.db, ctx.DbProvider.fabricStores)
	ctx.stores, err = NewBoltStores(ctx.DbProvider)

	ctx.NoError(err)

	ctx.NoError(RunMigrations(ctx.DbProvider, ctx.stores, nil))
}

func (ctx *TestContext) Cleanup() {
	if ctx.GetDb() != nil {
		if err := ctx.GetDb().Close(); err != nil {
			fmt.Printf("error closing bolt db: %v", err)
		}
	}

	if ctx.dbFile != nil {
		if err := os.Remove(ctx.dbFile.Name()); err != nil {
			fmt.Printf("error deleting bolt db file: %v", err)
		}
	}
}

func (ctx *TestContext) requireNewServicePolicy(policyType int32, identityRoles []string, serviceRoles []string) *ServicePolicy {
	entity := &ServicePolicy{
		BaseExtEntity: boltz.BaseExtEntity{Id: uuid.New().String()},
		Name:          uuid.New().String(),
		PolicyType:    policyType,
		IdentityRoles: identityRoles,
		ServiceRoles:  serviceRoles,
	}
	ctx.requireCreate(entity)
	return entity
}

func (ctx *TestContext) requireNewIdentity(name string, isAdmin bool) *Identity {
	identity := &Identity{
		BaseExtEntity: *boltz.NewExtEntity(uuid.New().String(), nil),
		Name:          name,
		IsAdmin:       isAdmin,
	}
	ctx.requireCreate(identity)
	return identity
}

func (ctx *TestContext) requireNewService(name string) *EdgeService {
	edgeService := &EdgeService{
		Service: db.Service{
			Id: uuid.New().String(),
		},
		Name: name,
	}
	ctx.requireCreate(edgeService)
	return edgeService
}

func (ctx *TestContext) requireDelete(entity boltz.Entity) {
	err := ctx.delete(entity)
	ctx.NoError(err)
	ctx.validateDeleted(entity.GetId())
}

func (ctx *TestContext) requireReload(entity boltz.Entity) {
	ctx.NoError(ctx.reload(entity))
}

func (ctx *TestContext) delete(entity boltz.Entity) error {
	return ctx.GetDb().Update(func(tx *bbolt.Tx) error {
		mutateContext := boltz.NewMutateContext(tx)
		store := ctx.stores.GetStoreForEntity(entity)
		if store == nil {
			return errors.Errorf("no store for entity of type '%v'", entity.GetEntityType())
		}
		return store.DeleteById(mutateContext, entity.GetId())
	})
}

func (ctx *TestContext) reload(entity boltz.Entity) error {
	return ctx.GetDb().View(func(tx *bbolt.Tx) error {
		store := ctx.stores.GetStoreForEntity(entity)
		if store == nil {
			return errors.Errorf("no store for entity of type '%v'", entity.GetEntityType())
		}
		found, err := store.BaseLoadOneById(tx, entity.GetId(), entity)
		if !found {
			return errors.Errorf("Could not reload %v with id %v", store.GetEntityType(), entity.GetId())
		}
		return err
	})
}

func (ctx *TestContext) validateDeleted(id string) {
	err := ctx.GetDb().View(func(tx *bbolt.Tx) error {
		return boltz.ValidateDeleted(tx, id)
	})
	ctx.NoError(err)
}

func (ctx *TestContext) requireCreate(entity boltz.Entity) {
	err := ctx.create(entity)
	if err != nil {
		fmt.Printf("error: %+v\n", err)
	}
	ctx.NoError(err)
}

func (ctx *TestContext) requireUpdate(entity boltz.Entity) {
	ctx.NoError(ctx.update(entity))
}

func (ctx *TestContext) create(entity boltz.Entity) error {
	return ctx.GetDb().Update(func(tx *bbolt.Tx) error {
		mutateContext := boltz.NewMutateContext(tx)
		store, err := ctx.getStoreForEntity(entity)
		if err != nil {
			return err
		}
		return store.Create(mutateContext, entity)
	})
}

func (ctx *TestContext) update(entity boltz.Entity) error {
	return ctx.GetDb().Update(func(tx *bbolt.Tx) error {
		mutateContext := boltz.NewMutateContext(tx)
		store, err := ctx.getStoreForEntity(entity)
		if err != nil {
			return err
		}
		return store.Update(mutateContext, entity, nil)
	})
}

func (ctx *TestContext) getStoreForEntity(entity boltz.Entity) (boltz.CrudStore, error) {
	var store boltz.CrudStore

	if _, ok := entity.(*db.Service); ok {
		store = ctx.stores.Service
	} else if _, ok := entity.(*db.Router); ok {
		store = ctx.stores.Router
	} else {
		store = ctx.stores.GetStoreForEntity(entity)
	}
	if store != nil {
		return store, nil
	}

	return nil, errors.Errorf("no store for entity of type '%v'", entity.GetEntityType())
}

func (ctx *TestContext) validateBaseline(entity boltz.ExtEntity) {
	store := ctx.stores.GetStoreForEntity(entity)
	ctx.NotNil(store, "no store for entity of type '%v'", entity.GetEntityType())

	loaded, ok := store.NewStoreEntity().(boltz.ExtEntity)
	ctx.True(ok, "store entity type does not implement Entity: %v", reflect.TypeOf(store.NewStoreEntity()))

	err := ctx.GetDb().View(func(tx *bbolt.Tx) error {
		found, err := store.BaseLoadOneById(tx, entity.GetId(), loaded)
		ctx.NoError(err)
		ctx.Equal(true, found)

		now := time.Now()
		ctx.Equal(entity.GetId(), loaded.GetId())
		ctx.Equal(entity.GetEntityType(), loaded.GetEntityType())
		ctx.True(loaded.GetCreatedAt().Equal(loaded.GetUpdatedAt()))
		ctx.True(loaded.GetCreatedAt().Equal(ctx.ReferenceTime) || loaded.GetCreatedAt().After(ctx.ReferenceTime))
		ctx.True(loaded.GetCreatedAt().Equal(now) || loaded.GetCreatedAt().Before(now))

		return nil
	})
	ctx.NoError(err)

	entity.SetCreatedAt(loaded.GetCreatedAt())
	entity.SetUpdatedAt(loaded.GetUpdatedAt())
	if entity.GetTags() == nil {
		entity.SetTags(map[string]interface{}{})
	}

	ctx.True(cmp.Equal(entity, loaded), cmp.Diff(entity, loaded))
}

func (ctx *TestContext) validateUpdated(entity boltz.ExtEntity) {
	store := ctx.stores.GetStoreForEntity(entity)
	ctx.NotNil(store, "no store for entity of type '%v'", entity.GetEntityType())

	loaded, ok := store.NewStoreEntity().(boltz.ExtEntity)
	ctx.True(ok, "store entity type does not implement Entity: %v", reflect.TypeOf(store.NewStoreEntity()))

	err := ctx.GetDb().View(func(tx *bbolt.Tx) error {
		found, err := store.BaseLoadOneById(tx, entity.GetId(), loaded)
		ctx.NoError(err)
		ctx.Equal(true, found)

		now := time.Now()
		ctx.Equal(entity.GetId(), loaded.GetId())
		ctx.Equal(entity.GetEntityType(), loaded.GetEntityType())
		ctx.Equal(entity.GetCreatedAt(), loaded.GetCreatedAt())
		ctx.True(loaded.GetCreatedAt().Before(loaded.GetUpdatedAt()))
		ctx.True(loaded.GetUpdatedAt().Equal(now) || loaded.GetUpdatedAt().Before(now))

		return nil
	})
	ctx.NoError(err)

	entity.SetCreatedAt(loaded.GetCreatedAt())
	entity.SetUpdatedAt(loaded.GetUpdatedAt())
	if entity.GetTags() == nil {
		entity.SetTags(map[string]interface{}{})
	}

	ctx.True(cmp.Equal(entity, loaded), cmp.Diff(entity, loaded))
}

func (ctx *TestContext) getRelatedIds(entity boltz.Entity, field string) []string {
	var result []string
	err := ctx.GetDb().View(func(tx *bbolt.Tx) error {
		store := ctx.stores.GetStoreForEntity(entity)
		if store == nil {
			return errors.Errorf("no store for entity of type '%v'", entity.GetEntityType())
		}
		result = store.GetRelatedEntitiesIdList(tx, entity.GetId(), field)
		return nil
	})
	ctx.NoError(err)
	return result
}

func (ctx *TestContext) createTags() map[string]interface{} {
	return map[string]interface{}{
		"hello":             uuid.New().String(),
		uuid.New().String(): "hello",
		"count":             rand.Int63(),
		"enabled":           rand.Int()%2 == 0,
		uuid.New().String(): int32(27),
		"markerKey":         nil,
	}
}

func (ctx *TestContext) cleanupAll() {
	stores := []boltz.CrudStore{
		ctx.stores.Session,
		ctx.stores.ApiSession,
		ctx.stores.EdgeRouterPolicy,
		ctx.stores.Appwan,
		ctx.stores.Service,
		ctx.stores.EdgeService,
		ctx.stores.Identity,
		ctx.stores.EdgeRouter,
		ctx.stores.Cluster,
		ctx.stores.Config,
	}
	_ = ctx.GetDb().Update(func(tx *bbolt.Tx) error {
		mutateContext := boltz.NewMutateContext(tx)
		for _, store := range stores {
			if err := store.DeleteWhere(mutateContext, `true limit none`); err != nil {
				pfxlog.Logger().WithError(err).Errorf("failure while cleaning up %v", store.GetEntityType())
				return err
			}
		}
		return nil
	})
}

func (ctx *TestContext) getIdentityTypeId() string {
	var result string
	err := ctx.GetDb().View(func(tx *bbolt.Tx) error {
		ids, _, err := ctx.stores.IdentityType.QueryIds(tx, "true")
		if err != nil {
			return err
		}
		result = ids[0]
		return nil
	})
	ctx.NoError(err)
	return result
}

func ss(vals ...string) []string {
	return vals
}
