package model

import (
	"github.com/google/uuid"
	"testing"
)

func Test_SessionHandlers(t *testing.T) {
	ctx := NewTestContext(t)
	defer ctx.Cleanup()
	ctx.Init()

	t.Run("test get edge routers for session", ctx.testGetSessionsForEdgeRouter)
}

func (ctx *TestContext) testGetSessionsForEdgeRouter(_ *testing.T) {
	service := ctx.requireNewService(uuid.New().String())
	identity := ctx.requireNewIdentity(uuid.New().String(), false)
	
}
