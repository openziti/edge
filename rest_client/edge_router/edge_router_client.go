// Code generated by go-swagger; DO NOT EDIT.

//
// Copyright NetFoundry, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// __          __              _
// \ \        / /             (_)
//  \ \  /\  / /_ _ _ __ _ __  _ _ __   __ _
//   \ \/  \/ / _` | '__| '_ \| | '_ \ / _` |
//    \  /\  / (_| | |  | | | | | | | | (_| | : This file is generated, do not edit it.
//     \/  \/ \__,_|_|  |_| |_|_|_| |_|\__, |
//                                      __/ |
//                                     |___/

package edge_router

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new edge router API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for edge router API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientService is the interface for Client methods
type ClientService interface {
	CreateEdgeRouter(params *CreateEdgeRouterParams, authInfo runtime.ClientAuthInfoWriter) (*CreateEdgeRouterOK, error)

	DeleteEdgeRouter(params *DeleteEdgeRouterParams, authInfo runtime.ClientAuthInfoWriter) (*DeleteEdgeRouterOK, error)

	DetailEdgeRouter(params *DetailEdgeRouterParams, authInfo runtime.ClientAuthInfoWriter) (*DetailEdgeRouterOK, error)

	LisgEdgeRouters(params *LisgEdgeRoutersParams, authInfo runtime.ClientAuthInfoWriter) (*LisgEdgeRoutersOK, error)

	ListEdgeRoutersEdgeRouterPolicies(params *ListEdgeRoutersEdgeRouterPoliciesParams, authInfo runtime.ClientAuthInfoWriter) (*ListEdgeRoutersEdgeRouterPoliciesOK, error)

	ListEdgeRoutersServicePolicies(params *ListEdgeRoutersServicePoliciesParams, authInfo runtime.ClientAuthInfoWriter) (*ListEdgeRoutersServicePoliciesOK, error)

	PatchEdgeRouter(params *PatchEdgeRouterParams, authInfo runtime.ClientAuthInfoWriter) (*PatchEdgeRouterOK, error)

	UpdateEdgeRouter(params *UpdateEdgeRouterParams, authInfo runtime.ClientAuthInfoWriter) (*UpdateEdgeRouterOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
  CreateEdgeRouter creates an edge router

  Create a edge router resource. Requires admin access.
*/
func (a *Client) CreateEdgeRouter(params *CreateEdgeRouterParams, authInfo runtime.ClientAuthInfoWriter) (*CreateEdgeRouterOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreateEdgeRouterParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "createEdgeRouter",
		Method:             "POST",
		PathPattern:        "/edge-routers",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CreateEdgeRouterReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*CreateEdgeRouterOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for createEdgeRouter: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  DeleteEdgeRouter deletes an edge router

  Delete an edge router by id. Requires admin access.
*/
func (a *Client) DeleteEdgeRouter(params *DeleteEdgeRouterParams, authInfo runtime.ClientAuthInfoWriter) (*DeleteEdgeRouterOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteEdgeRouterParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "deleteEdgeRouter",
		Method:             "DELETE",
		PathPattern:        "/edge-routers/{id}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteEdgeRouterReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*DeleteEdgeRouterOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for deleteEdgeRouter: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  DetailEdgeRouter retrieves a single edge router

  Retrieves a single edge router by id. Requires admin access.
*/
func (a *Client) DetailEdgeRouter(params *DetailEdgeRouterParams, authInfo runtime.ClientAuthInfoWriter) (*DetailEdgeRouterOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDetailEdgeRouterParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "detailEdgeRouter",
		Method:             "GET",
		PathPattern:        "/edge-routers/{id}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DetailEdgeRouterReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*DetailEdgeRouterOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for detailEdgeRouter: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  LisgEdgeRouters lists edge routers

  Retrieves a list of edge router resources; supports filtering, sorting, and pagination. Requires admin access.

*/
func (a *Client) LisgEdgeRouters(params *LisgEdgeRoutersParams, authInfo runtime.ClientAuthInfoWriter) (*LisgEdgeRoutersOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewLisgEdgeRoutersParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "lisgEdgeRouters",
		Method:             "GET",
		PathPattern:        "/edge-routers",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &LisgEdgeRoutersReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*LisgEdgeRoutersOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for lisgEdgeRouters: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  ListEdgeRoutersEdgeRouterPolicies lists the edge router policies that affect an edge router

  Retrieves a list of edge router policies that apply to the specified edge router.
*/
func (a *Client) ListEdgeRoutersEdgeRouterPolicies(params *ListEdgeRoutersEdgeRouterPoliciesParams, authInfo runtime.ClientAuthInfoWriter) (*ListEdgeRoutersEdgeRouterPoliciesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListEdgeRoutersEdgeRouterPoliciesParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "listEdgeRoutersEdgeRouterPolicies",
		Method:             "GET",
		PathPattern:        "/edge-routers/{id}/edge-router-policies",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListEdgeRoutersEdgeRouterPoliciesReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*ListEdgeRoutersEdgeRouterPoliciesOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listEdgeRoutersEdgeRouterPolicies: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  ListEdgeRoutersServicePolicies lists the service policies that affect an edge router

  Retrieves a list of service policies policies that apply to the specified edge router.
*/
func (a *Client) ListEdgeRoutersServicePolicies(params *ListEdgeRoutersServicePoliciesParams, authInfo runtime.ClientAuthInfoWriter) (*ListEdgeRoutersServicePoliciesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListEdgeRoutersServicePoliciesParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "listEdgeRoutersServicePolicies",
		Method:             "GET",
		PathPattern:        "/edge-routers/{id}/service-edge-router-policies",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListEdgeRoutersServicePoliciesReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*ListEdgeRoutersServicePoliciesOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listEdgeRoutersServicePolicies: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  PatchEdgeRouter updates the supplied fields on an edge router

  Update the supplied fields on an edge router. Requires admin access.
*/
func (a *Client) PatchEdgeRouter(params *PatchEdgeRouterParams, authInfo runtime.ClientAuthInfoWriter) (*PatchEdgeRouterOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPatchEdgeRouterParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "patchEdgeRouter",
		Method:             "PATCH",
		PathPattern:        "/edge-routers/{id}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PatchEdgeRouterReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*PatchEdgeRouterOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for patchEdgeRouter: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  UpdateEdgeRouter updates all fields on an edge router

  Update all fields on an edge router by id. Requires admin access.
*/
func (a *Client) UpdateEdgeRouter(params *UpdateEdgeRouterParams, authInfo runtime.ClientAuthInfoWriter) (*UpdateEdgeRouterOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewUpdateEdgeRouterParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "updateEdgeRouter",
		Method:             "PUT",
		PathPattern:        "/edge-routers/{id}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &UpdateEdgeRouterReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*UpdateEdgeRouterOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for updateEdgeRouter: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
