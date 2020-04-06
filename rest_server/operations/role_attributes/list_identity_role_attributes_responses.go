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

package role_attributes

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/netfoundry/ziti-edge/rest_model"
)

// ListIdentityRoleAttributesOKCode is the HTTP code returned for type ListIdentityRoleAttributesOK
const ListIdentityRoleAttributesOKCode int = 200

/*ListIdentityRoleAttributesOK A list of role attributes

swagger:response listIdentityRoleAttributesOK
*/
type ListIdentityRoleAttributesOK struct {

	/*
	  In: Body
	*/
	Payload *rest_model.ListRoleAttributesEnvelope `json:"body,omitempty"`
}

// NewListIdentityRoleAttributesOK creates ListIdentityRoleAttributesOK with default headers values
func NewListIdentityRoleAttributesOK() *ListIdentityRoleAttributesOK {

	return &ListIdentityRoleAttributesOK{}
}

// WithPayload adds the payload to the list identity role attributes o k response
func (o *ListIdentityRoleAttributesOK) WithPayload(payload *rest_model.ListRoleAttributesEnvelope) *ListIdentityRoleAttributesOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the list identity role attributes o k response
func (o *ListIdentityRoleAttributesOK) SetPayload(payload *rest_model.ListRoleAttributesEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *ListIdentityRoleAttributesOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// ListIdentityRoleAttributesUnauthorizedCode is the HTTP code returned for type ListIdentityRoleAttributesUnauthorized
const ListIdentityRoleAttributesUnauthorizedCode int = 401

/*ListIdentityRoleAttributesUnauthorized The currently supplied session does not have the correct access rights to request this resource

swagger:response listIdentityRoleAttributesUnauthorized
*/
type ListIdentityRoleAttributesUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewListIdentityRoleAttributesUnauthorized creates ListIdentityRoleAttributesUnauthorized with default headers values
func NewListIdentityRoleAttributesUnauthorized() *ListIdentityRoleAttributesUnauthorized {

	return &ListIdentityRoleAttributesUnauthorized{}
}

// WithPayload adds the payload to the list identity role attributes unauthorized response
func (o *ListIdentityRoleAttributesUnauthorized) WithPayload(payload *rest_model.APIErrorEnvelope) *ListIdentityRoleAttributesUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the list identity role attributes unauthorized response
func (o *ListIdentityRoleAttributesUnauthorized) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *ListIdentityRoleAttributesUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
