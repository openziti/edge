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

package session

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/netfoundry/ziti-edge/models"
)

// ListSessionsOKCode is the HTTP code returned for type ListSessionsOK
const ListSessionsOKCode int = 200

/*ListSessionsOK A list of sessions

swagger:response listSessionsOK
*/
type ListSessionsOK struct {

	/*
	  In: Body
	*/
	Payload *models.ListSessionsEnvelope `json:"body,omitempty"`
}

// NewListSessionsOK creates ListSessionsOK with default headers values
func NewListSessionsOK() *ListSessionsOK {

	return &ListSessionsOK{}
}

// WithPayload adds the payload to the list sessions o k response
func (o *ListSessionsOK) WithPayload(payload *models.ListSessionsEnvelope) *ListSessionsOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the list sessions o k response
func (o *ListSessionsOK) SetPayload(payload *models.ListSessionsEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *ListSessionsOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// ListSessionsUnauthorizedCode is the HTTP code returned for type ListSessionsUnauthorized
const ListSessionsUnauthorizedCode int = 401

/*ListSessionsUnauthorized The currently supplied session does not have the correct access rights to request this resource

swagger:response listSessionsUnauthorized
*/
type ListSessionsUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *models.APIErrorEnvelope `json:"body,omitempty"`
}

// NewListSessionsUnauthorized creates ListSessionsUnauthorized with default headers values
func NewListSessionsUnauthorized() *ListSessionsUnauthorized {

	return &ListSessionsUnauthorized{}
}

// WithPayload adds the payload to the list sessions unauthorized response
func (o *ListSessionsUnauthorized) WithPayload(payload *models.APIErrorEnvelope) *ListSessionsUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the list sessions unauthorized response
func (o *ListSessionsUnauthorized) SetPayload(payload *models.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *ListSessionsUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
