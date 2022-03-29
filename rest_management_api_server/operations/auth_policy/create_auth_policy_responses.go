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

package auth_policy

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/openziti/edge/rest_model"
)

// CreateAuthPolicyCreatedCode is the HTTP code returned for type CreateAuthPolicyCreated
const CreateAuthPolicyCreatedCode int = 201

/*CreateAuthPolicyCreated The create request was successful and the resource has been added at the following location

swagger:response createAuthPolicyCreated
*/
type CreateAuthPolicyCreated struct {

	/*
	  In: Body
	*/
	Payload *rest_model.CreateEnvelope `json:"body,omitempty"`
}

// NewCreateAuthPolicyCreated creates CreateAuthPolicyCreated with default headers values
func NewCreateAuthPolicyCreated() *CreateAuthPolicyCreated {

	return &CreateAuthPolicyCreated{}
}

// WithPayload adds the payload to the create auth policy created response
func (o *CreateAuthPolicyCreated) WithPayload(payload *rest_model.CreateEnvelope) *CreateAuthPolicyCreated {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the create auth policy created response
func (o *CreateAuthPolicyCreated) SetPayload(payload *rest_model.CreateEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *CreateAuthPolicyCreated) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(201)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// CreateAuthPolicyBadRequestCode is the HTTP code returned for type CreateAuthPolicyBadRequest
const CreateAuthPolicyBadRequestCode int = 400

/*CreateAuthPolicyBadRequest The supplied request contains invalid fields or could not be parsed (json and non-json bodies). The error's code, message, and cause fields can be inspected for further information

swagger:response createAuthPolicyBadRequest
*/
type CreateAuthPolicyBadRequest struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewCreateAuthPolicyBadRequest creates CreateAuthPolicyBadRequest with default headers values
func NewCreateAuthPolicyBadRequest() *CreateAuthPolicyBadRequest {

	return &CreateAuthPolicyBadRequest{}
}

// WithPayload adds the payload to the create auth policy bad request response
func (o *CreateAuthPolicyBadRequest) WithPayload(payload *rest_model.APIErrorEnvelope) *CreateAuthPolicyBadRequest {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the create auth policy bad request response
func (o *CreateAuthPolicyBadRequest) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *CreateAuthPolicyBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(400)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// CreateAuthPolicyUnauthorizedCode is the HTTP code returned for type CreateAuthPolicyUnauthorized
const CreateAuthPolicyUnauthorizedCode int = 401

/*CreateAuthPolicyUnauthorized The currently supplied session does not have the correct access rights to request this resource

swagger:response createAuthPolicyUnauthorized
*/
type CreateAuthPolicyUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewCreateAuthPolicyUnauthorized creates CreateAuthPolicyUnauthorized with default headers values
func NewCreateAuthPolicyUnauthorized() *CreateAuthPolicyUnauthorized {

	return &CreateAuthPolicyUnauthorized{}
}

// WithPayload adds the payload to the create auth policy unauthorized response
func (o *CreateAuthPolicyUnauthorized) WithPayload(payload *rest_model.APIErrorEnvelope) *CreateAuthPolicyUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the create auth policy unauthorized response
func (o *CreateAuthPolicyUnauthorized) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *CreateAuthPolicyUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
