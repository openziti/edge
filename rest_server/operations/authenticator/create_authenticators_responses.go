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

package authenticator

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/netfoundry/ziti-edge/rest_model"
)

// CreateAuthenticatorsOKCode is the HTTP code returned for type CreateAuthenticatorsOK
const CreateAuthenticatorsOKCode int = 200

/*CreateAuthenticatorsOK The create was successful

swagger:response createAuthenticatorsOK
*/
type CreateAuthenticatorsOK struct {

	/*
	  In: Body
	*/
	Payload *rest_model.AuthenticatorCreate `json:"body,omitempty"`
}

// NewCreateAuthenticatorsOK creates CreateAuthenticatorsOK with default headers values
func NewCreateAuthenticatorsOK() *CreateAuthenticatorsOK {

	return &CreateAuthenticatorsOK{}
}

// WithPayload adds the payload to the create authenticators o k response
func (o *CreateAuthenticatorsOK) WithPayload(payload *rest_model.AuthenticatorCreate) *CreateAuthenticatorsOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the create authenticators o k response
func (o *CreateAuthenticatorsOK) SetPayload(payload *rest_model.AuthenticatorCreate) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *CreateAuthenticatorsOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// CreateAuthenticatorsBadRequestCode is the HTTP code returned for type CreateAuthenticatorsBadRequest
const CreateAuthenticatorsBadRequestCode int = 400

/*CreateAuthenticatorsBadRequest The supplied request contains invalid fields or could not be parsed (json and non-json bodies). The error's code, message, and cause fields can be inspected for further information

swagger:response createAuthenticatorsBadRequest
*/
type CreateAuthenticatorsBadRequest struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewCreateAuthenticatorsBadRequest creates CreateAuthenticatorsBadRequest with default headers values
func NewCreateAuthenticatorsBadRequest() *CreateAuthenticatorsBadRequest {

	return &CreateAuthenticatorsBadRequest{}
}

// WithPayload adds the payload to the create authenticators bad request response
func (o *CreateAuthenticatorsBadRequest) WithPayload(payload *rest_model.APIErrorEnvelope) *CreateAuthenticatorsBadRequest {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the create authenticators bad request response
func (o *CreateAuthenticatorsBadRequest) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *CreateAuthenticatorsBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(400)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// CreateAuthenticatorsUnauthorizedCode is the HTTP code returned for type CreateAuthenticatorsUnauthorized
const CreateAuthenticatorsUnauthorizedCode int = 401

/*CreateAuthenticatorsUnauthorized The currently supplied session does not have the correct access rights to request this resource

swagger:response createAuthenticatorsUnauthorized
*/
type CreateAuthenticatorsUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewCreateAuthenticatorsUnauthorized creates CreateAuthenticatorsUnauthorized with default headers values
func NewCreateAuthenticatorsUnauthorized() *CreateAuthenticatorsUnauthorized {

	return &CreateAuthenticatorsUnauthorized{}
}

// WithPayload adds the payload to the create authenticators unauthorized response
func (o *CreateAuthenticatorsUnauthorized) WithPayload(payload *rest_model.APIErrorEnvelope) *CreateAuthenticatorsUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the create authenticators unauthorized response
func (o *CreateAuthenticatorsUnauthorized) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *CreateAuthenticatorsUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
