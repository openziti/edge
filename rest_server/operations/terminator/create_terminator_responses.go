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

package terminator

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/netfoundry/ziti-edge/models"
)

// CreateTerminatorOKCode is the HTTP code returned for type CreateTerminatorOK
const CreateTerminatorOKCode int = 200

/*CreateTerminatorOK The create request was successful and the resource has been added at the following location

swagger:response createTerminatorOK
*/
type CreateTerminatorOK struct {

	/*
	  In: Body
	*/
	Payload *models.Create `json:"body,omitempty"`
}

// NewCreateTerminatorOK creates CreateTerminatorOK with default headers values
func NewCreateTerminatorOK() *CreateTerminatorOK {

	return &CreateTerminatorOK{}
}

// WithPayload adds the payload to the create terminator o k response
func (o *CreateTerminatorOK) WithPayload(payload *models.Create) *CreateTerminatorOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the create terminator o k response
func (o *CreateTerminatorOK) SetPayload(payload *models.Create) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *CreateTerminatorOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// CreateTerminatorBadRequestCode is the HTTP code returned for type CreateTerminatorBadRequest
const CreateTerminatorBadRequestCode int = 400

/*CreateTerminatorBadRequest The supplied request contains invalid fields or could not be parsed (json and non-json bodies). The error's code, message, and cause fields can be inspected for further information

swagger:response createTerminatorBadRequest
*/
type CreateTerminatorBadRequest struct {

	/*
	  In: Body
	*/
	Payload *models.APIErrorEnvelope `json:"body,omitempty"`
}

// NewCreateTerminatorBadRequest creates CreateTerminatorBadRequest with default headers values
func NewCreateTerminatorBadRequest() *CreateTerminatorBadRequest {

	return &CreateTerminatorBadRequest{}
}

// WithPayload adds the payload to the create terminator bad request response
func (o *CreateTerminatorBadRequest) WithPayload(payload *models.APIErrorEnvelope) *CreateTerminatorBadRequest {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the create terminator bad request response
func (o *CreateTerminatorBadRequest) SetPayload(payload *models.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *CreateTerminatorBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(400)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// CreateTerminatorUnauthorizedCode is the HTTP code returned for type CreateTerminatorUnauthorized
const CreateTerminatorUnauthorizedCode int = 401

/*CreateTerminatorUnauthorized The currently supplied session does not have the correct access rights to request this resource

swagger:response createTerminatorUnauthorized
*/
type CreateTerminatorUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *models.APIErrorEnvelope `json:"body,omitempty"`
}

// NewCreateTerminatorUnauthorized creates CreateTerminatorUnauthorized with default headers values
func NewCreateTerminatorUnauthorized() *CreateTerminatorUnauthorized {

	return &CreateTerminatorUnauthorized{}
}

// WithPayload adds the payload to the create terminator unauthorized response
func (o *CreateTerminatorUnauthorized) WithPayload(payload *models.APIErrorEnvelope) *CreateTerminatorUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the create terminator unauthorized response
func (o *CreateTerminatorUnauthorized) SetPayload(payload *models.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *CreateTerminatorUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
