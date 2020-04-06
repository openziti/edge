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

package certificate_authority

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/netfoundry/ziti-edge/rest_model"
)

// PostCasIDVerifyOKCode is the HTTP code returned for type PostCasIDVerifyOK
const PostCasIDVerifyOKCode int = 200

/*PostCasIDVerifyOK Base empty response

swagger:response postCasIdVerifyOK
*/
type PostCasIDVerifyOK struct {

	/*
	  In: Body
	*/
	Payload *rest_model.Empty `json:"body,omitempty"`
}

// NewPostCasIDVerifyOK creates PostCasIDVerifyOK with default headers values
func NewPostCasIDVerifyOK() *PostCasIDVerifyOK {

	return &PostCasIDVerifyOK{}
}

// WithPayload adds the payload to the post cas Id verify o k response
func (o *PostCasIDVerifyOK) WithPayload(payload *rest_model.Empty) *PostCasIDVerifyOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the post cas Id verify o k response
func (o *PostCasIDVerifyOK) SetPayload(payload *rest_model.Empty) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *PostCasIDVerifyOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// PostCasIDVerifyBadRequestCode is the HTTP code returned for type PostCasIDVerifyBadRequest
const PostCasIDVerifyBadRequestCode int = 400

/*PostCasIDVerifyBadRequest The supplied request contains invalid fields or could not be parsed (json and non-json bodies). The error's code, message, and cause fields can be inspected for further information

swagger:response postCasIdVerifyBadRequest
*/
type PostCasIDVerifyBadRequest struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewPostCasIDVerifyBadRequest creates PostCasIDVerifyBadRequest with default headers values
func NewPostCasIDVerifyBadRequest() *PostCasIDVerifyBadRequest {

	return &PostCasIDVerifyBadRequest{}
}

// WithPayload adds the payload to the post cas Id verify bad request response
func (o *PostCasIDVerifyBadRequest) WithPayload(payload *rest_model.APIErrorEnvelope) *PostCasIDVerifyBadRequest {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the post cas Id verify bad request response
func (o *PostCasIDVerifyBadRequest) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *PostCasIDVerifyBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(400)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// PostCasIDVerifyUnauthorizedCode is the HTTP code returned for type PostCasIDVerifyUnauthorized
const PostCasIDVerifyUnauthorizedCode int = 401

/*PostCasIDVerifyUnauthorized The currently supplied session does not have the correct access rights to request this resource

swagger:response postCasIdVerifyUnauthorized
*/
type PostCasIDVerifyUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewPostCasIDVerifyUnauthorized creates PostCasIDVerifyUnauthorized with default headers values
func NewPostCasIDVerifyUnauthorized() *PostCasIDVerifyUnauthorized {

	return &PostCasIDVerifyUnauthorized{}
}

// WithPayload adds the payload to the post cas Id verify unauthorized response
func (o *PostCasIDVerifyUnauthorized) WithPayload(payload *rest_model.APIErrorEnvelope) *PostCasIDVerifyUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the post cas Id verify unauthorized response
func (o *PostCasIDVerifyUnauthorized) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *PostCasIDVerifyUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// PostCasIDVerifyNotFoundCode is the HTTP code returned for type PostCasIDVerifyNotFound
const PostCasIDVerifyNotFoundCode int = 404

/*PostCasIDVerifyNotFound The requested resource does not exist

swagger:response postCasIdVerifyNotFound
*/
type PostCasIDVerifyNotFound struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewPostCasIDVerifyNotFound creates PostCasIDVerifyNotFound with default headers values
func NewPostCasIDVerifyNotFound() *PostCasIDVerifyNotFound {

	return &PostCasIDVerifyNotFound{}
}

// WithPayload adds the payload to the post cas Id verify not found response
func (o *PostCasIDVerifyNotFound) WithPayload(payload *rest_model.APIErrorEnvelope) *PostCasIDVerifyNotFound {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the post cas Id verify not found response
func (o *PostCasIDVerifyNotFound) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *PostCasIDVerifyNotFound) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(404)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
