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

package geo_region

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/netfoundry/ziti-edge/rest_model"
)

// ListGeoRegionOKCode is the HTTP code returned for type ListGeoRegionOK
const ListGeoRegionOKCode int = 200

/*ListGeoRegionOK A list of geo-regions

swagger:response listGeoRegionOK
*/
type ListGeoRegionOK struct {

	/*
	  In: Body
	*/
	Payload *rest_model.ListGeoRegionsEnvelope `json:"body,omitempty"`
}

// NewListGeoRegionOK creates ListGeoRegionOK with default headers values
func NewListGeoRegionOK() *ListGeoRegionOK {

	return &ListGeoRegionOK{}
}

// WithPayload adds the payload to the list geo region o k response
func (o *ListGeoRegionOK) WithPayload(payload *rest_model.ListGeoRegionsEnvelope) *ListGeoRegionOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the list geo region o k response
func (o *ListGeoRegionOK) SetPayload(payload *rest_model.ListGeoRegionsEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *ListGeoRegionOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// ListGeoRegionUnauthorizedCode is the HTTP code returned for type ListGeoRegionUnauthorized
const ListGeoRegionUnauthorizedCode int = 401

/*ListGeoRegionUnauthorized The currently supplied session does not have the correct access rights to request this resource

swagger:response listGeoRegionUnauthorized
*/
type ListGeoRegionUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewListGeoRegionUnauthorized creates ListGeoRegionUnauthorized with default headers values
func NewListGeoRegionUnauthorized() *ListGeoRegionUnauthorized {

	return &ListGeoRegionUnauthorized{}
}

// WithPayload adds the payload to the list geo region unauthorized response
func (o *ListGeoRegionUnauthorized) WithPayload(payload *rest_model.APIErrorEnvelope) *ListGeoRegionUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the list geo region unauthorized response
func (o *ListGeoRegionUnauthorized) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *ListGeoRegionUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
