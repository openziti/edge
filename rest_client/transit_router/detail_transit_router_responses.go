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

package transit_router

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/netfoundry/ziti-edge/rest_model"
)

// DetailTransitRouterReader is a Reader for the DetailTransitRouter structure.
type DetailTransitRouterReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DetailTransitRouterReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDetailTransitRouterOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewDetailTransitRouterUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDetailTransitRouterNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewDetailTransitRouterOK creates a DetailTransitRouterOK with default headers values
func NewDetailTransitRouterOK() *DetailTransitRouterOK {
	return &DetailTransitRouterOK{}
}

/*DetailTransitRouterOK handles this case with default header values.

A single transit router
*/
type DetailTransitRouterOK struct {
	Payload *rest_model.DetailTransitRouterEnvelope
}

func (o *DetailTransitRouterOK) Error() string {
	return fmt.Sprintf("[GET /transit-routers/{id}][%d] detailTransitRouterOK  %+v", 200, o.Payload)
}

func (o *DetailTransitRouterOK) GetPayload() *rest_model.DetailTransitRouterEnvelope {
	return o.Payload
}

func (o *DetailTransitRouterOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.DetailTransitRouterEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDetailTransitRouterUnauthorized creates a DetailTransitRouterUnauthorized with default headers values
func NewDetailTransitRouterUnauthorized() *DetailTransitRouterUnauthorized {
	return &DetailTransitRouterUnauthorized{}
}

/*DetailTransitRouterUnauthorized handles this case with default header values.

The currently supplied session does not have the correct access rights to request this resource
*/
type DetailTransitRouterUnauthorized struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *DetailTransitRouterUnauthorized) Error() string {
	return fmt.Sprintf("[GET /transit-routers/{id}][%d] detailTransitRouterUnauthorized  %+v", 401, o.Payload)
}

func (o *DetailTransitRouterUnauthorized) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *DetailTransitRouterUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDetailTransitRouterNotFound creates a DetailTransitRouterNotFound with default headers values
func NewDetailTransitRouterNotFound() *DetailTransitRouterNotFound {
	return &DetailTransitRouterNotFound{}
}

/*DetailTransitRouterNotFound handles this case with default header values.

The requested resource does not exist
*/
type DetailTransitRouterNotFound struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *DetailTransitRouterNotFound) Error() string {
	return fmt.Sprintf("[GET /transit-routers/{id}][%d] detailTransitRouterNotFound  %+v", 404, o.Payload)
}

func (o *DetailTransitRouterNotFound) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *DetailTransitRouterNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
