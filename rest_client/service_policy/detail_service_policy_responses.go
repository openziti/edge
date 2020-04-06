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

package service_policy

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/netfoundry/ziti-edge/rest_model"
)

// DetailServicePolicyReader is a Reader for the DetailServicePolicy structure.
type DetailServicePolicyReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DetailServicePolicyReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDetailServicePolicyOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewDetailServicePolicyUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDetailServicePolicyNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewDetailServicePolicyOK creates a DetailServicePolicyOK with default headers values
func NewDetailServicePolicyOK() *DetailServicePolicyOK {
	return &DetailServicePolicyOK{}
}

/*DetailServicePolicyOK handles this case with default header values.

A signle service policy
*/
type DetailServicePolicyOK struct {
	Payload *rest_model.DetailServicePolicyEnvelop
}

func (o *DetailServicePolicyOK) Error() string {
	return fmt.Sprintf("[GET /service-policies/{id}][%d] detailServicePolicyOK  %+v", 200, o.Payload)
}

func (o *DetailServicePolicyOK) GetPayload() *rest_model.DetailServicePolicyEnvelop {
	return o.Payload
}

func (o *DetailServicePolicyOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.DetailServicePolicyEnvelop)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDetailServicePolicyUnauthorized creates a DetailServicePolicyUnauthorized with default headers values
func NewDetailServicePolicyUnauthorized() *DetailServicePolicyUnauthorized {
	return &DetailServicePolicyUnauthorized{}
}

/*DetailServicePolicyUnauthorized handles this case with default header values.

The currently supplied session does not have the correct access rights to request this resource
*/
type DetailServicePolicyUnauthorized struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *DetailServicePolicyUnauthorized) Error() string {
	return fmt.Sprintf("[GET /service-policies/{id}][%d] detailServicePolicyUnauthorized  %+v", 401, o.Payload)
}

func (o *DetailServicePolicyUnauthorized) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *DetailServicePolicyUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDetailServicePolicyNotFound creates a DetailServicePolicyNotFound with default headers values
func NewDetailServicePolicyNotFound() *DetailServicePolicyNotFound {
	return &DetailServicePolicyNotFound{}
}

/*DetailServicePolicyNotFound handles this case with default header values.

The requested resource does not exist
*/
type DetailServicePolicyNotFound struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *DetailServicePolicyNotFound) Error() string {
	return fmt.Sprintf("[GET /service-policies/{id}][%d] detailServicePolicyNotFound  %+v", 404, o.Payload)
}

func (o *DetailServicePolicyNotFound) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *DetailServicePolicyNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
