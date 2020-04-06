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

package enrollment

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/netfoundry/ziti-edge/rest_model"
)

// DetailEnrollmentReader is a Reader for the DetailEnrollment structure.
type DetailEnrollmentReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DetailEnrollmentReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDetailEnrollmentOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewDetailEnrollmentUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDetailEnrollmentNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewDetailEnrollmentOK creates a DetailEnrollmentOK with default headers values
func NewDetailEnrollmentOK() *DetailEnrollmentOK {
	return &DetailEnrollmentOK{}
}

/*DetailEnrollmentOK handles this case with default header values.

A singular enrollment resource
*/
type DetailEnrollmentOK struct {
	Payload *rest_model.DetailEnrollmentEnvelope
}

func (o *DetailEnrollmentOK) Error() string {
	return fmt.Sprintf("[GET /enrollments/{id}][%d] detailEnrollmentOK  %+v", 200, o.Payload)
}

func (o *DetailEnrollmentOK) GetPayload() *rest_model.DetailEnrollmentEnvelope {
	return o.Payload
}

func (o *DetailEnrollmentOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.DetailEnrollmentEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDetailEnrollmentUnauthorized creates a DetailEnrollmentUnauthorized with default headers values
func NewDetailEnrollmentUnauthorized() *DetailEnrollmentUnauthorized {
	return &DetailEnrollmentUnauthorized{}
}

/*DetailEnrollmentUnauthorized handles this case with default header values.

The currently supplied session does not have the correct access rights to request this resource
*/
type DetailEnrollmentUnauthorized struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *DetailEnrollmentUnauthorized) Error() string {
	return fmt.Sprintf("[GET /enrollments/{id}][%d] detailEnrollmentUnauthorized  %+v", 401, o.Payload)
}

func (o *DetailEnrollmentUnauthorized) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *DetailEnrollmentUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDetailEnrollmentNotFound creates a DetailEnrollmentNotFound with default headers values
func NewDetailEnrollmentNotFound() *DetailEnrollmentNotFound {
	return &DetailEnrollmentNotFound{}
}

/*DetailEnrollmentNotFound handles this case with default header values.

The requested resource does not exist
*/
type DetailEnrollmentNotFound struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *DetailEnrollmentNotFound) Error() string {
	return fmt.Sprintf("[GET /enrollments/{id}][%d] detailEnrollmentNotFound  %+v", 404, o.Payload)
}

func (o *DetailEnrollmentNotFound) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *DetailEnrollmentNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
