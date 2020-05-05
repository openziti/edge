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

package current_api_session

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/openziti/edge/rest_model"
)

// DetailCurrentIdentityAuthenticatorReader is a Reader for the DetailCurrentIdentityAuthenticator structure.
type DetailCurrentIdentityAuthenticatorReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DetailCurrentIdentityAuthenticatorReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDetailCurrentIdentityAuthenticatorOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewDetailCurrentIdentityAuthenticatorUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDetailCurrentIdentityAuthenticatorNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewDetailCurrentIdentityAuthenticatorOK creates a DetailCurrentIdentityAuthenticatorOK with default headers values
func NewDetailCurrentIdentityAuthenticatorOK() *DetailCurrentIdentityAuthenticatorOK {
	return &DetailCurrentIdentityAuthenticatorOK{}
}

/*DetailCurrentIdentityAuthenticatorOK handles this case with default header values.

A singular authenticator resource
*/
type DetailCurrentIdentityAuthenticatorOK struct {
	Payload *rest_model.DetailAuthenticatorEnvelope
}

func (o *DetailCurrentIdentityAuthenticatorOK) Error() string {
	return fmt.Sprintf("[GET /current-identity/authenticators/{id}][%d] detailCurrentIdentityAuthenticatorOK  %+v", 200, o.Payload)
}

func (o *DetailCurrentIdentityAuthenticatorOK) GetPayload() *rest_model.DetailAuthenticatorEnvelope {
	return o.Payload
}

func (o *DetailCurrentIdentityAuthenticatorOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.DetailAuthenticatorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDetailCurrentIdentityAuthenticatorUnauthorized creates a DetailCurrentIdentityAuthenticatorUnauthorized with default headers values
func NewDetailCurrentIdentityAuthenticatorUnauthorized() *DetailCurrentIdentityAuthenticatorUnauthorized {
	return &DetailCurrentIdentityAuthenticatorUnauthorized{}
}

/*DetailCurrentIdentityAuthenticatorUnauthorized handles this case with default header values.

The currently supplied session does not have the correct access rights to request this resource
*/
type DetailCurrentIdentityAuthenticatorUnauthorized struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *DetailCurrentIdentityAuthenticatorUnauthorized) Error() string {
	return fmt.Sprintf("[GET /current-identity/authenticators/{id}][%d] detailCurrentIdentityAuthenticatorUnauthorized  %+v", 401, o.Payload)
}

func (o *DetailCurrentIdentityAuthenticatorUnauthorized) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *DetailCurrentIdentityAuthenticatorUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDetailCurrentIdentityAuthenticatorNotFound creates a DetailCurrentIdentityAuthenticatorNotFound with default headers values
func NewDetailCurrentIdentityAuthenticatorNotFound() *DetailCurrentIdentityAuthenticatorNotFound {
	return &DetailCurrentIdentityAuthenticatorNotFound{}
}

/*DetailCurrentIdentityAuthenticatorNotFound handles this case with default header values.

The requested resource does not exist
*/
type DetailCurrentIdentityAuthenticatorNotFound struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *DetailCurrentIdentityAuthenticatorNotFound) Error() string {
	return fmt.Sprintf("[GET /current-identity/authenticators/{id}][%d] detailCurrentIdentityAuthenticatorNotFound  %+v", 404, o.Payload)
}

func (o *DetailCurrentIdentityAuthenticatorNotFound) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *DetailCurrentIdentityAuthenticatorNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
