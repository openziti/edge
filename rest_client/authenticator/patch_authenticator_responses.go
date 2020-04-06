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
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/netfoundry/ziti-edge/rest_model"
)

// PatchAuthenticatorReader is a Reader for the PatchAuthenticator structure.
type PatchAuthenticatorReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PatchAuthenticatorReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPatchAuthenticatorOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewPatchAuthenticatorBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewPatchAuthenticatorUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewPatchAuthenticatorNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewPatchAuthenticatorOK creates a PatchAuthenticatorOK with default headers values
func NewPatchAuthenticatorOK() *PatchAuthenticatorOK {
	return &PatchAuthenticatorOK{}
}

/*PatchAuthenticatorOK handles this case with default header values.

The patch request was successful and the resource has been altered
*/
type PatchAuthenticatorOK struct {
	Payload *rest_model.Empty
}

func (o *PatchAuthenticatorOK) Error() string {
	return fmt.Sprintf("[PATCH /authenticators/{id}][%d] patchAuthenticatorOK  %+v", 200, o.Payload)
}

func (o *PatchAuthenticatorOK) GetPayload() *rest_model.Empty {
	return o.Payload
}

func (o *PatchAuthenticatorOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.Empty)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchAuthenticatorBadRequest creates a PatchAuthenticatorBadRequest with default headers values
func NewPatchAuthenticatorBadRequest() *PatchAuthenticatorBadRequest {
	return &PatchAuthenticatorBadRequest{}
}

/*PatchAuthenticatorBadRequest handles this case with default header values.

The supplied request contains invalid fields or could not be parsed (json and non-json bodies). The error's code, message, and cause fields can be inspected for further information
*/
type PatchAuthenticatorBadRequest struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *PatchAuthenticatorBadRequest) Error() string {
	return fmt.Sprintf("[PATCH /authenticators/{id}][%d] patchAuthenticatorBadRequest  %+v", 400, o.Payload)
}

func (o *PatchAuthenticatorBadRequest) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *PatchAuthenticatorBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchAuthenticatorUnauthorized creates a PatchAuthenticatorUnauthorized with default headers values
func NewPatchAuthenticatorUnauthorized() *PatchAuthenticatorUnauthorized {
	return &PatchAuthenticatorUnauthorized{}
}

/*PatchAuthenticatorUnauthorized handles this case with default header values.

The currently supplied session does not have the correct access rights to request this resource
*/
type PatchAuthenticatorUnauthorized struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *PatchAuthenticatorUnauthorized) Error() string {
	return fmt.Sprintf("[PATCH /authenticators/{id}][%d] patchAuthenticatorUnauthorized  %+v", 401, o.Payload)
}

func (o *PatchAuthenticatorUnauthorized) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *PatchAuthenticatorUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPatchAuthenticatorNotFound creates a PatchAuthenticatorNotFound with default headers values
func NewPatchAuthenticatorNotFound() *PatchAuthenticatorNotFound {
	return &PatchAuthenticatorNotFound{}
}

/*PatchAuthenticatorNotFound handles this case with default header values.

The requested resource does not exist
*/
type PatchAuthenticatorNotFound struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *PatchAuthenticatorNotFound) Error() string {
	return fmt.Sprintf("[PATCH /authenticators/{id}][%d] patchAuthenticatorNotFound  %+v", 404, o.Payload)
}

func (o *PatchAuthenticatorNotFound) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *PatchAuthenticatorNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
