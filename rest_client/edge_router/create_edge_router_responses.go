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

package edge_router

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/netfoundry/ziti-edge/rest_model"
)

// CreateEdgeRouterReader is a Reader for the CreateEdgeRouter structure.
type CreateEdgeRouterReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateEdgeRouterReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCreateEdgeRouterOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateEdgeRouterBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateEdgeRouterUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewCreateEdgeRouterOK creates a CreateEdgeRouterOK with default headers values
func NewCreateEdgeRouterOK() *CreateEdgeRouterOK {
	return &CreateEdgeRouterOK{}
}

/*CreateEdgeRouterOK handles this case with default header values.

The create request was successful and the resource has been added at the following location
*/
type CreateEdgeRouterOK struct {
	Payload *rest_model.Create
}

func (o *CreateEdgeRouterOK) Error() string {
	return fmt.Sprintf("[POST /edge-routers][%d] createEdgeRouterOK  %+v", 200, o.Payload)
}

func (o *CreateEdgeRouterOK) GetPayload() *rest_model.Create {
	return o.Payload
}

func (o *CreateEdgeRouterOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.Create)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateEdgeRouterBadRequest creates a CreateEdgeRouterBadRequest with default headers values
func NewCreateEdgeRouterBadRequest() *CreateEdgeRouterBadRequest {
	return &CreateEdgeRouterBadRequest{}
}

/*CreateEdgeRouterBadRequest handles this case with default header values.

The supplied request contains invalid fields or could not be parsed (json and non-json bodies). The error's code, message, and cause fields can be inspected for further information
*/
type CreateEdgeRouterBadRequest struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *CreateEdgeRouterBadRequest) Error() string {
	return fmt.Sprintf("[POST /edge-routers][%d] createEdgeRouterBadRequest  %+v", 400, o.Payload)
}

func (o *CreateEdgeRouterBadRequest) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *CreateEdgeRouterBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateEdgeRouterUnauthorized creates a CreateEdgeRouterUnauthorized with default headers values
func NewCreateEdgeRouterUnauthorized() *CreateEdgeRouterUnauthorized {
	return &CreateEdgeRouterUnauthorized{}
}

/*CreateEdgeRouterUnauthorized handles this case with default header values.

The currently supplied session does not have the correct access rights to request this resource
*/
type CreateEdgeRouterUnauthorized struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *CreateEdgeRouterUnauthorized) Error() string {
	return fmt.Sprintf("[POST /edge-routers][%d] createEdgeRouterUnauthorized  %+v", 401, o.Payload)
}

func (o *CreateEdgeRouterUnauthorized) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *CreateEdgeRouterUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
