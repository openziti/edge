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

package service_edge_router_policy

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/netfoundry/ziti-edge/models"
)

// CreateServiceEdgeRouterPolicyReader is a Reader for the CreateServiceEdgeRouterPolicy structure.
type CreateServiceEdgeRouterPolicyReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateServiceEdgeRouterPolicyReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCreateServiceEdgeRouterPolicyOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewCreateServiceEdgeRouterPolicyBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewCreateServiceEdgeRouterPolicyUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewCreateServiceEdgeRouterPolicyOK creates a CreateServiceEdgeRouterPolicyOK with default headers values
func NewCreateServiceEdgeRouterPolicyOK() *CreateServiceEdgeRouterPolicyOK {
	return &CreateServiceEdgeRouterPolicyOK{}
}

/*CreateServiceEdgeRouterPolicyOK handles this case with default header values.

The create request was successful and the resource has been added at the following location
*/
type CreateServiceEdgeRouterPolicyOK struct {
	Payload *models.Create
}

func (o *CreateServiceEdgeRouterPolicyOK) Error() string {
	return fmt.Sprintf("[POST /service-edge-router-policies][%d] createServiceEdgeRouterPolicyOK  %+v", 200, o.Payload)
}

func (o *CreateServiceEdgeRouterPolicyOK) GetPayload() *models.Create {
	return o.Payload
}

func (o *CreateServiceEdgeRouterPolicyOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Create)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateServiceEdgeRouterPolicyBadRequest creates a CreateServiceEdgeRouterPolicyBadRequest with default headers values
func NewCreateServiceEdgeRouterPolicyBadRequest() *CreateServiceEdgeRouterPolicyBadRequest {
	return &CreateServiceEdgeRouterPolicyBadRequest{}
}

/*CreateServiceEdgeRouterPolicyBadRequest handles this case with default header values.

The supplied request contains invalid fields or could not be parsed (json and non-json bodies). The error's code, message, and cause fields can be inspected for further information
*/
type CreateServiceEdgeRouterPolicyBadRequest struct {
	Payload *models.APIErrorEnvelope
}

func (o *CreateServiceEdgeRouterPolicyBadRequest) Error() string {
	return fmt.Sprintf("[POST /service-edge-router-policies][%d] createServiceEdgeRouterPolicyBadRequest  %+v", 400, o.Payload)
}

func (o *CreateServiceEdgeRouterPolicyBadRequest) GetPayload() *models.APIErrorEnvelope {
	return o.Payload
}

func (o *CreateServiceEdgeRouterPolicyBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCreateServiceEdgeRouterPolicyUnauthorized creates a CreateServiceEdgeRouterPolicyUnauthorized with default headers values
func NewCreateServiceEdgeRouterPolicyUnauthorized() *CreateServiceEdgeRouterPolicyUnauthorized {
	return &CreateServiceEdgeRouterPolicyUnauthorized{}
}

/*CreateServiceEdgeRouterPolicyUnauthorized handles this case with default header values.

The currently supplied session does not have the correct access rights to request this resource
*/
type CreateServiceEdgeRouterPolicyUnauthorized struct {
	Payload *models.APIErrorEnvelope
}

func (o *CreateServiceEdgeRouterPolicyUnauthorized) Error() string {
	return fmt.Sprintf("[POST /service-edge-router-policies][%d] createServiceEdgeRouterPolicyUnauthorized  %+v", 401, o.Payload)
}

func (o *CreateServiceEdgeRouterPolicyUnauthorized) GetPayload() *models.APIErrorEnvelope {
	return o.Payload
}

func (o *CreateServiceEdgeRouterPolicyUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
