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
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"

	"github.com/netfoundry/ziti-edge/rest_model"
)

// NewCreateServicePolicyParams creates a new CreateServicePolicyParams object
// with the default values initialized.
func NewCreateServicePolicyParams() *CreateServicePolicyParams {
	var ()
	return &CreateServicePolicyParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewCreateServicePolicyParamsWithTimeout creates a new CreateServicePolicyParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewCreateServicePolicyParamsWithTimeout(timeout time.Duration) *CreateServicePolicyParams {
	var ()
	return &CreateServicePolicyParams{

		timeout: timeout,
	}
}

// NewCreateServicePolicyParamsWithContext creates a new CreateServicePolicyParams object
// with the default values initialized, and the ability to set a context for a request
func NewCreateServicePolicyParamsWithContext(ctx context.Context) *CreateServicePolicyParams {
	var ()
	return &CreateServicePolicyParams{

		Context: ctx,
	}
}

// NewCreateServicePolicyParamsWithHTTPClient creates a new CreateServicePolicyParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewCreateServicePolicyParamsWithHTTPClient(client *http.Client) *CreateServicePolicyParams {
	var ()
	return &CreateServicePolicyParams{
		HTTPClient: client,
	}
}

/*CreateServicePolicyParams contains all the parameters to send to the API endpoint
for the create service policy operation typically these are written to a http.Request
*/
type CreateServicePolicyParams struct {

	/*Body
	  A service policy to create

	*/
	Body *rest_model.ServicePolicyCreate

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the create service policy params
func (o *CreateServicePolicyParams) WithTimeout(timeout time.Duration) *CreateServicePolicyParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the create service policy params
func (o *CreateServicePolicyParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the create service policy params
func (o *CreateServicePolicyParams) WithContext(ctx context.Context) *CreateServicePolicyParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the create service policy params
func (o *CreateServicePolicyParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the create service policy params
func (o *CreateServicePolicyParams) WithHTTPClient(client *http.Client) *CreateServicePolicyParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the create service policy params
func (o *CreateServicePolicyParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the create service policy params
func (o *CreateServicePolicyParams) WithBody(body *rest_model.ServicePolicyCreate) *CreateServicePolicyParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the create service policy params
func (o *CreateServicePolicyParams) SetBody(body *rest_model.ServicePolicyCreate) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *CreateServicePolicyParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Body != nil {
		if err := r.SetBodyParam(o.Body); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
