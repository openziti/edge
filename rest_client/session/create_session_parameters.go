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

package session

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

	"github.com/netfoundry/ziti-edge/models"
)

// NewCreateSessionParams creates a new CreateSessionParams object
// with the default values initialized.
func NewCreateSessionParams() *CreateSessionParams {
	var ()
	return &CreateSessionParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewCreateSessionParamsWithTimeout creates a new CreateSessionParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewCreateSessionParamsWithTimeout(timeout time.Duration) *CreateSessionParams {
	var ()
	return &CreateSessionParams{

		timeout: timeout,
	}
}

// NewCreateSessionParamsWithContext creates a new CreateSessionParams object
// with the default values initialized, and the ability to set a context for a request
func NewCreateSessionParamsWithContext(ctx context.Context) *CreateSessionParams {
	var ()
	return &CreateSessionParams{

		Context: ctx,
	}
}

// NewCreateSessionParamsWithHTTPClient creates a new CreateSessionParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewCreateSessionParamsWithHTTPClient(client *http.Client) *CreateSessionParams {
	var ()
	return &CreateSessionParams{
		HTTPClient: client,
	}
}

/*CreateSessionParams contains all the parameters to send to the API endpoint
for the create session operation typically these are written to a http.Request
*/
type CreateSessionParams struct {

	/*Body
	  A session to create

	*/
	Body *models.SessionCreate

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the create session params
func (o *CreateSessionParams) WithTimeout(timeout time.Duration) *CreateSessionParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the create session params
func (o *CreateSessionParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the create session params
func (o *CreateSessionParams) WithContext(ctx context.Context) *CreateSessionParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the create session params
func (o *CreateSessionParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the create session params
func (o *CreateSessionParams) WithHTTPClient(client *http.Client) *CreateSessionParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the create session params
func (o *CreateSessionParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the create session params
func (o *CreateSessionParams) WithBody(body *models.SessionCreate) *CreateSessionParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the create session params
func (o *CreateSessionParams) SetBody(body *models.SessionCreate) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *CreateSessionParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
