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

package config

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

// NewPatchConfigParams creates a new PatchConfigParams object
// with the default values initialized.
func NewPatchConfigParams() *PatchConfigParams {
	var ()
	return &PatchConfigParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewPatchConfigParamsWithTimeout creates a new PatchConfigParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewPatchConfigParamsWithTimeout(timeout time.Duration) *PatchConfigParams {
	var ()
	return &PatchConfigParams{

		timeout: timeout,
	}
}

// NewPatchConfigParamsWithContext creates a new PatchConfigParams object
// with the default values initialized, and the ability to set a context for a request
func NewPatchConfigParamsWithContext(ctx context.Context) *PatchConfigParams {
	var ()
	return &PatchConfigParams{

		Context: ctx,
	}
}

// NewPatchConfigParamsWithHTTPClient creates a new PatchConfigParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewPatchConfigParamsWithHTTPClient(client *http.Client) *PatchConfigParams {
	var ()
	return &PatchConfigParams{
		HTTPClient: client,
	}
}

/*PatchConfigParams contains all the parameters to send to the API endpoint
for the patch config operation typically these are written to a http.Request
*/
type PatchConfigParams struct {

	/*Body
	  A config patch object

	*/
	Body *models.ConfigPatch
	/*ID
	  The id of the requested resource

	*/
	ID strfmt.UUID

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the patch config params
func (o *PatchConfigParams) WithTimeout(timeout time.Duration) *PatchConfigParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the patch config params
func (o *PatchConfigParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the patch config params
func (o *PatchConfigParams) WithContext(ctx context.Context) *PatchConfigParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the patch config params
func (o *PatchConfigParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the patch config params
func (o *PatchConfigParams) WithHTTPClient(client *http.Client) *PatchConfigParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the patch config params
func (o *PatchConfigParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the patch config params
func (o *PatchConfigParams) WithBody(body *models.ConfigPatch) *PatchConfigParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the patch config params
func (o *PatchConfigParams) SetBody(body *models.ConfigPatch) {
	o.Body = body
}

// WithID adds the id to the patch config params
func (o *PatchConfigParams) WithID(id strfmt.UUID) *PatchConfigParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the patch config params
func (o *PatchConfigParams) SetID(id strfmt.UUID) {
	o.ID = id
}

// WriteToRequest writes these params to a swagger request
func (o *PatchConfigParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Body != nil {
		if err := r.SetBodyParam(o.Body); err != nil {
			return err
		}
	}

	// path param id
	if err := r.SetPathParam("id", o.ID.String()); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
