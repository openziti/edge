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

package rest_model

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// PostureQuery posture query
//
// swagger:model postureQuery
type PostureQuery struct {
	BaseEntity

	// is passing
	// Required: true
	IsPassing *bool `json:"isPassing"`

	// process
	Process *PostureQueryProcess `json:"process,omitempty"`

	// query type
	// Required: true
	QueryType PostureCheckType `json:"queryType"`
}

// UnmarshalJSON unmarshals this object from a JSON structure
func (m *PostureQuery) UnmarshalJSON(raw []byte) error {
	// AO0
	var aO0 BaseEntity
	if err := swag.ReadJSON(raw, &aO0); err != nil {
		return err
	}
	m.BaseEntity = aO0

	// AO1
	var dataAO1 struct {
		IsPassing *bool `json:"isPassing"`

		Process *PostureQueryProcess `json:"process,omitempty"`

		QueryType PostureCheckType `json:"queryType"`
	}
	if err := swag.ReadJSON(raw, &dataAO1); err != nil {
		return err
	}

	m.IsPassing = dataAO1.IsPassing

	m.Process = dataAO1.Process

	m.QueryType = dataAO1.QueryType

	return nil
}

// MarshalJSON marshals this object to a JSON structure
func (m PostureQuery) MarshalJSON() ([]byte, error) {
	_parts := make([][]byte, 0, 2)

	aO0, err := swag.WriteJSON(m.BaseEntity)
	if err != nil {
		return nil, err
	}
	_parts = append(_parts, aO0)
	var dataAO1 struct {
		IsPassing *bool `json:"isPassing"`

		Process *PostureQueryProcess `json:"process,omitempty"`

		QueryType PostureCheckType `json:"queryType"`
	}

	dataAO1.IsPassing = m.IsPassing

	dataAO1.Process = m.Process

	dataAO1.QueryType = m.QueryType

	jsonDataAO1, errAO1 := swag.WriteJSON(dataAO1)
	if errAO1 != nil {
		return nil, errAO1
	}
	_parts = append(_parts, jsonDataAO1)
	return swag.ConcatJSON(_parts...), nil
}

// Validate validates this posture query
func (m *PostureQuery) Validate(formats strfmt.Registry) error {
	var res []error

	// validation for a type composition with BaseEntity
	if err := m.BaseEntity.Validate(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateIsPassing(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateProcess(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateQueryType(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *PostureQuery) validateIsPassing(formats strfmt.Registry) error {

	if err := validate.Required("isPassing", "body", m.IsPassing); err != nil {
		return err
	}

	return nil
}

func (m *PostureQuery) validateProcess(formats strfmt.Registry) error {

	if swag.IsZero(m.Process) { // not required
		return nil
	}

	if m.Process != nil {
		if err := m.Process.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("process")
			}
			return err
		}
	}

	return nil
}

func (m *PostureQuery) validateQueryType(formats strfmt.Registry) error {

	if err := m.QueryType.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("queryType")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *PostureQuery) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PostureQuery) UnmarshalBinary(b []byte) error {
	var res PostureQuery
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
