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
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// ExternalJWTSignerDetail A External JWT Signer resource
//
// swagger:model externalJwtSignerDetail
type ExternalJWTSignerDetail struct {
	BaseEntity

	// cert pem
	// Required: true
	CertPem *string `json:"certPem"`

	// claims property
	// Required: true
	ClaimsProperty *string `json:"claimsProperty"`

	// common name
	// Required: true
	CommonName *string `json:"commonName"`

	// enabled
	// Required: true
	Enabled *bool `json:"enabled"`

	// external auth Url
	// Required: true
	ExternalAuthURL *string `json:"externalAuthUrl"`

	// fingerprint
	// Required: true
	Fingerprint *string `json:"fingerprint"`

	// name
	// Example: MyApps Signer
	// Required: true
	Name *string `json:"name"`

	// not after
	// Required: true
	// Format: date-time
	NotAfter *strfmt.DateTime `json:"notAfter"`

	// not before
	// Required: true
	// Format: date-time
	NotBefore *strfmt.DateTime `json:"notBefore"`

	// use external Id
	// Required: true
	UseExternalID *bool `json:"useExternalId"`
}

// UnmarshalJSON unmarshals this object from a JSON structure
func (m *ExternalJWTSignerDetail) UnmarshalJSON(raw []byte) error {
	// AO0
	var aO0 BaseEntity
	if err := swag.ReadJSON(raw, &aO0); err != nil {
		return err
	}
	m.BaseEntity = aO0

	// AO1
	var dataAO1 struct {
		CertPem *string `json:"certPem"`

		ClaimsProperty *string `json:"claimsProperty"`

		CommonName *string `json:"commonName"`

		Enabled *bool `json:"enabled"`

		ExternalAuthURL *string `json:"externalAuthUrl"`

		Fingerprint *string `json:"fingerprint"`

		Name *string `json:"name"`

		NotAfter *strfmt.DateTime `json:"notAfter"`

		NotBefore *strfmt.DateTime `json:"notBefore"`

		UseExternalID *bool `json:"useExternalId"`
	}
	if err := swag.ReadJSON(raw, &dataAO1); err != nil {
		return err
	}

	m.CertPem = dataAO1.CertPem

	m.ClaimsProperty = dataAO1.ClaimsProperty

	m.CommonName = dataAO1.CommonName

	m.Enabled = dataAO1.Enabled

	m.ExternalAuthURL = dataAO1.ExternalAuthURL

	m.Fingerprint = dataAO1.Fingerprint

	m.Name = dataAO1.Name

	m.NotAfter = dataAO1.NotAfter

	m.NotBefore = dataAO1.NotBefore

	m.UseExternalID = dataAO1.UseExternalID

	return nil
}

// MarshalJSON marshals this object to a JSON structure
func (m ExternalJWTSignerDetail) MarshalJSON() ([]byte, error) {
	_parts := make([][]byte, 0, 2)

	aO0, err := swag.WriteJSON(m.BaseEntity)
	if err != nil {
		return nil, err
	}
	_parts = append(_parts, aO0)
	var dataAO1 struct {
		CertPem *string `json:"certPem"`

		ClaimsProperty *string `json:"claimsProperty"`

		CommonName *string `json:"commonName"`

		Enabled *bool `json:"enabled"`

		ExternalAuthURL *string `json:"externalAuthUrl"`

		Fingerprint *string `json:"fingerprint"`

		Name *string `json:"name"`

		NotAfter *strfmt.DateTime `json:"notAfter"`

		NotBefore *strfmt.DateTime `json:"notBefore"`

		UseExternalID *bool `json:"useExternalId"`
	}

	dataAO1.CertPem = m.CertPem

	dataAO1.ClaimsProperty = m.ClaimsProperty

	dataAO1.CommonName = m.CommonName

	dataAO1.Enabled = m.Enabled

	dataAO1.ExternalAuthURL = m.ExternalAuthURL

	dataAO1.Fingerprint = m.Fingerprint

	dataAO1.Name = m.Name

	dataAO1.NotAfter = m.NotAfter

	dataAO1.NotBefore = m.NotBefore

	dataAO1.UseExternalID = m.UseExternalID

	jsonDataAO1, errAO1 := swag.WriteJSON(dataAO1)
	if errAO1 != nil {
		return nil, errAO1
	}
	_parts = append(_parts, jsonDataAO1)
	return swag.ConcatJSON(_parts...), nil
}

// Validate validates this external Jwt signer detail
func (m *ExternalJWTSignerDetail) Validate(formats strfmt.Registry) error {
	var res []error

	// validation for a type composition with BaseEntity
	if err := m.BaseEntity.Validate(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCertPem(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateClaimsProperty(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCommonName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEnabled(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateExternalAuthURL(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateFingerprint(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateNotAfter(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateNotBefore(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUseExternalID(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ExternalJWTSignerDetail) validateCertPem(formats strfmt.Registry) error {

	if err := validate.Required("certPem", "body", m.CertPem); err != nil {
		return err
	}

	return nil
}

func (m *ExternalJWTSignerDetail) validateClaimsProperty(formats strfmt.Registry) error {

	if err := validate.Required("claimsProperty", "body", m.ClaimsProperty); err != nil {
		return err
	}

	return nil
}

func (m *ExternalJWTSignerDetail) validateCommonName(formats strfmt.Registry) error {

	if err := validate.Required("commonName", "body", m.CommonName); err != nil {
		return err
	}

	return nil
}

func (m *ExternalJWTSignerDetail) validateEnabled(formats strfmt.Registry) error {

	if err := validate.Required("enabled", "body", m.Enabled); err != nil {
		return err
	}

	return nil
}

func (m *ExternalJWTSignerDetail) validateExternalAuthURL(formats strfmt.Registry) error {

	if err := validate.Required("externalAuthUrl", "body", m.ExternalAuthURL); err != nil {
		return err
	}

	return nil
}

func (m *ExternalJWTSignerDetail) validateFingerprint(formats strfmt.Registry) error {

	if err := validate.Required("fingerprint", "body", m.Fingerprint); err != nil {
		return err
	}

	return nil
}

func (m *ExternalJWTSignerDetail) validateName(formats strfmt.Registry) error {

	if err := validate.Required("name", "body", m.Name); err != nil {
		return err
	}

	return nil
}

func (m *ExternalJWTSignerDetail) validateNotAfter(formats strfmt.Registry) error {

	if err := validate.Required("notAfter", "body", m.NotAfter); err != nil {
		return err
	}

	if err := validate.FormatOf("notAfter", "body", "date-time", m.NotAfter.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *ExternalJWTSignerDetail) validateNotBefore(formats strfmt.Registry) error {

	if err := validate.Required("notBefore", "body", m.NotBefore); err != nil {
		return err
	}

	if err := validate.FormatOf("notBefore", "body", "date-time", m.NotBefore.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *ExternalJWTSignerDetail) validateUseExternalID(formats strfmt.Registry) error {

	if err := validate.Required("useExternalId", "body", m.UseExternalID); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this external Jwt signer detail based on the context it is used
func (m *ExternalJWTSignerDetail) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	// validation for a type composition with BaseEntity
	if err := m.BaseEntity.ContextValidate(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// MarshalBinary interface implementation
func (m *ExternalJWTSignerDetail) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ExternalJWTSignerDetail) UnmarshalBinary(b []byte) error {
	var res ExternalJWTSignerDetail
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
