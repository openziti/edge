/*
	Copyright NetFoundry, Inc.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package model

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/edge/controller/apierror"
	"github.com/openziti/edge/controller/persistence"
	"github.com/openziti/edge/internal/cert"
	"github.com/openziti/foundation/util/errorz"
	nfpem "github.com/openziti/foundation/util/pem"
	cmap "github.com/orcaman/concurrent-map"
	"github.com/sirupsen/logrus"
	"net/http"
	"time"
)

const (
	ClientCertHeader       = "X-Client-CertPem"
	EdgeRouterProxyRequest = "X-Edge-Router-Proxy-Request"
)

var _ AuthProcessor = &AuthModuleCert{}

type AuthModuleCert struct {
	env                  Env
	method               string
	fingerprintGenerator cert.FingerprintGenerator
	caChain              []byte
	staticCaCerts        []*x509.Certificate
	dynamicCaCache       cmap.ConcurrentMap //map[string][]*x509.Certificate
}

func NewAuthModuleCert(env Env, caChain []byte) *AuthModuleCert {
	handler := &AuthModuleCert{
		env:                  env,
		method:               persistence.MethodAuthenticatorCert,
		fingerprintGenerator: cert.NewFingerprintGenerator(),
		staticCaCerts:        nfpem.PemBytesToCertificates(caChain),
		dynamicCaCache:       cmap.New(),
	}

	return handler
}

func (module *AuthModuleCert) CanHandle(method string) bool {
	return method == module.method
}

func (module *AuthModuleCert) Process(context AuthContext) (string, string, string, error) {
	fingerprints, err := module.GetFingerprints(context)

	if err != nil {
		return "", "", "", err
	}

	for fingerprint, authCert := range fingerprints {
		logger := pfxlog.Logger().WithField("authMethod", module.method)
		authenticator, _ := module.env.GetHandlers().Authenticator.ReadByFingerprint(fingerprint)

		if authenticator != nil {
			identityId, externalId, authenticatorId, err := module.handleNonSPIFFECert(logger, authenticator, authCert)

			if err == nil {
				return identityId, externalId, authenticatorId, nil
			}
		} else if spiffeId, ok := module.getSPIFFEId(authCert); ok {
			identityId, externalId, authenticatorId, err := module.handleSPIFFECert(logger, spiffeId, authCert)

			if err == nil {
				return identityId, externalId, authenticatorId, nil
			}
		}
	}

	return "", "", "", apierror.NewInvalidAuth()
}

func (module *AuthModuleCert) handleSPIFFECert(logger *logrus.Entry, spiffeId string, authCert *x509.Certificate) (string, string, string, error) {
	identity, err := module.env.GetHandlers().Identity.ReadByExternalId(spiffeId)

	if err != nil {
		return "", "", "", err
	}

	authPolicy, err := module.env.GetHandlers().AuthPolicy.Read(identity.AuthPolicyId)

	if err != nil {
		return "", "", "", err
	}

	if identity == nil {
		return "", "", "", apierror.NewInvalidAuth()
	}

	if authPolicy.Primary.Cert.AllowExpiredCerts {
		authCert.NotBefore = time.Now().Add(-1 * time.Hour)
		authCert.NotAfter = time.Now().Add(1 * time.Hour)
	}

	opts := x509.VerifyOptions{
		Roots:         module.getRootPool(),
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if _, err := authCert.Verify(opts); err == nil {
		return identity.Id, spiffeId, "", nil
	} else {
		logger.Tracef("error verifying client certificate [%s] did not verify: %v", spiffeId, err)
	}

	return "", "", "", apierror.NewInvalidAuth()
}

func (module *AuthModuleCert) handleNonSPIFFECert(logger *logrus.Entry, authenticator *Authenticator, cert *x509.Certificate) (string, string, string, error) {
	fingerprint := module.env.GetFingerprintGenerator().FromCert(cert)

	logger = logger.
		WithField("authenticatorId", authenticator.Id).
		WithField("identityId", authenticator.IdentityId)

	authPolicy, identity, err := getAuthPolicyByIdentityId(module.env, module.method, authenticator.Id, authenticator.IdentityId)

	if err != nil {
		logger.WithError(err).Error("could not lookup identity and auth policy for cert authentication")
		return "", "", "", apierror.NewInvalidAuth()
	}

	logger = logger.WithField("authPolicyId", authPolicy.Id)

	if identity.Disabled {
		logger.
			WithField("disabledAt", identity.DisabledAt).
			WithField("disabledUntil", identity.DisabledUntil).
			Error("authentication failed, identity is disabled")
		return "", "", "", apierror.NewInvalidAuth()
	}

	if !authPolicy.Primary.Cert.Allowed {
		logger.Error("invalid certificate authentication, not allowed by auth policy")
		return "", "", "", apierror.NewInvalidAuth()
	}

	if authCert, ok := authenticator.SubType.(*AuthenticatorCert); ok {
		if authCert.Pem == "" {
			certPem := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			})

			authCert.Pem = string(certPem)
			if err = module.env.GetHandlers().Authenticator.Update(authenticator); err != nil {
				logger.WithError(err).Errorf("error during cert auth attempting to update PEM, fingerprint: %s", fingerprint)
			}
		}
	}

	if authPolicy.Primary.Cert.AllowExpiredCerts {
		cert.NotBefore = time.Now().Add(-1 * time.Hour)
		cert.NotAfter = time.Now().Add(1 * time.Hour)
	}

	opts := x509.VerifyOptions{
		Roots:         module.getRootPool(),
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if _, err := cert.Verify(opts); err == nil {
		return authenticator.IdentityId, "", authenticator.Id, nil
	} else {
		logger.Tracef("error verifying client certificate [%s] did not verify: %v", fingerprint, err)
	}

	return "", "", "", apierror.NewInvalidAuth()
}

func (module *AuthModuleCert) getRootPool() *x509.CertPool {
	roots := x509.NewCertPool()

	for _, ca := range module.getCACerts() {
		roots.AddCert(ca)
	}

	return roots
}

func (module *AuthModuleCert) getSPIFFECertPool() *x509.CertPool {
	roots := x509.NewCertPool()

	for _, ca := range module.getCACerts() {
		if _, ok := module.getSPIFFEId(ca); ok {
			roots.AddCert(ca)
		}
	}

	return roots
}

func (module *AuthModuleCert) getCACerts() []*x509.Certificate {
	var result []*x509.Certificate

	for _, caCert := range module.staticCaCerts {
		result = append(result, caCert)
	}

	err := module.env.GetHandlers().Ca.Stream("isAuthEnabled = true and isVerified = true", func(ca *Ca, err error) error {
		if ca == nil && err == nil {
			return nil
		}

		if err != nil {
			//continue on err
			pfxlog.Logger().Errorf("error streaming cas for authentication: %vs", err)
			return nil
		}

		if val, ok := module.dynamicCaCache.Get(ca.Id); ok {
			if caCerts, ok := val.([]*x509.Certificate); ok {
				for _, caCert := range caCerts {
					result = append(result, caCert)
				}
			}
		} else {
			caCerts := nfpem.PemStringToCertificates(ca.CertPem)
			module.dynamicCaCache.Set(ca.Id, caCerts)
			for _, caCert := range caCerts {
				result = append(result, caCert)
			}
		}

		return nil
	})

	if err != nil {
		return nil
	}

	return result
}

func (module *AuthModuleCert) isEdgeRouter(certs []*x509.Certificate) bool {

	for _, certificate := range certs {
		fingerprint := module.fingerprintGenerator.FromCert(certificate)

		router, err := module.env.GetHandlers().EdgeRouter.ReadOneByFingerprint(fingerprint)

		if router != nil {
			return true
		}

		if err != nil {
			pfxlog.Logger().WithError(err).Errorf("could not read edge router by fingerprint %s", fingerprint)
		}
	}
	return false
}

func (module *AuthModuleCert) GetFingerprints(ctx AuthContext) (cert.Fingerprints, error) {
	peerCerts := ctx.GetCerts()
	authCerts := peerCerts
	proxiedRaw64 := ""

	if proxiedRaw64Interface := ctx.GetHeaders()[ClientCertHeader]; proxiedRaw64Interface != nil {
		proxiedRaw64 = proxiedRaw64Interface.(string)
	}

	isProxied := false

	if proxyHeader := ctx.GetHeaders()[EdgeRouterProxyRequest]; proxyHeader != nil {
		isProxied = true
	}

	if isProxied && proxiedRaw64 == "" {
		return nil, apierror.NewInvalidAuth()
	}

	if proxiedRaw64 != "" {

		isValid := module.isEdgeRouter(ctx.GetCerts())

		if !isValid {
			return nil, apierror.NewInvalidAuth()
		}

		var proxiedRaw []byte
		_, err := base64.StdEncoding.Decode(proxiedRaw, []byte(proxiedRaw64))

		if err != nil {
			return nil, &errorz.ApiError{
				Code:    apierror.CouldNotDecodeProxiedCertCode,
				Message: apierror.CouldNotDecodeProxiedCertMessage,
				Cause:   err,
				Status:  http.StatusBadRequest,
			}
		}

		proxiedCerts, err := x509.ParseCertificates(proxiedRaw)

		if err != nil {
			return nil, &errorz.ApiError{
				Code:    apierror.CouldNotParseX509FromDerCode,
				Message: apierror.CouldNotParseX509FromDerMessage,
				Cause:   err,
				Status:  http.StatusBadRequest,
			}
		}

		authCerts = proxiedCerts
	}

	return module.fingerprintGenerator.FromCerts(authCerts), nil
}

// getSPIFFEId returns the embedded SPIFFE Id and true, or empty string and false if
// no SPIFFE ID is present
func (module *AuthModuleCert) getSPIFFEId(cert *x509.Certificate) (string, bool) {
	for _, uri := range cert.URIs {
		if uri.Scheme == "spiffe:" {
			return uri.String(), true
		}
	}

	return "", false
}

func getAuthPolicyByIdentityId(env Env, authMethod string, authenticatorId string, identityId string) (*AuthPolicy, *Identity, error) {
	logger := pfxlog.Logger().
		WithField("authenticatorId", authenticatorId).
		WithField("identityId", identityId).
		WithField("authMethod", authMethod)
	identity, err := env.GetHandlers().Identity.Read(identityId)

	if err != nil {
		logger.WithError(err).Errorf("encountered error during %s auth when looking up authenticator", authMethod)
		return nil, nil, apierror.NewInvalidAuth()
	}

	logger = logger.WithField("authPolicyId", identity.AuthPolicyId)

	authPolicy, err := env.GetHandlers().AuthPolicy.Read(identity.AuthPolicyId)

	if err != nil {
		logger.WithError(err).Errorf("encountered error during %s auth when looking up auth policy", authMethod)
		return nil, nil, apierror.NewInvalidAuth()
	}

	return authPolicy, identity, nil
}

func getAuthPolicyByExternalId(env Env, authMethod string, authenticatorId string, externalId string) (*AuthPolicy, *Identity, error) {
	logger := pfxlog.Logger().
		WithField("authenticatorId", authenticatorId).
		WithField("externalId", externalId).
		WithField("authMethod", authMethod)
	identity, err := env.GetHandlers().Identity.ReadByExternalId(externalId)

	if err != nil {
		logger.WithError(err).Errorf("encountered error during %s auth when looking up authenticator", authMethod)
		return nil, nil, apierror.NewInvalidAuth()
	}

	logger = logger.WithField("authPolicyId", identity.AuthPolicyId)

	authPolicy, err := env.GetHandlers().AuthPolicy.Read(identity.AuthPolicyId)

	if err != nil {
		logger.WithError(err).Errorf("encountered error during %s auth when looking up auth policy", authMethod)
		return nil, nil, apierror.NewInvalidAuth()
	}

	return authPolicy, identity, nil
}
