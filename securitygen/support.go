package securitygen

import (
	"bytes"
	_ "embed"
	"fmt"
	"text/template"
)

//go:embed templates/apikey.go.tmpl
var apiKeySource string

//go:embed templates/basicauth.go.tmpl
var basicAuthSource string

//go:embed templates/bearerauth.go.tmpl
var bearerAuthSource string

//go:embed templates/oauth2.go.tmpl
var oauth2Source string

type dependency struct {
	field string
	typ   string
}

type schemeSupport struct {
	kind         securityKind
	name         string
	declarations []string
	dependencies []dependency
	imports      map[string]string
	template     *template.Template
}

// This order determines constructor argument order, independently of method order.
var supportedSchemes = []schemeSupport{
	{
		kind: apiKeyKind,
		name: "API key",
		declarations: []string{
			"APIKeyStore", "APIKeyRecord", "APIKeyIdentity", "APIKeyIdentityFromContext",
			"apiKeyContextKey", "ErrInvalidAPIKey", "ErrAPIKeyForbidden", "ErrAPIKeyStoreNotConfigured",
		},
		dependencies: []dependency{{field: "apiKeys", typ: "APIKeyStore"}},
		imports: map[string]string{
			"context": "context", "sha256": "crypto/sha256", "subtle": "crypto/subtle",
			"errors": "errors", "fmt": "fmt", "slices": "slices", "time": "time",
		},
		template: template.Must(template.New("apikey").Parse(apiKeySource)),
	},
	{
		kind: basicAuthKind,
		name: "Basic auth",
		declarations: []string{
			"BasicAuthStore", "BasicAuthRecord", "PasswordVerifier", "BasicAuthIdentity", "BasicAuthIdentityFromContext",
			"basicAuthContextKey", "ErrInvalidBasicAuth", "ErrBasicAuthForbidden", "ErrBasicAuthStoreNotConfigured", "ErrPasswordVerifierNotConfigured",
		},
		dependencies: []dependency{
			{field: "basicAuth", typ: "BasicAuthStore"},
			{field: "passwords", typ: "PasswordVerifier"},
		},
		imports: map[string]string{
			"context": "context", "errors": "errors", "fmt": "fmt", "slices": "slices", "time": "time",
		},
		template: template.Must(template.New("basicauth").Parse(basicAuthSource)),
	},
	{
		kind: bearerAuthKind,
		name: "Bearer auth",
		declarations: []string{
			"BearerTokenVerifier", "BearerAuthIdentity", "BearerAuthIdentityFromContext",
			"bearerAuthContextKey", "ErrInvalidBearerToken", "ErrBearerAuthForbidden", "ErrBearerTokenVerifierNotConfigured",
		},
		dependencies: []dependency{{field: "bearerTokens", typ: "BearerTokenVerifier"}},
		imports: map[string]string{
			"context": "context", "errors": "errors", "fmt": "fmt", "slices": "slices",
		},
		template: template.Must(template.New("bearerauth").Parse(bearerAuthSource)),
	},
	{
		kind: oauth2Kind,
		name: "OAuth2",
		declarations: []string{
			"OAuth2TokenVerifier", "OAuth2TokenRecord", "OAuth2Identity", "OAuth2IdentityFromContext",
			"oauth2ContextKey", "ErrInvalidOAuth2Token", "ErrOAuth2Forbidden", "ErrOAuth2TokenVerifierNotConfigured",
		},
		dependencies: []dependency{{field: "oauth2Tokens", typ: "OAuth2TokenVerifier"}},
		imports: map[string]string{
			"context": "context", "errors": "errors", "fmt": "fmt", "slices": "slices", "time": "time",
		},
		template: template.Must(template.New("oauth2").Parse(oauth2Source)),
	},
}

func (s schemeSupport) render(q *qualifier) ([]byte, error) {
	data := map[string]string{"Type": handlerTypeName}
	for name, importPath := range s.imports {
		data[name] = q.importName(name, importPath)
	}
	var out bytes.Buffer
	if err := s.template.Execute(&out, data); err != nil {
		return nil, fmt.Errorf("render %s support: %w", s.name, err)
	}
	return out.Bytes(), nil
}
