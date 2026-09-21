package api

type OperationName string

type CookieCredential struct {
	APIKey string
	Roles  []string
}

type HeaderCredential struct {
	APIKey string
	Roles  []string
}

type QueryCredential struct {
	APIKey string
	Roles  []string
}

type LegacyCredential struct{ APIKey string }
type AliasCredential = HeaderCredential
type PointerCredential struct{ APIKey string }
type CustomCredential struct{ Credentials string }
