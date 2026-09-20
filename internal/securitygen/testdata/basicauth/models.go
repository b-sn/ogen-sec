package api

type OperationName string

type LoginCredential struct {
	Username string
	Password string
	Roles    []string
}

type LegacyCredential struct{ Username, Password string }
type AliasCredential = LoginCredential
type PointerCredential struct{ Username, Password string }
type KeyCredential struct{ APIKey string }
