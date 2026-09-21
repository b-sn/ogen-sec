package api

type OperationName string

type AccessCredential struct {
	Token  string
	Scopes []string
}

type AliasCredential = AccessCredential

type PointerCredential struct {
	Token  string
	Scopes []string
}
