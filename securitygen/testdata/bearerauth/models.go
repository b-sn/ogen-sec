package api

type OperationName string

type CredentialXYZ struct {
	Token string
	Roles []string
}

type ReferencedToken = CredentialXYZ

type LegacyToken struct {
	Token string
}

type PointerToken struct {
	Token string
	Roles []string
}

type CustomCredential struct{ Credentials string }
