package api

import ctxt "context"

type SecurityHandler interface {
	HandleToken(s ctxt.Context, context OperationName, h CredentialXYZ) (next ctxt.Context, err error)
	HandleReferenced(ctxt.Context, OperationName, ReferencedToken) (ctxt.Context, error)
	HandleLegacy(ctxt.Context, OperationName, LegacyToken) (ctxt.Context, error)
	HandlePointer(ctxt.Context, OperationName, *PointerToken) (ctxt.Context, error)
	HandleUnsupported(ctxt.Context, OperationName, CustomCredential) (ctxt.Context, error)
}
