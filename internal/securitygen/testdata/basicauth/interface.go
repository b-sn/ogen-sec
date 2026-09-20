package api

import ctxt "context"

type SecurityHandler interface {
	HandleLogin(s ctxt.Context, context OperationName, h LoginCredential) (next ctxt.Context, err error)
	HandleLegacy(ctxt.Context, OperationName, LegacyCredential) (ctxt.Context, error)
	HandleAlias(ctxt.Context, OperationName, AliasCredential) (ctxt.Context, error)
	HandlePointer(ctxt.Context, OperationName, *PointerCredential) (ctxt.Context, error)
	HandleKey(ctxt.Context, OperationName, KeyCredential) (ctxt.Context, error)
}
