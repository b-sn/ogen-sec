package api

import ctxt "context"

type SecurityHandler interface {
	HandleCookie(ctxt.Context, OperationName, CookieCredential) (ctxt.Context, error)
	HandleHeader(s ctxt.Context, h OperationName, context HeaderCredential) (next ctxt.Context, err error)
	HandleQuery(ctx ctxt.Context, op OperationName, t QueryCredential) (ctxt.Context, error)
	HandleLegacy(ctxt.Context, OperationName, LegacyCredential) (ctxt.Context, error)
	HandleAlias(ctxt.Context, OperationName, AliasCredential) (ctxt.Context, error)
	HandlePointer(ctxt.Context, OperationName, *PointerCredential) (ctxt.Context, error)
	HandleUnsupported(ctxt.Context, OperationName, CustomCredential) (ctxt.Context, error)
}
