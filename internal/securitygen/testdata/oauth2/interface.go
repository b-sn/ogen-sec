package api

import ctxt "context"

type SecurityHandler interface {
	HandleAccess(s ctxt.Context, context OperationName, h AccessCredential) (next ctxt.Context, err error)
	HandleAlias(ctxt.Context, OperationName, AliasCredential) (ctxt.Context, error)
	HandlePointer(ctxt.Context, OperationName, *PointerCredential) (ctxt.Context, error)
}
