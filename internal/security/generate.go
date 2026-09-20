package security

// Paths are relative to this directory. This directive lives outside security.go
// because the generator replaces that file, including any manual edits.
//go:generate go run ../../cmd/securitygen/main.go -source ../ogen/api/oas_security_gen.go -output security.go -api-import ogen-sec/internal/ogen/api -package security -type passthroughSecurityHandler -constructor NewPassthroughSecurityHandler
