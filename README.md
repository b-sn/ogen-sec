# securitygen

`securitygen` generates implementations of ogen's `SecurityHandler` interface for use from `go generate` in other Go modules.

The repository now contains only the generator itself:

- `cmd/securitygen`: CLI entry point.
- `securitygen`: generation engine, embedded templates, and tests.

The generated implementation supports these credential shapes from an ogen-generated `SecurityHandler` interface:

- API key: `APIKey string` with optional `Roles []string`
- Basic auth: `Username string`, `Password string`, and optional `Roles []string`
- HTTP Bearer: `Token string` with optional `Roles []string`
- OAuth2: `Token string` and `Scopes []string`

Unsupported schemes remain explicit `panic("<method>: not implemented")` stubs.

## Using from `go generate`

Add a directive next to the package where you want the generated handler to live:

```go
package security

//go:generate go run github.com/b-sn/ogen-sec/cmd/securitygen@v0.1.0 -source ../api/oas_security_gen.go -output security.go -api-import example.com/project/internal/api -package security -type Handler -constructor NewHandler
```

The example is pinned to the first release tag, `v0.1.0`.
You can switch it to a newer released tag or a specific commit when needed.

The required flags are:

- `-source`: Go file that declares `SecurityHandler`
- `-output`: destination file to overwrite
- `-api-import`: import path of the package that contains `SecurityHandler` and its credential types

Optional flags:

- `-package`: destination package name, default `security`
- `-type`: generated struct name, default `passthroughSecurityHandler`
- `-constructor`: generated constructor name, default `NewPassthroughSecurityHandler`

`securitygen` parses source files directly. It does not run ogen and does not need the API package to build first. To resolve credential structs it reads the source file and other active non-test Go files in the same package, which matches the way ogen emits `oas_security_gen.go` and `oas_schemas_gen.go`.

## Local development

Run the command directly from this repository:

```sh
go run ./cmd/securitygen -source ./path/to/oas_security_gen.go -output ./path/to/security.go -api-import example.com/project/internal/api
```

Run the test suite:

```sh
go test ./...
```