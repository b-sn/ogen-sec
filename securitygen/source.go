package securitygen

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

type securityKind int

const (
	apiKeyKind securityKind = iota + 1
	basicAuthKind
	bearerAuthKind
	oauth2Kind
)

type securityMethod struct {
	kind    securityKind
	scheme  string
	roles   bool
	pointer bool
}

// readTypes reads declarations without loading dependencies or compiling the API.
// ogen declares credential structs in a sibling file, usually oas_schemas_gen.go.
func readTypes(fset *token.FileSet, cfg config, source *ast.File) (map[string]ast.Expr, error) {
	declarations := make(map[string]ast.Expr)
	dir := filepath.Dir(cfg.source)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read API directory: %w", err)
	}
	outputPath, err := filepath.Abs(cfg.output)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		filename := filepath.Join(dir, name)
		absolute, err := filepath.Abs(filename)
		if err != nil {
			return nil, err
		}
		if absolute == outputPath {
			continue
		}
		file := source
		if name != filepath.Base(cfg.source) {
			match, err := build.Default.MatchFile(dir, name)
			if err != nil {
				return nil, fmt.Errorf("read build constraints for %s: %w", name, err)
			}
			if !match {
				continue
			}
			file, err = parser.ParseFile(fset, filename, nil, parser.SkipObjectResolution)
			if err != nil {
				return nil, fmt.Errorf("parse API declarations in %s: %w", name, err)
			}
		}
		if file.Name.Name != source.Name.Name {
			continue
		}
		for _, decl := range file.Decls {
			decl, ok := decl.(*ast.GenDecl)
			if !ok || decl.Tok != token.TYPE {
				continue
			}
			for _, spec := range decl.Specs {
				spec := spec.(*ast.TypeSpec)
				declarations[spec.Name.Name] = spec.Type
			}
		}
	}
	return declarations, nil
}

func detectSecurityMethod(signature *ast.FuncType, declarations map[string]ast.Expr, imports map[string]string) (*securityMethod, error) {
	params := fieldTypes(signature.Params)
	if len(params) != 3 {
		return nil, nil
	}
	typ := params[2]
	pointer := false
	if ptr, ok := typ.(*ast.StarExpr); ok {
		typ, pointer = ptr.X, true
	}
	name, ok := typ.(*ast.Ident)
	if !ok {
		return nil, nil
	}
	scheme := name.Name
	seen := make(map[string]bool)
	for {
		name, ok := typ.(*ast.Ident)
		if !ok {
			break
		}
		if seen[name.Name] {
			return nil, fmt.Errorf("cyclic credential type %s", name.Name)
		}
		seen[name.Name] = true
		typ = declarations[name.Name]
	}
	structure, ok := typ.(*ast.StructType)
	if !ok {
		return nil, nil
	}
	fields := make(map[string]ast.Expr)
	for _, field := range structure.Fields.List {
		for _, name := range field.Names {
			fields[name.Name] = field.Type
		}
	}
	keyType, hasKey := fields["APIKey"]
	usernameType, hasUsername := fields["Username"]
	passwordType, hasPassword := fields["Password"]
	tokenType, hasToken := fields["Token"]
	scopes, hasScopes := fields["Scopes"]
	if !hasKey && !hasUsername && !hasPassword && !hasToken && !hasScopes {
		return nil, nil
	}
	if hasKey && (hasUsername || hasPassword) {
		return nil, fmt.Errorf("credential %s mixes API key and Basic auth fields", scheme)
	}
	if hasToken && (hasKey || hasUsername || hasPassword) {
		return nil, fmt.Errorf("credential %s mixes token and other authentication fields", scheme)
	}
	if hasScopes && (hasKey || hasUsername || hasPassword) {
		return nil, fmt.Errorf("credential %s mixes Scopes and other authentication fields", scheme)
	}
	kind, description := apiKeyKind, "API key"
	switch {
	case hasToken || hasScopes:
		// Ogen distinguishes HTTP Bearer credentials (Roles) from OAuth2
		// credentials (Scopes). Never authorize OAuth2 while ignoring scopes.
		kind, description = bearerAuthKind, "Bearer auth"
		if hasScopes {
			if _, hasRoles := fields["Roles"]; hasRoles {
				return nil, fmt.Errorf("token credential %s mixes Roles and Scopes", scheme)
			}
			kind, description = oauth2Kind, "OAuth2"
			if !isStringSlice(scopes) {
				return nil, fmt.Errorf("OAuth2 credential %s must have Scopes of type []string", scheme)
			}
		}
		if !isIdent(tokenType, "string") {
			return nil, fmt.Errorf("%s credential %s must have a Token string field", description, scheme)
		}
	case hasKey:
		if !isIdent(keyType, "string") {
			return nil, fmt.Errorf("API key credential %s must have an APIKey string field", scheme)
		}
	default:
		kind, description = basicAuthKind, "Basic auth"
		if !isIdent(usernameType, "string") || !isIdent(passwordType, "string") {
			return nil, fmt.Errorf("basic auth credential %s must have Username and Password string fields", scheme)
		}
	}
	roles, hasRoles := fields["Roles"]
	if hasRoles && !isStringSlice(roles) {
		return nil, fmt.Errorf("%s credential %s must have Roles of type []string", description, scheme)
	}
	results := fieldTypes(signature.Results)
	if !isContext(params[0], imports) || len(results) != 2 || !isContext(results[0], imports) || !isIdent(results[1], "error") {
		return nil, fmt.Errorf("%s method must accept context.Context and return (context.Context, error)", description)
	}
	return &securityMethod{kind: kind, scheme: scheme, roles: hasRoles, pointer: pointer}, nil
}

func fieldTypes(fields *ast.FieldList) []ast.Expr {
	var result []ast.Expr
	if fields != nil {
		for _, field := range fields.List {
			count := len(field.Names)
			if count == 0 {
				count = 1
			}
			for i := 0; i < count; i++ {
				result = append(result, field.Type)
			}
		}
	}
	return result
}

func isIdent(expr ast.Expr, name string) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == name
}

func isStringSlice(expr ast.Expr) bool {
	array, ok := expr.(*ast.ArrayType)
	return ok && array.Len == nil && isIdent(array.Elt, "string")
}

func isContext(expr ast.Expr, imports map[string]string) bool {
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Context" {
		return false
	}
	pkg, ok := selector.X.(*ast.Ident)
	return ok && imports[pkg.Name] == "context"
}

// Normalize parameter names so generated bodies do not depend on ogen's names.
func nameCredentialParams(signature *ast.FuncType) {
	params := fieldTypes(signature.Params)
	signature.Params.List = nil
	for i, name := range []string{"ctx", "_", "credentials"} {
		signature.Params.List = append(signature.Params.List, &ast.Field{
			Names: []*ast.Ident{ast.NewIdent(name)}, Type: params[i],
		})
	}
	for _, field := range signature.Results.List {
		field.Names = nil
	}
}
