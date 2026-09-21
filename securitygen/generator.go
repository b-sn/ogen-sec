// Package securitygen generates implementations of ogen's SecurityHandler interface.
package securitygen

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type config struct {
	source      string
	output      string
	apiImport   string
	packageName string
	typeName    string
	constructor string
}

// Run parses command-line arguments and writes the generated implementation.
// It returns flag.ErrHelp when help is requested.
func Run(args []string) error {
	var cfg config
	flags := flag.NewFlagSet("securitygen", flag.ContinueOnError)
	flags.StringVar(&cfg.source, "source", "", "Go file declaring SecurityHandler (required)")
	flags.StringVar(&cfg.output, "output", "", "destination Go file, overwritten on every run (required)")
	flags.StringVar(&cfg.apiImport, "api-import", "", "import path of the source API package (required)")
	flags.StringVar(&cfg.packageName, "package", "security", "destination package name")
	flags.StringVar(&cfg.typeName, "type", "passthroughSecurityHandler", "implementation type name")
	flags.StringVar(&cfg.constructor, "constructor", "NewPassthroughSecurityHandler", "constructor name")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %v", flags.Args())
	}
	if cfg.source == "" || cfg.output == "" || cfg.apiImport == "" {
		return fmt.Errorf("-source, -output and -api-import are required")
	}
	for _, name := range []string{cfg.packageName, cfg.typeName, cfg.constructor} {
		if !token.IsIdentifier(name) || name == "_" || name == "init" || types.Universe.Lookup(name) != nil {
			return fmt.Errorf("invalid generated identifier %q", name)
		}
	}
	if cfg.typeName == cfg.constructor {
		return fmt.Errorf("type and constructor names must differ")
	}
	sourcePath, err := filepath.Abs(cfg.source)
	if err != nil {
		return err
	}
	outputPath, err := filepath.Abs(cfg.output)
	if err != nil {
		return err
	}
	if sourcePath == outputPath {
		return fmt.Errorf("source and output must be different files")
	}
	code, err := generate(cfg)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.output), 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	if err := os.WriteFile(cfg.output, code, 0o644); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

func generate(cfg config) ([]byte, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, cfg.source, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("parse source: %w", err)
	}
	var handler *ast.InterfaceType
	for _, decl := range file.Decls {
		decl, ok := decl.(*ast.GenDecl)
		if !ok || decl.Tok != token.TYPE {
			continue
		}
		for _, spec := range decl.Specs {
			spec := spec.(*ast.TypeSpec)
			if spec.Name.Name == "SecurityHandler" {
				handler, ok = spec.Type.(*ast.InterfaceType)
				if !ok || spec.TypeParams != nil {
					return nil, fmt.Errorf("SecurityHandler must be a non-generic interface")
				}
			}
		}
	}
	if handler == nil {
		return nil, fmt.Errorf("SecurityHandler interface not found in %s", cfg.source)
	}

	q := qualifier{
		sourceImports: make(map[string]string),
		imports:       make(map[string]string),
		reserved:      map[string]bool{cfg.typeName: true, cfg.constructor: true},
	}
	q.apiAlias = q.importName("api", cfg.apiImport)
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return nil, fmt.Errorf("parse import: %w", err)
		}
		name := path.Base(importPath)
		if spec.Name != nil {
			name = spec.Name.Name
		}
		if name == "." {
			return nil, fmt.Errorf("dot imports are not supported")
		}
		q.sourceImports[name] = importPath
	}

	declarations, err := readTypes(fset, cfg, file)
	if err != nil {
		return nil, err
	}
	securityMethods := make(map[string]*securityMethod)
	kinds := make(map[securityKind]bool)
	for _, method := range handler.Methods.List {
		signature, ok := method.Type.(*ast.FuncType)
		if !ok || len(method.Names) != 1 {
			return nil, fmt.Errorf("SecurityHandler must declare methods directly; embedded interfaces are not supported")
		}
		name := method.Names[0].Name
		security, err := detectSecurityMethod(signature, declarations, q.sourceImports)
		if err != nil {
			return nil, fmt.Errorf("method %s: %w", name, err)
		}
		if security != nil {
			securityMethods[name] = security
			kinds[security.kind] = true
		}
	}
	var support []byte
	var dependencies []dependency
	for _, scheme := range supportedSchemes {
		if !kinds[scheme.kind] {
			continue
		}
		for _, name := range scheme.declarations {
			if q.reserved[name] {
				return nil, fmt.Errorf("generated identifier %s conflicts with %s support", name, scheme.name)
			}
			q.reserved[name] = true
		}
		dependencies = append(dependencies, scheme.dependencies...)
	}
	// Reserve all declarations before importing runtime dependencies, so source
	// aliases cannot shadow identifiers in the generated implementation bodies.
	for _, scheme := range supportedSchemes {
		if !kinds[scheme.kind] {
			continue
		}
		code, err := scheme.render(cfg, &q)
		if err != nil {
			return nil, err
		}
		support = append(support, code...)
	}

	var methods bytes.Buffer
	for _, method := range handler.Methods.List {
		signature, ok := method.Type.(*ast.FuncType)
		if !ok || len(method.Names) != 1 {
			return nil, fmt.Errorf("SecurityHandler must declare methods directly; embedded interfaces are not supported")
		}
		name := method.Names[0].Name
		if !ast.IsExported(name) {
			return nil, fmt.Errorf("cannot implement unexported method %s in another package", name)
		}
		security := securityMethods[name]
		if security != nil {
			nameCredentialParams(signature)
		}
		if err := q.fields(signature.Params); err != nil {
			return nil, fmt.Errorf("method %s parameters: %w", name, err)
		}
		if err := q.fields(signature.Results); err != nil {
			return nil, fmt.Errorf("method %s results: %w", name, err)
		}
		var sig bytes.Buffer
		if err := format.Node(&sig, fset, signature); err != nil {
			return nil, fmt.Errorf("format method %s: %w", name, err)
		}
		fmt.Fprintf(&methods, "// %s implements %s.SecurityHandler.\n", name, q.apiAlias)
		if security == nil {
			fmt.Fprintf(&methods, "func (*%s) %s%s {\n\tpanic(%q)\n}\n\n",
				cfg.typeName, name, sig.String()[len("func"):], name+": not implemented")
		} else {
			fmt.Fprintf(&methods, "func (s *%s) %s%s {\n", cfg.typeName, name, sig.String()[len("func"):])
			invalidError := "ErrInvalidAPIKey"
			switch security.kind {
			case basicAuthKind:
				invalidError = "ErrInvalidBasicAuth"
			case bearerAuthKind:
				invalidError = "ErrInvalidBearerToken"
			case oauth2Kind:
				invalidError = "ErrInvalidOAuth2Token"
			}
			if security.pointer {
				fmt.Fprintf(&methods, "if credentials == nil { return ctx, %s }\n", invalidError)
			}
			roles := "nil"
			if security.roles {
				roles = "credentials.Roles"
			}
			switch security.kind {
			case apiKeyKind:
				fmt.Fprintf(&methods, "return s.authorizeAPIKey(ctx, %q, credentials.APIKey, %s)\n}\n\n", security.scheme, roles)
			case basicAuthKind:
				fmt.Fprintf(&methods, "return s.authorizeBasicAuth(ctx, %q, credentials.Username, credentials.Password, %s)\n}\n\n", security.scheme, roles)
			case bearerAuthKind:
				fmt.Fprintf(&methods, "return s.authorizeBearerAuth(ctx, %q, credentials.Token, %s)\n}\n\n", security.scheme, roles)
			case oauth2Kind:
				fmt.Fprintf(&methods, "return s.authorizeOAuth2(ctx, %q, credentials.Token, credentials.Scopes)\n}\n\n", security.scheme)
			}
		}
	}

	var out bytes.Buffer
	fmt.Fprintf(&out, "// Code generated by securitygen; DO NOT EDIT.\n\npackage %s\n\nimport (\n", cfg.packageName)
	aliases := make([]string, 0, len(q.imports))
	for alias := range q.imports {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)
	for _, alias := range aliases {
		fmt.Fprintf(&out, "\t%s %q\n", alias, q.imports[alias])
	}
	fmt.Fprint(&out, ")\n\n")
	out.Write(support)
	fmt.Fprintf(&out, "// %s implements %s.SecurityHandler. Unsupported schemes remain stubs.\n", cfg.typeName, q.apiAlias)
	fmt.Fprintf(&out, "type %s struct {\n", cfg.typeName)
	var arguments, initializers []string
	for _, dep := range dependencies {
		fmt.Fprintf(&out, "%s %s\n", dep.field, dep.typ)
		arguments = append(arguments, dep.field+" "+dep.typ)
		initializers = append(initializers, dep.field+": "+dep.field)
	}
	fmt.Fprint(&out, "}\n\n")
	fmt.Fprintf(&out, "// %s creates a security handler. Nil dependencies reject requests for their schemes.\n", cfg.constructor)
	fmt.Fprintf(&out, "func %s(%s) *%s {\nreturn &%s{%s}\n}\n\n",
		cfg.constructor, strings.Join(arguments, ", "), cfg.typeName, cfg.typeName, strings.Join(initializers, ", "))
	fmt.Fprintf(&out, "var _ %s.SecurityHandler = (*%s)(nil)\n\n", q.apiAlias, cfg.typeName)
	out.Write(methods.Bytes())
	code, err := format.Source(out.Bytes())
	if err != nil {
		return nil, fmt.Errorf("format output: %w", err)
	}
	return code, nil
}

// qualifier moves signature types into the destination package and imports only
// the packages used by those signatures. It does not load or compile the API.
type qualifier struct {
	apiAlias      string
	sourceImports map[string]string
	imports       map[string]string
	reserved      map[string]bool
}

func (q *qualifier) importName(preferred, importPath string) string {
	for alias, existing := range q.imports {
		if existing == importPath {
			return alias
		}
	}
	alias := preferred
	for n := 2; q.reserved[alias] || q.imports[alias] != ""; n++ {
		alias = preferred + strconv.Itoa(n)
	}
	q.imports[alias] = importPath
	return alias
}

func (q *qualifier) fields(fields *ast.FieldList) error {
	if fields == nil {
		return nil
	}
	for _, field := range fields.List {
		for _, name := range field.Names {
			if name.Name == "panic" {
				name.Name = "_"
			}
		}
		typ, err := q.expr(field.Type)
		if err != nil {
			return err
		}
		field.Type = typ
	}
	return nil
}

func (q *qualifier) expr(expr ast.Expr) (ast.Expr, error) {
	var err error
	switch expr := expr.(type) {
	case *ast.Ident:
		if types.Universe.Lookup(expr.Name) != nil {
			return expr, nil
		}
		if !ast.IsExported(expr.Name) {
			return nil, fmt.Errorf("cannot reference unexported API identifier %s", expr.Name)
		}
		return &ast.SelectorExpr{X: ast.NewIdent(q.apiAlias), Sel: expr}, nil
	case *ast.SelectorExpr:
		pkg, ok := expr.X.(*ast.Ident)
		if !ok || q.sourceImports[pkg.Name] == "" {
			return nil, fmt.Errorf("unknown package in selector")
		}
		expr.X = ast.NewIdent(q.importName(pkg.Name, q.sourceImports[pkg.Name]))
	case *ast.StarExpr:
		expr.X, err = q.expr(expr.X)
	case *ast.ArrayType:
		if expr.Len != nil {
			expr.Len, err = q.expr(expr.Len)
			if err != nil {
				return nil, err
			}
		}
		expr.Elt, err = q.expr(expr.Elt)
	case *ast.MapType:
		expr.Key, err = q.expr(expr.Key)
		if err != nil {
			return nil, err
		}
		expr.Value, err = q.expr(expr.Value)
	case *ast.ChanType:
		expr.Value, err = q.expr(expr.Value)
	case *ast.Ellipsis:
		expr.Elt, err = q.expr(expr.Elt)
	case *ast.ParenExpr:
		expr.X, err = q.expr(expr.X)
	case *ast.FuncType:
		if err = q.fields(expr.Params); err == nil {
			err = q.fields(expr.Results)
		}
	case *ast.BasicLit:
		// Array lengths can be literals.
	default:
		return nil, fmt.Errorf("unsupported signature expression %T", expr)
	}
	return expr, err
}
