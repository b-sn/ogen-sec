package securitygen

import (
	"bytes"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testModuleGoVersion = "1.25"

func TestGenerateImplementsInterface(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source string
	}{
		{
			name: "renamed methods and import aliases",
			source: `package upstream
import (
	ctx "context"
	api "net/http"
	"strings"
)
var _ = strings.TrimSpace
type OperationName string
type TokenXYZ12 struct{}
type SecurityHandler interface {
	HandleRenamedXYZ12(ctx ctx.Context, op OperationName, t TokenXYZ12) (ctx.Context, error)
	HandleRequest(ctx ctx.Context, r *api.Request, tokens ...*TokenXYZ12) (next ctx.Context, err error)
	HandleTokens(tokens map[string][]*TokenXYZ12) error
}
`,
		},
		{
			name:   "empty interface",
			source: "package upstream\ntype SecurityHandler interface{}\n",
		},
		{
			name:   "parameter named panic",
			source: "package upstream\ntype SecurityHandler interface { Handle(panic string) (error) }\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := filepath.Join(t.TempDir(), "source.go")
			writeTestFile(t, source, []byte(tc.source))
			cfg := config{
				source:      source,
				apiImport:   "example.test/api",
				packageName: "security",
				constructor: "NewHandler",
			}
			code, err := generate(cfg)
			if err != nil {
				t.Fatal(err)
			}
			assertImplementationCompiles(t, cfg, code, tc.source)
			if !bytes.Contains(code, []byte("type handler struct")) || bytes.Contains(code, []byte("type Handler struct")) || !bytes.Contains(code, []byte("func NewHandler() *handler")) {
				t.Fatal("generated handler type must be private and available through its constructor")
			}
			if bytes.Contains(code, []byte(`"strings"`)) {
				t.Fatal("unused source imports leaked into the output")
			}
			again, err := generate(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(code, again) {
				t.Fatal("generation is not deterministic")
			}
		})
	}
}

func TestRunReplacesOutput(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.go")
	output := filepath.Join(dir, "nested", "custom.go")
	args := []string{
		"-source", source, "-output", output, "-api-import", "example.test/api",
		"-package", "auth", "-constructor", "NewStub",
	}
	writeTestFile(t, source, []byte("package api\ntype SecurityHandler interface { HandleOld() }\n"))
	if err := Run(args); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, source, []byte("package api\ntype SecurityHandler interface { HandleNew() }\n"))
	if err := Run(args); err != nil {
		t.Fatal(err)
	}
	code, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"package auth", "func NewStub() *handler", "func (*handler) HandleNew()", `panic("HandleNew: not implemented")`} {
		if !strings.Contains(string(code), want) {
			t.Errorf("output is missing %q", want)
		}
	}
	if strings.Contains(string(code), "HandleOld") {
		t.Fatal("obsolete method was retained")
	}
	if err := Run(append(append([]string(nil), args...), "-type", "Handler")); err == nil {
		t.Fatal("removed -type option was accepted")
	}
	if err := Run(append(append([]string(nil), args[:len(args)-1]...), "handler")); err == nil {
		t.Fatal("constructor name collided with the private handler type")
	}

	for _, invalid := range []string{
		"package api\ntype Other interface{}\n",
		"package api\ntype SecurityHandler struct{}\n",
		"package api\ntype Base interface{}\ntype SecurityHandler interface { Base }\n",
		"package api\ntype SecurityHandler interface {",
	} {
		writeTestFile(t, source, []byte(invalid))
		if err := Run(args); err == nil {
			t.Fatalf("expected failure for source %q", invalid)
		}
		after, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(code, after) {
			t.Fatal("failed generation changed the existing output")
		}
	}
}

func assertImplementationCompiles(t *testing.T, cfg config, code []byte, sources ...string) {
	t.Helper()
	// Type-check the source and the generated implementation together, using
	// only standard-library imports and an in-memory API package.
	fset := token.NewFileSet()
	var apiFiles []*ast.File
	for _, source := range sources {
		file, err := parser.ParseFile(fset, "source.go", source, 0)
		if err != nil {
			t.Fatal(err)
		}
		apiFiles = append(apiFiles, file)
	}
	imports := importer.Default()
	checker := types.Config{Importer: imports}
	apiPackage, err := checker.Check(cfg.apiImport, fset, apiFiles, nil)
	if err != nil {
		t.Fatal(err)
	}
	generated, err := parser.ParseFile(fset, "security.go", code, 0)
	if err != nil {
		t.Fatal(err)
	}
	checker.Importer = apiImporter{Importer: imports, api: apiPackage}
	if _, err := checker.Check("example.test/security", fset, []*ast.File{generated}, nil); err != nil {
		t.Fatalf("generated implementation does not compile: %v\n%s", err, code)
	}
}

type apiImporter struct {
	types.Importer
	api *types.Package
}

func (i apiImporter) Import(importPath string) (*types.Package, error) {
	if importPath == i.api.Path() {
		return i.api, nil
	}
	return i.Importer.Import(importPath)
}

func writeTestFile(t *testing.T, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(name, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
