package securitygen

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const ogenVersion = "v1.24.0"

// TestGenerateFromOpenAPIFixtures exercises the public compatibility boundary:
// OpenAPI schema -> ogen -> securitygen -> a compiling Go module. Golden files
// deliberately cover securitygen's output only; ogen owns its own output.
func TestGenerateFromOpenAPIFixtures(t *testing.T) {
	ogen := findOgen(t)
	for _, tc := range []struct {
		name, schema, config, golden string
		securityHandler              bool
	}{
		{
			name:            "full security matrix",
			schema:          "testdata/integration/openapi.yaml",
			config:          "testdata/integration/ogen.yml",
			golden:          "testdata/integration/expected_security.go",
			securityHandler: true,
		},
		{
			name:            "API key",
			schema:          "testdata/integration/apikey/openapi.yaml",
			golden:          "testdata/integration/apikey/expected_security.go",
			securityHandler: true,
		},
		{
			name:            "Basic authentication",
			schema:          "testdata/integration/basicauth/openapi.yaml",
			golden:          "testdata/integration/basicauth/expected_security.go",
			securityHandler: true,
		},
		{
			name:            "Bearer authentication",
			schema:          "testdata/integration/bearer/openapi.yaml",
			golden:          "testdata/integration/bearer/expected_security.go",
			securityHandler: true,
		},
		{
			name:            "OAuth2",
			schema:          "testdata/integration/oauth2/openapi.yaml",
			golden:          "testdata/integration/oauth2/expected_security.go",
			securityHandler: true,
		},
		{
			name:   "no authentication",
			schema: "testdata/integration/noauth/openapi.yaml",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			apiDir := filepath.Join(dir, "api")
			runOgen(t, ogen, tc.schema, tc.config, apiDir)

			source := filepath.Join(apiDir, "oas_security_gen.go")
			if !tc.securityHandler {
				if _, err := os.Stat(source); !os.IsNotExist(err) {
					t.Fatalf("ogen produced %s for a schema without security: %v", source, err)
				}
				compileGeneratedModule(t, dir)
				return
			}

			if _, err := os.Stat(source); err != nil {
				t.Fatalf("ogen did not produce SecurityHandler: %v", err)
			}
			output := filepath.Join(dir, "security.go")
			if err := Run([]string{
				"-source", source,
				"-output", output,
				"-api-import", "example.test/generated/api",
				"-package", "security",
				"-constructor", "NewHandler",
			}); err != nil {
				t.Fatal(err)
			}
			assertGolden(t, tc.golden, output)
			compileGeneratedModule(t, dir)
		})
	}
}

func findOgen(t *testing.T) string {
	t.Helper()
	if ogen := os.Getenv("OGEN_BIN"); ogen != "" {
		if _, err := os.Stat(ogen); err != nil {
			t.Fatalf("OGEN_BIN %q is unavailable: %v", ogen, err)
		}
		return ogen
	}
	ogen := filepath.Join("..", "bin", "ogen")
	if _, err := os.Stat(ogen); err != nil {
		t.Skipf("ogen %s is required for OpenAPI integration tests; run make test or set OGEN_BIN", ogen)
	}
	return ogen
}

func runOgen(t *testing.T, ogen, schema, config, target string) {
	t.Helper()
	args := []string{"--target", target, "--clean"}
	if config != "" {
		args = append(args, "--config", config)
	}
	args = append(args, schema)
	cmd := exec.Command(ogen, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ogen failed: %v\n%s", err, output)
	}
}

func assertGolden(t *testing.T, golden, actual string) {
	t.Helper()
	got, err := os.ReadFile(actual)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden %s: %v (run UPDATE_GOLDEN=1 make test to create it)", golden, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("generated code differs from %s; inspect the diff or run UPDATE_GOLDEN=1 make test after reviewing the change", golden)
	}
}

func compileGeneratedModule(t *testing.T, dir string) {
	t.Helper()
	writeTestFile(t, filepath.Join(dir, "go.mod"), fmt.Appendf([]byte{}, "module example.test/generated\n\ngo %s\n\nrequire github.com/ogen-go/ogen %s\n", testModuleGoVersion, ogenVersion))
	for _, args := range [][]string{{"mod", "tidy"}, {"test", "./..."}} {
		cmd := exec.Command("go", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("go %v failed: %v\n%s", args, err, output)
		}
	}
}
