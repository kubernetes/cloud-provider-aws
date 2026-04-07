package aws

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAllLoadDefaultConfigHaveHTTPClient scans all .go source files and verifies
// that every call to LoadDefaultConfig includes a WithHTTPClient option.
// This prevents SDK clients from being created without an explicit HTTP timeout,
// which can lead to clock skew overcorrection on slow responses.
func TestAllLoadDefaultConfigHaveHTTPClient(t *testing.T) {
	repoRoot := filepath.Join("..", "..", "..")
	var violations []string

	err := filepath.Walk(repoRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			name := info.Name()
			if name == "vendor" || name == ".git" || name == "tests" {
				return filepath.SkipDir
			}
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		fset := token.NewFileSet()
		node, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return nil
		}

		ast.Inspect(node, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if !isLoadDefaultConfig(call) {
				return true
			}
			if !hasWithHTTPClient(call) {
				pos := fset.Position(call.Pos())
				violations = append(violations, pos.String())
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk source tree: %v", err)
	}

	for _, v := range violations {
		t.Errorf("LoadDefaultConfig without WithHTTPClient at %s", v)
	}
}

func isLoadDefaultConfig(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	return sel.Sel.Name == "LoadDefaultConfig"
}

func hasWithHTTPClient(call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		if containsIdent(arg, "WithHTTPClient") {
			return true
		}
	}
	return false
}

func containsIdent(node ast.Node, name string) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if ident, ok := n.(*ast.Ident); ok && ident.Name == name {
			found = true
			return false
		}
		return true
	})
	return found
}
