package posture

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Packages that could let the statement builder read files, the network or
// OS state. Neither this package nor the in-module packages it builds on
// may import them directly.
var forbiddenImports = []string{
	"os", "os/exec", "os/user", "io/fs", "io/ioutil", "path", "path/filepath",
	"net", "net/http", "net/url", "syscall", "embed", "bufio", "runtime/cgo",
}

func parseDir(t *testing.T, dir string) []*ast.File {
	t.Helper()
	fset := token.NewFileSet()
	matches, _ := filepath.Glob(filepath.Join(dir, "*.go"))
	var files []*ast.File
	for _, m := range matches {
		if strings.HasSuffix(m, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, m, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		t.Fatalf("no Go files in %s", dir)
	}
	return files
}

func TestBuilderCannotTouchFilesOrNetwork(t *testing.T) {
	for _, dir := range []string{".", "../canon", "../sigs", "../dsse", "../tsa", "../brand"} {
		for _, f := range parseDir(t, dir) {
			for _, imp := range f.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				for _, bad := range forbiddenImports {
					if p == bad {
						t.Errorf("%s imports %q; the statement builder and its dependencies must not reach the file system, network or OS", dir, p)
					}
				}
			}
		}
	}
}

// isUntyped reports types that could carry arbitrary text or file handles.
func isUntyped(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name == "string" || x.Name == "any" || x.Name == "byte" || x.Name == "rune"
	case *ast.ArrayType:
		return isUntyped(x.Elt)
	case *ast.MapType, *ast.InterfaceType, *ast.FuncType, *ast.ChanType:
		return true
	case *ast.StarExpr:
		return isUntyped(x.X)
	case *ast.SelectorExpr:
		pkg, _ := x.X.(*ast.Ident)
		return pkg != nil && (pkg.Name == "io" || pkg.Name == "fs" || pkg.Name == "os")
	case *ast.Ellipsis:
		return isUntyped(x.Elt)
	}
	return false
}

// Every exported Build* function takes only typed values, and the input
// structs it reads have no string, byte, map or interface fields. A path
// cannot reach the builder because there is nowhere to put one.
func TestBuilderAcceptsOnlyTypedValues(t *testing.T) {
	builders := 0
	for _, f := range parseDir(t, ".") {
		for _, d := range f.Decls {
			switch x := d.(type) {
			case *ast.FuncDecl:
				if !x.Name.IsExported() || !strings.HasPrefix(x.Name.Name, "Build") {
					continue
				}
				builders++
				for _, p := range x.Type.Params.List {
					if isUntyped(p.Type) {
						t.Errorf("%s has an untyped parameter %s", x.Name.Name, exprString(p.Type))
					}
				}
			case *ast.GenDecl:
				for _, s := range x.Specs {
					ts, ok := s.(*ast.TypeSpec)
					if !ok {
						continue
					}
					st, ok := ts.Type.(*ast.StructType)
					if !ok || !builderInput[ts.Name.Name] {
						continue
					}
					for _, fld := range st.Fields.List {
						if isUntyped(fld.Type) {
							t.Errorf("builder input %s has an untyped field %s", ts.Name.Name, exprString(fld.Type))
						}
					}
				}
			}
		}
	}
	if builders < 5 {
		t.Fatalf("found only %d Build functions; the test is not looking in the right place", builders)
	}
}

var builderInput = map[string]bool{
	"Header": true, "DeviceChecks": true, "TenantPosture": true, "VerifyBeforePay": true,
	"RestoreDrill": true, "StaffEvent": true, "EnrollmentInfo": true, "Count": true, "ScanResult": true, "ScanResults": true,
}

func exprString(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.ArrayType:
		return "[]" + exprString(x.Elt)
	case *ast.StarExpr:
		return "*" + exprString(x.X)
	case *ast.SelectorExpr:
		return exprString(x.X) + "." + x.Sel.Name
	}
	return "?"
}
