package proof

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// These tests make the privacy rule checkable by tooling, as in the proof
// engine: the statement builder cannot reach files, the network or OS
// state, and its inputs have nowhere to put text.

var forbiddenImports = []string{
	"os", "os/exec", "os/user", "io/fs", "io/ioutil", "path", "path/filepath",
	"net", "net/http", "net/url", "syscall", "embed", "bufio", "runtime/cgo",
	"unsafe", "golang.org/x/sys/windows", "golang.org/x/sys/windows/registry",
}

func parsePackage(t *testing.T) []*ast.File {
	t.Helper()
	fset := token.NewFileSet()
	matches, _ := filepath.Glob("*.go")
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
	if len(files) < 4 {
		t.Fatalf("found only %d source files; the test is not looking in the right place", len(files))
	}
	return files
}

func TestBuilderCannotTouchFilesNetworkOrOS(t *testing.T) {
	for _, f := range parsePackage(t) {
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			for _, bad := range forbiddenImports {
				if p == bad {
					t.Errorf("package proof imports %q; the statement builder must not reach files, the network or the OS", p)
				}
			}
			if strings.HasPrefix(p, "github.com/kendallcoding202/kovyr-edr/") {
				t.Errorf("package proof imports %q; it must depend only on the standard library", p)
			}
		}
	}
}

// isUntyped reports types that could carry arbitrary text or handles.
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
	case *ast.Ellipsis:
		return isUntyped(x.Elt)
	case *ast.SelectorExpr:
		pkg, _ := x.X.(*ast.Ident)
		return pkg != nil && (pkg.Name == "io" || pkg.Name == "fs" || pkg.Name == "os")
	}
	return false
}

// builderInputs are the structs BuildSensorHealth reads (time.Time is a
// timestamp and is allowed).
var builderInputs = map[string]bool{
	"Header": true, "Readings": true, "SecurityCenter": true, "Defender": true,
	"EDR": true, "EDRAgent": true, "Version": true,
}

// vocabularyTypes must be small unsigned integers, never strings.
var vocabularyTypes = map[string]bool{
	"Availability": true, "Toggle": true, "BlocklistState": true, "VolumeProtection": true,
	"RunningMode": true, "Vendor": true, "KeyProtection": true, "NonceSource": true,
}

func TestBuilderAcceptsOnlyTypedValues(t *testing.T) {
	builders, inputs, vocab := 0, 0, 0
	for _, f := range parsePackage(t) {
		for _, d := range f.Decls {
			switch x := d.(type) {
			case *ast.FuncDecl:
				if x.Recv != nil || !strings.HasPrefix(x.Name.Name, "Build") {
					continue
				}
				builders++
				for _, p := range x.Type.Params.List {
					if isUntyped(p.Type) {
						t.Errorf("%s has an untyped parameter", x.Name.Name)
					}
				}
			case *ast.GenDecl:
				for _, s := range x.Specs {
					ts, ok := s.(*ast.TypeSpec)
					if !ok {
						continue
					}
					if vocabularyTypes[ts.Name.Name] {
						vocab++
						if id, ok := ts.Type.(*ast.Ident); !ok || id.Name != "uint8" {
							t.Errorf("vocabulary type %s must be a uint8 enum", ts.Name.Name)
						}
					}
					st, ok := ts.Type.(*ast.StructType)
					if !ok || !builderInputs[ts.Name.Name] {
						continue
					}
					inputs++
					for _, fld := range st.Fields.List {
						if isUntyped(fld.Type) {
							t.Errorf("builder input %s has an untyped field", ts.Name.Name)
						}
					}
				}
			}
		}
	}
	if builders != 1 || inputs != len(builderInputs) || vocab != len(vocabularyTypes) {
		t.Fatalf("found %d builders, %d of %d inputs, %d of %d vocabulary types; the test is not looking in the right place",
			builders, inputs, len(builderInputs), vocab, len(vocabularyTypes))
	}
}
