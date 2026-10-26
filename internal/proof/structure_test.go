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

const module = "github.com/kendallcoding202/kovyr-edr/"

// allowedLibs are the only in-module packages the statement builder may
// import: the shared proof library's encoding, signature, schema and
// constant packages. They are checked below with the same import rules.
var allowedLibs = map[string]bool{
	module + "proof/canon": true, module + "proof/dsse": true,
	module + "proof/sigs": true, module + "proof/posture": true,
	module + "proof/brand": true, module + "proof/tsa": true,
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
		t.Fatalf("no Go files in %s; the test is not looking in the right place", dir)
	}
	return files
}

func parsePackage(t *testing.T) []*ast.File {
	t.Helper()
	files := parseDir(t, ".")
	if len(files) < 4 {
		t.Fatalf("found only %d source files; the test is not looking in the right place", len(files))
	}
	return files
}

func TestBuilderCannotTouchFilesNetworkOrOS(t *testing.T) {
	// Walk package proof and every in-module package it reaches.
	seen := map[string]bool{}
	queue := []string{"."}
	for len(queue) > 0 {
		dir := queue[0]
		queue = queue[1:]
		if seen[dir] {
			continue
		}
		seen[dir] = true
		for _, f := range parseDir(t, dir) {
			for _, imp := range f.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				for _, bad := range forbiddenImports {
					if p == bad {
						t.Errorf("%s imports %q; the statement builder and the library under it must not reach files, the network or the OS", dir, p)
					}
				}
				if !strings.HasPrefix(p, module) {
					continue
				}
				if dir == "." && !allowedLibs[p] {
					t.Errorf("package proof imports %q; it may use only the shared proof library's encoding, signature and schema packages", p)
				}
				queue = append(queue, filepath.Join("..", "..", strings.TrimPrefix(p, module)))
			}
		}
	}
	if len(seen) < 5 {
		t.Fatalf("walked only %d packages; the test is not looking in the right place", len(seen))
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
	"Header": true, "SensorHealth": true, "Readings": true, "SecurityCenter": true,
	"Defender": true, "EDR": true, "EDRAgent": true, "Version": true, "Schedule": true,
	"Tripwire": true, "TripCounts": true,
}

// vocabularyTypes must be small unsigned integers, never strings.
var vocabularyTypes = map[string]bool{
	"Availability": true, "Toggle": true, "BlocklistState": true, "VolumeProtection": true,
	"RunningMode": true, "Vendor": true, "KeyProtection": true,
	"TripReason": true, "TripWindow": true, "TripBucket": true,
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
