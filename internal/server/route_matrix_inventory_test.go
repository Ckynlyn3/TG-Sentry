package server

import (
	"aegishook/internal/core"
	"bytes"
	"encoding/json"
	"go/ast"
	"go/constant"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// ServeMux has no public iterator. Type-check the actual package and inspect its
// source registrations instead of reflecting on private runtime fields.
func TestRouteMatrixCoversEveryRegisteredRoute(t *testing.T) {
	fset, files, info := routeMatrixPackage(t)
	bindings, ranges, mutable := routePatternBindings(files, info)
	registrations := 0
	for _, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "HandleFunc" && sel.Sel.Name != "Handle") {
				return true
			}
			registrations++
			patterns := routePatternValues(call.Args[0], info, bindings, ranges, mutable, map[types.Object]bool{})
			pos := fset.Position(call.Pos())
			if len(patterns) == 0 {
				t.Errorf("%s:%d: unresolvable mux registration pattern", filepath.Base(pos.Filename), pos.Line)
			}
			for _, pattern := range patterns {
				if _, ok := routeRoles[constant.StringVal(pattern)]; !ok {
					t.Errorf("registered route absent from matrix: %s (%s:%d)", constant.StringVal(pattern), filepath.Base(pos.Filename), pos.Line)
				}
			}
			return true
		})
	}
	if registrations == 0 {
		t.Fatal("no mux registrations inspected")
	}
	if routeRoles["GET /api/v1/session-summaries"] != core.RoleReadOnly {
		t.Fatal("#16 session-summaries contract missing")
	}
}

// go list supplies build-selected files and module-aware export data; the parser,
// importer and checker are all stdlib. See pkg.go.dev/go/types#Info.Types and
// pkg.go.dev/go/importer#ForCompiler (lookup is required for module-aware imports).
func routeMatrixPackage(t *testing.T) (*token.FileSet, []*ast.File, *types.Info) {
	t.Helper()
	cmd := exec.Command("go", "list", "-deps", "-export", "-json", ".")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("load route package: %v\n%s", err, &stderr)
	}
	type listedPackage struct {
		ImportPath, Dir, Export string
		GoFiles, CgoFiles       []string
	}
	var pkg listedPackage
	exports := map[string]string{}
	decoder := json.NewDecoder(bytes.NewReader(out))
	for {
		var next listedPackage
		if err := decoder.Decode(&next); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		exports[next.ImportPath] = next.Export
		pkg = next
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, name := range append(pkg.GoFiles, pkg.CgoFiles...) {
		file, err := parser.ParseFile(fset, filepath.Join(pkg.Dir, name), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
	}
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}}
	conf := types.Config{Importer: importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		return os.Open(exports[path])
	})}
	if _, err := conf.Check(pkg.ImportPath, fset, files, info); err != nil {
		t.Fatalf("type-check route package: %v", err)
	}
	return fset, files, info
}

// ponytail: only immutable initializers and composite-literal string ranges are
// modeled. Reassignment/address-taking or other runtime values fail closed;
// extend the supported syntax explicitly if routing ever needs more data flow.
func routePatternBindings(files []*ast.File, info *types.Info) (map[types.Object]ast.Expr, map[types.Object]*ast.CompositeLit, map[types.Object]bool) {
	bindings := map[types.Object]ast.Expr{}
	ranges := map[types.Object]*ast.CompositeLit{}
	mutable := map[types.Object]bool{}
	for _, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				for i, lhs := range n.Lhs {
					if id, ok := lhs.(*ast.Ident); ok {
						if obj := info.Defs[id]; obj != nil && len(n.Lhs) == len(n.Rhs) {
							bindings[obj] = n.Rhs[i]
						} else {
							mutable[info.ObjectOf(id)] = true
						}
					}
				}
			case *ast.ValueSpec:
				if len(n.Names) == len(n.Values) {
					for i, id := range n.Names {
						bindings[info.Defs[id]] = n.Values[i]
					}
				}
			case *ast.RangeStmt:
				if id, ok := n.Value.(*ast.Ident); ok {
					if obj := info.Defs[id]; obj != nil {
						ranges[obj], _ = n.X.(*ast.CompositeLit)
					} else {
						mutable[info.ObjectOf(id)] = true
					}
				}
			case *ast.UnaryExpr:
				if n.Op == token.AND {
					if id, ok := ast.Unparen(n.X).(*ast.Ident); ok {
						mutable[info.ObjectOf(id)] = true
					}
				}
			}
			return true
		})
	}
	return bindings, ranges, mutable
}

func routePatternValues(expr ast.Expr, info *types.Info, bindings map[types.Object]ast.Expr, ranges map[types.Object]*ast.CompositeLit, mutable, visiting map[types.Object]bool) []constant.Value {
	if value := info.Types[expr].Value; value != nil && value.Kind() == constant.String {
		return []constant.Value{value}
	}
	switch expr := expr.(type) {
	case *ast.ParenExpr:
		return routePatternValues(expr.X, info, bindings, ranges, mutable, visiting)
	case *ast.Ident:
		obj := info.ObjectOf(expr)
		if mutable[obj] || visiting[obj] {
			return nil
		}
		visiting[obj] = true
		defer delete(visiting, obj)
		if init := bindings[obj]; init != nil {
			return routePatternValues(init, info, bindings, ranges, mutable, visiting)
		}
		if literal := ranges[obj]; literal != nil {
			var values []constant.Value
			for _, elt := range literal.Elts {
				resolved := routePatternValues(elt, info, bindings, ranges, mutable, visiting)
				if len(resolved) == 0 {
					return nil
				}
				values = append(values, resolved...)
			}
			return values
		}
	case *ast.BinaryExpr:
		if expr.Op == token.ADD {
			left := routePatternValues(expr.X, info, bindings, ranges, mutable, visiting)
			right := routePatternValues(expr.Y, info, bindings, ranges, mutable, visiting)
			var values []constant.Value
			for _, l := range left {
				for _, r := range right {
					values = append(values, constant.BinaryOp(l, token.ADD, r))
				}
			}
			return values
		}
	}
	return nil
}
