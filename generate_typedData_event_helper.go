// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: MIT

//go:build ignore
// +build ignore

package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"text/template"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <schema-version> <schema-commit>\n", os.Args[0])
		os.Exit(1)
		return
	}

	version := os.Args[1]
	commit := os.Args[2]

	headerTmpl := `// Generated from network-schema:typedData.json at version v{{.SchemaVersion}} ({{.SchemaCommit}}).
//lint:file-ignore U1000 Ignore all unused code, it's generated

package main

import "fmt"

func (evt *Event) typeAndTypedDataMap() (string, map[string]any) {
	var unwrapped typedDataMaper
	var name string
	switch union := evt.Union.(type) {
	{{range $wrapped, $evtName := .Types}}
	case *{{$wrapped}}:
		name = "{{$evtName}}"
		unwrapped = union.{{$evtName}}{{end}}
	default:
		panic(fmt.Sprintf("unknown event type: %T", evt.Union))
	}
	return name, unwrapped.typedDataMap()
}
`

	tmpl, err := template.New("code").Parse(headerTmpl)
	check(err)

	err = tmpl.Execute(os.Stdout, map[string]any{
		"Types":         GetAllStructs(),
		"SchemaVersion": version,
		"SchemaCommit":  commit,
	})
	check(err)
}

func GetAllStructs() map[string]string {
	fset := token.NewFileSet()

	f, err := parser.ParseFile(fset, "gen_network_schema.pb.go", nil, parser.SkipObjectResolution)
	check(err)

	var sf eventTypeFinder
	sf.structs = make(map[string]string)
	ast.Walk(sf, f)
	return sf.structs
}

type eventTypeFinder struct {
	structs map[string]string
}

func (sf eventTypeFinder) Visit(n ast.Node) ast.Visitor {
	if n == nil {
		return nil
	}
	switch tv := n.(type) {
	case *ast.GenDecl:
		if tv.Tok == token.TYPE {
			for _, spec := range tv.Specs {
				spec := spec.(*ast.TypeSpec)
				typeName := spec.Name.Name
				if strings.HasPrefix(typeName, "Event_") {
					sf.structs[typeName] = strings.TrimPrefix(typeName, "Event_")
				}
			}
		}
	}
	return sf
}
