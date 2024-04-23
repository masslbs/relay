// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: MIT

//go:build ignore
// +build ignore

// TODO: add sql unmarshling code for UpdateManifest_ManifestField && UpdateItem_ItemField

package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"unicode"
)

type TypeMapping struct {
	PascalName string
	Num        int
	Type       string
}

func (tm TypeMapping) GetResponseName() string {
	return strings.Replace(tm.PascalName, "Request", "Response", 1)
}

type OpTypeMapping struct {
	Name string
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <schema-version> <schema-commit>\n", os.Args[0])
		os.Exit(1)
		return
	}
	networkSchemaVersion := os.Args[1]
	commitHash := os.Args[2]

	tmplString := `// Generated from massmarket-network-schema:network/encoding.txt at network v{{.NetworkSchemaVersion}} ({{.CommitHash}})
//lint:file-ignore U1000 Ignore all unused code, it's generated

package main

import (
  "reflect"
)

const schemaVersion = {{.NetworkSchemaVersion}}

var typesNumToType = make(map[uint8]reflect.Type)
var typesTypePointerToNum = make(map[reflect.Type]uint8)

func networkMessage(typeNum uint8, typeInstance interface{}) {
  typeType := reflect.TypeOf(typeInstance)
  typeTypePointer := reflect.PtrTo(typeType)
  typesNumToType[typeNum] = typeType
  typesTypePointerToNum[typeTypePointer] = typeNum
}

{{range .Mappings}}
const type{{.PascalName}} = {{.Num}}

func init() {
  networkMessage({{.Num}}, {{.PascalName}}{})
}
func (r *{{.PascalName}}) getRequestID() requestID {
  return r.RequestId
}
{{if eq .Type "Request"}}
func (r *{{.PascalName}}) response(err *Error) Message {
  return &{{.GetResponseName}}{RequestId: r.RequestId, Error: err}
}
{{else if eq .Type "Response"}}
func (r *{{.GetResponseName}}) getError() *Error {
  return r.Error
}
{{end}}{{end}}

{{range .Operations}}
func (op *{{.Name}}) getSessionID() requestID {
  return op.sessionID
}
func (op *{{.Name}}) setErr(err *Error) {
  op.err = err
}
{{end}}
`

	tmpl, err := template.New("code").Parse(tmplString)
	checkError(err)

	mappings := processEncodingFile(filepath.Join(os.Getenv("MASS_SCHEMA"), "encoding.txt"))
	operations := processGoFile("main.go")

	// Execute templating
	err = tmpl.Execute(os.Stdout, map[string]interface{}{
		"NetworkSchemaVersion": networkSchemaVersion,
		"CommitHash":           commitHash,
		"Mappings":             mappings,
		"Operations":           operations,
	})
	checkError(err)
}

func processEncodingFile(filePath string) []TypeMapping {
	file, err := os.Open(filePath)
	checkError(err)
	defer file.Close()

	var mappings []TypeMapping
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		tokens := strings.Fields(line)
		typeName := upperCaseFirstLetter(tokens[0])
		typeNum, err := strconv.Atoi(tokens[1])
		checkError(err)
		typeKind := getTypeKind(tokens[0])

		mappings = append(mappings, TypeMapping{PascalName: typeName, Num: typeNum, Type: typeKind})
	}

	return mappings
}

func processGoFile(filePath string) []OpTypeMapping {
	file, err := os.Open(filePath)
	checkError(err)
	defer file.Close()

	var mappings []OpTypeMapping
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Op struct") {
			opName := strings.Trim(strings.Split(line, " ")[1], "{}")
			if strings.HasSuffix(opName, "InternalOp") {
				continue
			}
			mappings = append(mappings, OpTypeMapping{Name: opName})
		}
	}

	return mappings
}

func upperCaseFirstLetter(s string) string {
	r := []rune(s)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}

func getTypeKind(s string) string {
	if strings.HasSuffix(s, "Request") {
		return "Request"
	} else if strings.HasSuffix(s, "Response") {
		return "Response"
	} else {
		return ""
	}
}

func checkError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
