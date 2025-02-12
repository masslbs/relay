// SPDX-FileCopyrightText: 2024 - 2025 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build ignore
// +build ignore

package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type Constants struct {
	Name  string
	Value string
}

type FromSQL struct {
	EventTypes []EventTypes
}

type EventTypes struct {
	Name  string
	Value string
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <schema-version>\n", os.Args[0])
		os.Exit(1)
		return
	}
	version := os.Args[1]
	date := time.Now().Format("2006-01-02")

	headerTmpl := `// Generated from network-schema. Files: constants.txt at version v{{.Version}} ({{.Date}})
//lint:file-ignore U1000 Ignore all unused code, it's generated

package main

// file: constants.txt
{{range .Constants}}const {{.Name}} = {{.Value}}
{{end}}
// file: db/schema.sql
type eventType string
const (
	eventTypeInvalid eventType = "invalid"
	{{range .EventTypes}}eventType{{.Name}} eventType = "{{.Value}}"
	{{end}}
)
`
	constantsTxt := processFile(filepath.Join(os.Getenv("MASS_SCHEMA"), "constants.txt"))
	fromSQL := processSchemaSQL("db/schema.sql")

	tmpl, err := template.New("code").Parse(headerTmpl)
	if err != nil {
		log.Fatal(err)
	}

	err = tmpl.Execute(os.Stdout, map[string]interface{}{
		"Version":    version,
		"Date":       date,
		"Constants":  constantsTxt,
		"EventTypes": fromSQL.EventTypes,
	})

	if err != nil {
		log.Fatal(err)
	}
}

func processFile(filePath string) []Constants {
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	var constants []Constants
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		tokens := strings.Fields(line)
		constants = append(constants, Constants{Name: tokens[0], Value: tokens[1]})
	}
	if scanner.Err() != nil {
		log.Fatal(scanner.Err())
	}

	return constants
}

// processSchemaSQL processes schema.sql and returns enum values
func processSchemaSQL(filePath string) FromSQL {
	capitalizer := cases.Title(language.English, cases.NoLower)

	file, err := os.Open(filePath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	var eventTypes []EventTypes
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		prefix := "create type eventTypeEnum as enum ("
		if strings.HasPrefix(line, prefix) {
			trimmed := strings.Trim(line, prefix)
			types := strings.Split(trimmed, ", ")
			for _, eventType := range types {
				eventType = strings.Split(eventType, "'")[1]
				eventTypes = append(eventTypes, EventTypes{
					Value: eventType,
					Name:  capitalizer.String(eventType),
				})
			}
		}
	}
	if scanner.Err() != nil {
		log.Fatal(scanner.Err())
	}

	return FromSQL{
		EventTypes: eventTypes,
	}
}
