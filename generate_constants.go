// SPDX-FileCopyrightText: 2024 Mass Labs
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

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type Constants struct {
	Name  string
	Value string
}

type FromSQL struct {
	EventTypes   []EventTypes
	ManifestEnum []EnumValue
	ItemEnum     []EnumValue
}

type EventTypes struct {
	Name  string
	Value string
}

type EnumValue struct {
	Number int
	Value  string
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <schema-version> <schema-commit>\n", os.Args[0])
		os.Exit(1)
		return
	}
	version := os.Args[1]
	date := os.Args[2]

	headerTmpl := `// Generated from network-schema. Files: constants.txt at version v{{.Version}} ({{.Date}})
//lint:file-ignore U1000 Ignore all unused code, it's generated

package main

import (
	"database/sql/driver"
	"fmt"
)

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

// Value implements the driver.Valuer interface.
func (mv UpdateStoreManifest_ManifestField) Value() (driver.Value, error) {
	switch mv {
		// TODO: use UpdateManifest_MANIFEST_FIELD_* instead of numbers
	{{range .ManifestEnum}}
	case {{.Number}}:
		return "{{.Value}}", nil{{end}}
	}
	return nil, fmt.Errorf("unknown UpdateStoreManifest_ManifestField %q", mv)
}

// Scan implements the sql.Scanner interface
func (mv *UpdateStoreManifest_ManifestField) Scan(src interface{}) error {
	tv, ok := src.(string)
	if !ok {
		return fmt.Errorf("cannot convert %T to string", src)
	}
	switch tv {
	// TODO: use UpdateManifest_MANIFEST_FIELD_* instead of numbers
	{{range .ManifestEnum}}
	case "{{.Value}}":
		*mv = {{.Number}}{{end}}
	default:
		return fmt.Errorf("unknown database enum value %q", tv)
	}
	return nil
}

// Value implements the driver.Valuer interface.
func (mv UpdateItem_ItemField) Value() (driver.Value, error) {
	switch mv {
		// TODO: use UpdateItem_ITEM_FIELD* instead of numbers
	{{range .ItemEnum}}
	case {{.Number}}:
		return "{{.Value}}", nil{{end}}
	}
	return nil, fmt.Errorf("unknown UpdateItem_ItemField %q", mv)
}

// Scan implements the sql.Scanner interface
func (mv *UpdateItem_ItemField) Scan(src interface{}) error {
	tv, ok := src.(string)
	if !ok {
		return fmt.Errorf("cannot convert %T to string", src)
	}
	switch tv {
	// TODO: use UpdateItem_ITEM_FIELD* instead of numbers
	{{range .ItemEnum}}
	case "{{.Value}}":
		*mv = {{.Number}}{{end}}
	default:
		return fmt.Errorf("unknown database enum value %q", tv)
	}
	return nil
}

`
	constantsTxt := processFile(filepath.Join(os.Getenv("MASS_SCHEMA"), "constants.txt"))
	fromSQL := processSchemaSQL("db/schema.sql")

	tmpl, err := template.New("code").Parse(headerTmpl)
	if err != nil {
		log.Fatal(err)
	}

	err = tmpl.Execute(os.Stdout, map[string]interface{}{
		"Version":      version,
		"Date":         date,
		"Constants":    constantsTxt,
		"EventTypes":   fromSQL.EventTypes,
		"ManifestEnum": fromSQL.ManifestEnum,
		"ItemEnum":     fromSQL.ItemEnum,
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
	var manifestEnums []EnumValue
	var itemFieldEnum []EnumValue
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

		prefix = "create type manifestFieldEnum as enum ("
		num := 1
		if strings.HasPrefix(line, prefix) {
			trimmed := strings.Trim(line, prefix)
			fields := strings.Split(trimmed, ", ")
			for _, field := range fields {
				manifestEnums = append(manifestEnums, EnumValue{
					Number: num,
					Value:  strings.Split(field, "'")[1],
				})
				num++
			}
		}

		prefix = "create type itemFieldEnum as enum ("
		num = 1
		if strings.HasPrefix(line, prefix) {
			trimmed := strings.Trim(line, prefix)
			fields := strings.Split(trimmed, ", ")
			for _, field := range fields {
				itemFieldEnum = append(itemFieldEnum, EnumValue{
					Number: num,
					Value:  strings.Split(field, "'")[1],
				})
				num++
			}
		}
	}
	if scanner.Err() != nil {
		log.Fatal(scanner.Err())
	}

	return FromSQL{
		EventTypes:   eventTypes,
		ManifestEnum: manifestEnums,
		ItemEnum:     itemFieldEnum,
	}
}
