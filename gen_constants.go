// SPDX-FileCopyrightText: 2025 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

// Generated from network-schema. Files: constants.txt at version v4 (e64f5b35644da55a6b17f6601bd176f62a9393a0)
//lint:file-ignore U1000 Ignore all unused code, it's generated

package main

// file: constants.txt
const limitMaxInRequests = 1024
const limitMaxInBatchSize = 64
const limitMaxOutRequests = 1024
const limitMaxOutBatchSize = 64

// file: db/schema.sql
type eventType string

const (
	eventTypeInvalid   eventType = "invalid"
	eventTypeManifest  eventType = "manifest"
	eventTypeListing   eventType = "listing"
	eventTypeTag       eventType = "tag"
	eventTypeOrder     eventType = "order"
	eventTypeInventory eventType = "inventory"
	eventTypeAccount   eventType = "account"
)
