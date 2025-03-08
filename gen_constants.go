// SPDX-FileCopyrightText: 2025 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

// Generated from network-schema. Files: constants.txt at version v4 (a3043c7d50595372e3a607fd237e834d1ca18a8f)
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
