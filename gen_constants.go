// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

// Generated from network-schema. Files: constants.txt at version v3 (5ac728e84c6ed53e4aea4c58dee94ad539169b0b)
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
	eventTypeInvalid         eventType = "invalid"
	eventTypeManifest        eventType = "manifest"
	eventTypeUpdateManifest  eventType = "updateManifest"
	eventTypeListing         eventType = "listing"
	eventTypeUpdateListing   eventType = "updateListing"
	eventTypeTag             eventType = "tag"
	eventTypeUpdateTag       eventType = "updateTag"
	eventTypeCreateOrder     eventType = "createOrder"
	eventTypeUpdateOrder     eventType = "updateOrder"
	eventTypeChangeInventory eventType = "changeInventory"
	eventTypeAccount         eventType = "account"
)
