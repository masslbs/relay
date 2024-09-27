// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

// Generated from network-schema. Files: constants.txt at version v3 (2125585d9649f1fb04379972d958345b093d4da4)
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
