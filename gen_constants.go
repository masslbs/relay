// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

// Generated from network-schema. Files: constants.txt at version v2 (7add0e4a0f4842870b3fb38386705a946292d017)
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
	eventTypeInvalid            eventType = "invalid"
	eventTypeShopManifest       eventType = "shopManifest"
	eventTypeUpdateShopManifest eventType = "updateShopManifest"
	eventTypeCreateItem         eventType = "createItem"
	eventTypeUpdateItem         eventType = "updateItem"
	eventTypeCreateTag          eventType = "createTag"
	eventTypeUpdateTag          eventType = "updateTag"
	eventTypeCreateOrder        eventType = "createOrder"
	eventTypeUpdateOrder        eventType = "updateOrder"
	eventTypeChangeStock        eventType = "changeStock"
	eventTypeNewKeyCard         eventType = "newKeyCard"
)
