// SPDX-FileCopyrightText: 2025 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

// Generated from network-schema. Files: constants.txt at version v4 (4bbb6a36b5db40469b3d7427bfd8eaeddc412e0b)
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
	eventTypeManifest  eventType = "Manifest"
	eventTypeListings  eventType = "Listings"
	eventTypeTags      eventType = "Tags"
	eventTypeOrders    eventType = "Orders"
	eventTypeInventory eventType = "Inventory"
	eventTypeAccounts  eventType = "Accounts"
)
