// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

// Generated from network-schema. Files: constants.txt at version v2 (2e3d27ecfc5a19681af710e2ec288709139e19bc)
//lint:file-ignore U1000 Ignore all unused code, it's generated

package main

import (
	"database/sql/driver"
	"fmt"
)

// file: constants.txt
const limitMaxInRequests = 1024
const limitMaxInBatchSize = 64
const limitMaxOutRequests = 1024
const limitMaxOutBatchSize = 64

// file: db/schema.sql
type eventType string

const (
	eventTypeInvalid             eventType = "invalid"
	eventTypeStoreManifest       eventType = "storeManifest"
	eventTypeUpdateStoreManifest eventType = "updateStoreManifest"
	eventTypeCreateItem          eventType = "createItem"
	eventTypeUpdateItem          eventType = "updateItem"
	eventTypeCreateTag           eventType = "createTag"
	eventTypeUpdateTag           eventType = "updateTag"
	eventTypeCreateCart          eventType = "createCart"
	eventTypeChangeCart          eventType = "changeCart"
	eventTypeCartFinalized       eventType = "cartFinalized"
	eventTypeCartAbandoned       eventType = "cartAbandoned"
	eventTypeChangeStock         eventType = "changeStock"
	eventTypeNewKeyCard          eventType = "newKeyCard"
)

// Value implements the driver.Valuer interface.
func (mv UpdateStoreManifest_ManifestField) Value() (driver.Value, error) {
	switch mv {
	// TODO: use UpdateManifest_MANIFEST_FIELD_* instead of numbers

	case 1:
		return "domain", nil
	case 2:
		return "paymentAddr", nil
	case 3:
		return "publishedTagId", nil
	case 4:
		return "addErc20", nil
	case 5:
		return "removeErc20", nil
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

	case "domain":
		*mv = 1
	case "paymentAddr":
		*mv = 2
	case "publishedTagId":
		*mv = 3
	case "addErc20":
		*mv = 4
	case "removeErc20":
		*mv = 5
	default:
		return fmt.Errorf("unknown database enum value %q", tv)
	}
	return nil
}

// Value implements the driver.Valuer interface.
func (mv UpdateItem_ItemField) Value() (driver.Value, error) {
	switch mv {
	// TODO: use UpdateItem_ITEM_FIELD* instead of numbers

	case 1:
		return "price", nil
	case 2:
		return "metadata", nil
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

	case "price":
		*mv = 1
	case "metadata":
		*mv = 2
	default:
		return fmt.Errorf("unknown database enum value %q", tv)
	}
	return nil
}
