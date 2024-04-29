// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

// Generated from network-schema:typedData.json at version v2 (2e3d27ecfc5a19681af710e2ec288709139e19bc).
//lint:file-ignore U1000 Ignore all unused code, it's generated

package main

import "fmt"

func (evt *StoreEvent) typeAndTypedDataMap() (string, map[string]any) {
	var unwrapped typedDataMaper
	var name string
	switch union := evt.Union.(type) {

	case *StoreEvent_CartAbandoned:
		name = "CartAbandoned"
		unwrapped = union.CartAbandoned
	case *StoreEvent_CartFinalized:
		name = "CartFinalized"
		unwrapped = union.CartFinalized
	case *StoreEvent_ChangeCart:
		name = "ChangeCart"
		unwrapped = union.ChangeCart
	case *StoreEvent_ChangeStock:
		name = "ChangeStock"
		unwrapped = union.ChangeStock
	case *StoreEvent_CreateCart:
		name = "CreateCart"
		unwrapped = union.CreateCart
	case *StoreEvent_CreateItem:
		name = "CreateItem"
		unwrapped = union.CreateItem
	case *StoreEvent_CreateTag:
		name = "CreateTag"
		unwrapped = union.CreateTag
	case *StoreEvent_NewKeyCard:
		name = "NewKeyCard"
		unwrapped = union.NewKeyCard
	case *StoreEvent_StoreManifest:
		name = "StoreManifest"
		unwrapped = union.StoreManifest
	case *StoreEvent_UpdateItem:
		name = "UpdateItem"
		unwrapped = union.UpdateItem
	case *StoreEvent_UpdateStoreManifest:
		name = "UpdateStoreManifest"
		unwrapped = union.UpdateStoreManifest
	case *StoreEvent_UpdateTag:
		name = "UpdateTag"
		unwrapped = union.UpdateTag
	default:
		panic(fmt.Sprintf("unknown event type: %T", evt.Union))
	}
	return name, unwrapped.typedDataMap()
}
