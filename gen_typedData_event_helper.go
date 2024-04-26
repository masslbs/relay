// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

// Generated from network-schema:typedData.json at version v2 (edd1dde077de3346e9876d917781ed9e94563fd3).
//lint:file-ignore U1000 Ignore all unused code, it's generated

package main

import "fmt"

func (evt *Event) typeAndTypedDataMap() (string, map[string]any) {
	var unwrapped typedDataMaper
	var name string
	switch union := evt.Union.(type) {

	case *Event_CartAbandoned:
		name = "CartAbandoned"
		unwrapped = union.CartAbandoned
	case *Event_CartFinalized:
		name = "CartFinalized"
		unwrapped = union.CartFinalized
	case *Event_ChangeCart:
		name = "ChangeCart"
		unwrapped = union.ChangeCart
	case *Event_ChangeStock:
		name = "ChangeStock"
		unwrapped = union.ChangeStock
	case *Event_CreateCart:
		name = "CreateCart"
		unwrapped = union.CreateCart
	case *Event_CreateItem:
		name = "CreateItem"
		unwrapped = union.CreateItem
	case *Event_CreateTag:
		name = "CreateTag"
		unwrapped = union.CreateTag
	case *Event_NewKeyCard:
		name = "NewKeyCard"
		unwrapped = union.NewKeyCard
	case *Event_StoreManifest:
		name = "StoreManifest"
		unwrapped = union.StoreManifest
	case *Event_UpdateItem:
		name = "UpdateItem"
		unwrapped = union.UpdateItem
	case *Event_UpdateStoreManifest:
		name = "UpdateStoreManifest"
		unwrapped = union.UpdateStoreManifest
	case *Event_UpdateTag:
		name = "UpdateTag"
		unwrapped = union.UpdateTag
	default:
		panic(fmt.Sprintf("unknown event type: %T", evt.Union))
	}
	return name, unwrapped.typedDataMap()
}
