// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

// Generated from network-schema:typedData.json at version v2 (b16798f77d65153596d1932a06753cccae4bbc1e).
//lint:file-ignore U1000 Ignore all unused code, it's generated

package main

import "fmt"

func (evt *StoreEvent) typeAndTypedDataMap() (string, map[string]any) {
	var unwrapped typedDataMaper
	var name string
	switch union := evt.Union.(type) {

	case *StoreEvent_ChangeStock:
		name = "ChangeStock"
		unwrapped = union.ChangeStock
	case *StoreEvent_CreateItem:
		name = "CreateItem"
		unwrapped = union.CreateItem
	case *StoreEvent_CreateOrder:
		name = "CreateOrder"
		unwrapped = union.CreateOrder
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
	case *StoreEvent_UpdateOrder:
		name = "UpdateOrder"
		unwrapped = union.UpdateOrder
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
