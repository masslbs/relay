// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

// Generated from network-schema:typedData.json at version v2 (e01b832f8fc10dbcd91d87288052157c02b7488f).
//lint:file-ignore U1000 Ignore all unused code, it's generated

package main

import "fmt"

func (evt *ShopEvent) typeAndTypedDataMap() (string, map[string]any) {
	var unwrapped typedDataMaper
	var name string
	switch union := evt.Union.(type) {

	case *ShopEvent_ChangeStock:
		name = "ChangeStock"
		unwrapped = union.ChangeStock
	case *ShopEvent_CreateItem:
		name = "CreateItem"
		unwrapped = union.CreateItem
	case *ShopEvent_CreateOrder:
		name = "CreateOrder"
		unwrapped = union.CreateOrder
	case *ShopEvent_CreateTag:
		name = "CreateTag"
		unwrapped = union.CreateTag
	case *ShopEvent_NewKeyCard:
		name = "NewKeyCard"
		unwrapped = union.NewKeyCard
	case *ShopEvent_ShopManifest:
		name = "ShopManifest"
		unwrapped = union.ShopManifest
	case *ShopEvent_UpdateItem:
		name = "UpdateItem"
		unwrapped = union.UpdateItem
	case *ShopEvent_UpdateOrder:
		name = "UpdateOrder"
		unwrapped = union.UpdateOrder
	case *ShopEvent_UpdateShopManifest:
		name = "UpdateShopManifest"
		unwrapped = union.UpdateShopManifest
	case *ShopEvent_UpdateTag:
		name = "UpdateTag"
		unwrapped = union.UpdateTag
	default:
		panic(fmt.Sprintf("unknown event type: %T", evt.Union))
	}
	return name, unwrapped.typedDataMap()
}
