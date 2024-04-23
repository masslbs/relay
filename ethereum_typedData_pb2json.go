// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"math/big"
)

// TODO: this code could be generated at some point

func (evt *StoreManifest) typedDataMap() map[string]any {
	return map[string]any{
		"event_id":         evt.EventId,
		"store_token_id":   evt.StoreTokenId,
		"domain":           evt.Domain,
		"published_tag_id": evt.PublishedTagId,
	}
}

func (evt *UpdateManifest) typedDataMap() map[string]any {
	m := map[string]any{
		"event_id": evt.EventId,
		"field":    big.NewInt(int64(evt.Field)),
	}
	switch evt.Field {
	case UpdateManifest_MANIFEST_FIELD_DOMAIN:
		m["string"] = evt.Value.(*UpdateManifest_String_).String_
	case UpdateManifest_MANIFEST_FIELD_PUBLISHED_TAG:
		m["tag_id"] = evt.Value.(*UpdateManifest_TagId).TagId
	case UpdateManifest_MANIFEST_FIELD_ADD_ERC20:
		def := evt.Value.(*UpdateManifest_Erc20Addr).Erc20Addr
		m["erc20_addr"] = def
	case UpdateManifest_MANIFEST_FIELD_REMOVE_ERC20:
		def := evt.Value.(*UpdateManifest_Erc20Addr).Erc20Addr
		m["erc20_addr"] = def
	default:
		panic(fmt.Sprintf("unknown field: %v", evt.Field))
	}
	return m
}

func (evt *CreateItem) typedDataMap() map[string]any {
	return map[string]any{
		"event_id": evt.EventId,
		"price":    evt.Price,
		"metadata": evt.Metadata,
	}
}

func (evt *UpdateItem) typedDataMap() map[string]any {
	m := map[string]any{
		"event_id": evt.EventId,
		"item_id":  evt.ItemId,
		"field":    big.NewInt(int64(evt.Field)),
	}
	switch evt.Field {
	case UpdateItem_ITEM_FIELD_PRICE:
		price := evt.Value.(*UpdateItem_Price).Price
		m["price"] = price
	case UpdateItem_ITEM_FIELD_METADATA:
		m["metadata"] = evt.Value.(*UpdateItem_Metadata).Metadata
	default:
		panic(fmt.Sprintf("unknown field: %v", evt.Field))
	}
	return m
}

func (evt *CreateTag) typedDataMap() map[string]any {
	return map[string]any{
		"event_id": evt.EventId,
		"name":     evt.Name,
	}
}

func (evt *AddToTag) typedDataMap() map[string]any {
	return map[string]any{
		"event_id": evt.EventId,
		"tag_id":   evt.TagId,
		"item_id":  evt.ItemId,
	}
}

func (evt *RemoveFromTag) typedDataMap() map[string]any {
	return map[string]any{
		"event_id": evt.EventId,
		"tag_id":   evt.TagId,
		"item_id":  evt.ItemId,
	}
}

func (evt *RenameTag) typedDataMap() map[string]any {
	return map[string]any{
		"event_id": evt.EventId,
		"tag_id":   evt.TagId,
		"name":     evt.Name,
	}
}

func (evt *DeleteTag) typedDataMap() map[string]any {
	return map[string]any{
		"event_id": evt.EventId,
		"tag_id":   evt.TagId,
	}
}

func (evt *CreateCart) typedDataMap() map[string]any {
	return map[string]any{
		"event_id": evt.EventId,
	}
}

func (evt *ChangeCart) typedDataMap() map[string]any {
	return map[string]any{
		"event_id": evt.EventId,
		"cart_id":  evt.CartId,
		"item_id":  evt.ItemId,
		"quantity": big.NewInt(int64(evt.Quantity)),
	}
}

func (evt *CartFinalized) typedDataMap() map[string]any {
	m := map[string]any{
		"event_id":        evt.EventId,
		"cart_id":         evt.CartId,
		"purchase_addr":   evt.PurchaseAddr,
		"sub_total":       evt.SubTotal,
		"sales_tax":       evt.SalesTax,
		"total":           evt.Total,
		"total_in_crypto": evt.TotalInCrypto,
	}
	if len(evt.Erc20Addr) == 20 {
		m["erc20_addr"] = evt.Erc20Addr
	}
	return m
}

func (evt *CartAbandoned) typedDataMap() map[string]any {
	return map[string]any{
		"event_id": evt.EventId,
		"cart_id":  evt.CartId,
	}
}

func (evt *ChangeStock) typedDataMap() map[string]any {
	bigDiffs := make([]*big.Int, len(evt.Diffs))
	for i, diff := range evt.Diffs {
		bigDiffs[i] = big.NewInt(int64(diff))
	}
	return map[string]any{
		"event_id": evt.EventId,
		"cart_id":  evt.CartId,
		"tx_hash":  evt.TxHash,
		"item_ids": evt.ItemIds,
		"diffs":    bigDiffs,
	}
}

func (evt *NewKeyCard) typedDataMap() map[string]any {
	return map[string]any{
		"event_id":         evt.EventId,
		"user_wallet_addr": evt.UserWalletAddr,
		"card_public_key":  evt.CardPublicKey,
	}
}
