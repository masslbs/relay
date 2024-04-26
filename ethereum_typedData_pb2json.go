// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"math/big"
)

// TODO: this code could be generated at some point

func (evt *NewKeyCard) typedDataMap() map[string]any {
	return map[string]any{
		"event_id":         evt.EventId,
		"user_wallet_addr": evt.UserWalletAddr,
		"card_public_key":  evt.CardPublicKey,
		"is_guest":         evt.IsGuest,
	}
}

func (evt *StoreManifest) typedDataMap() map[string]any {
	return map[string]any{
		"event_id":         evt.EventId,
		"store_token_id":   evt.StoreTokenId,
		"domain":           evt.Domain,
		"published_tag_id": evt.PublishedTagId,
	}
}

func (evt *UpdateStoreManifest) typedDataMap() map[string]any {
	m := map[string]any{
		"event_id": evt.EventId,
		"field":    big.NewInt(int64(evt.Field)),
	}
	switch evt.Field {
	case UpdateStoreManifest_MANIFEST_FIELD_DOMAIN:
		m["string"] = evt.Value.(*UpdateStoreManifest_String_).String_
	case UpdateStoreManifest_MANIFEST_FIELD_PUBLISHED_TAG:
		m["tag_id"] = evt.Value.(*UpdateStoreManifest_TagId).TagId
	case UpdateStoreManifest_MANIFEST_FIELD_ADD_ERC20:
		def := evt.Value.(*UpdateStoreManifest_Erc20Addr).Erc20Addr
		m["erc20_addr"] = def
	case UpdateStoreManifest_MANIFEST_FIELD_REMOVE_ERC20:
		def := evt.Value.(*UpdateStoreManifest_Erc20Addr).Erc20Addr
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

func (evt *UpdateTag) typedDataMap() map[string]any {
	m := map[string]any{
		"event_id": evt.EventId,
		"tag_id":   evt.TagId,
		"action":   big.NewInt(int64(evt.Action)),
	}
	switch evt.Action {
	case UpdateTag_TAG_ACTION_ADD_ITEM:
		fallthrough
	case UpdateTag_TAG_ACTION_REMOVE_ITEM:
		itemID := evt.Value.(*UpdateTag_ItemId).ItemId
		m["item_id"] = itemID
	case UpdateTag_TAG_ACTION_RENAME:
		m["new_name"] = evt.Value.(*UpdateTag_NewName).NewName
	case UpdateTag_TAG_ACTION_DELETE_TAG:
		m["delete"] = true
	default:
		panic(fmt.Sprintf("unknown action: %v", evt.Action))
	}
	return m
}

func (evt *CreateOrder) typedDataMap() map[string]any {
	return map[string]any{
		"event_id": evt.EventId,
	}
}

func (evt *UpdateOrder) typedDataMap() map[string]any {
	m := map[string]any{
		"event_id": evt.EventId,
		"order_id": evt.OrderId,
	}
	switch tv := evt.Action.(type) {
	case *UpdateOrder_ChangeItems_:
		ci := tv.ChangeItems
		m["change_items"] = map[string]any{
			"item_id":  ci.ItemId,
			"quantity": big.NewInt(int64(ci.Quantity)),
		}
	case *UpdateOrder_ItemsFinalized_:
		fin := tv.ItemsFinalized
		finMap := map[string]any{
			"payment_id":          fin.PaymentId,
			"sub_total":           fin.SubTotal,
			"sales_tax":           fin.SalesTax,
			"total":               fin.Total,
			"total_in_crypto":     fin.TotalInCrypto,
			"ttl":                 fin.Ttl,
			"order_hash":          fin.OrderHash,
			"payee_addr":          fin.PayeeAddr,
			"is_payment_endpoint": fin.IsPaymentEndpoint,
			"shop_signature":      fin.ShopSignature,
		}
		if len(fin.CurrencyAddr) == 20 {
			finMap["currency_addr"] = fin.CurrencyAddr
		}
		m["items_finalized"] = finMap
	case *UpdateOrder_OrderCanceled_:
		oc := tv.OrderCanceled
		m["order_canceled"] = map[string]any{
			"timestamp": big.NewInt(int64(oc.Timestamp)),
		}
	default:
		panic(fmt.Sprintf("unknown action: %v", evt.Action))
	}
	return m
}

func (evt *ChangeStock) typedDataMap() map[string]any {
	bigDiffs := make([]*big.Int, len(evt.Diffs))
	for i, diff := range evt.Diffs {
		bigDiffs[i] = big.NewInt(int64(diff))
	}
	return map[string]any{
		"event_id": evt.EventId,
		"order_id": evt.OrderId,
		"tx_hash":  evt.TxHash,
		"item_ids": evt.ItemIds,
		"diffs":    bigDiffs,
	}
}
