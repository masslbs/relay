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

func (evt *ShopManifest) typedDataMap() map[string]any {
	return map[string]any{
		"event_id":         evt.EventId,
		"shop_token_id":    evt.ShopTokenId,
		"domain":           evt.Domain,
		"published_tag_id": evt.PublishedTagId,
	}
}

func (evt *UpdateShopManifest) typedDataMap() map[string]any {
	m := map[string]any{
		"event_id": evt.EventId,
	}
	if d := evt.Domain; d != nil {
		m["domain"] = *d
	}
	if pt := evt.PublishedTagId; len(pt) > 0 {
		m["published_tag_id"] = pt
	}
	if addr := evt.AddErc20Addr; len(addr) > 0 {
		m["add_erc20_addr"] = addr
	}
	if addr := evt.RemoveErc20Addr; len(addr) > 0 {
		m["remove_erc20_addr"] = addr
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
	}
	if p := evt.Price; p != nil {
		m["price"] = *p
	}
	if meta := evt.Metadata; len(meta) > 0 {
		m["metadata"] = meta
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
	}
	if id := evt.AddItemId; len(id) > 0 {
		m["add_item_id"] = id
	}
	if id := evt.RemoveItemId; len(id) > 0 {
		m["remove_item_id"] = id
	}
	if r := evt.Rename; r != nil {
		m["rename"] = *r
	}
	if d := evt.Delete; d != nil {
		m["delete"] = *d
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
