// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: MIT

package main

import (
	"testing"

	"github.com/cockroachdb/apd"
	"github.com/ethereum/go-ethereum/common"
	tassert "github.com/stretchr/testify/assert"
)

func TestCoinGecko(t *testing.T) {
	if !isCIEnv {
		t.Skip("Skipping test unless CI environment is set")
		return
	}
	cg := newCoinGecko("", "usd", "ethereum")
	price, err := cg.GetCoinPrice("bitcoin")
	if err != nil {
		t.Fatalf("GetCoinPrice failed: %v", err)
	}
	if price.String() == "0" {
		t.Errorf("GetCoinPrice returned zero price")
	}
	t.Log("BTC:", price.String())
}

func TestCoingGeckoERC20(t *testing.T) {
	if !isCIEnv {
		t.Skip("Skipping test unless CI environment is set")
		return
	}
	cg := newCoinGecko("", "usd", "ethereum")
	addr := common.HexToAddress("0xdac17f958d2ee523a2206206994597c13d831ec7")
	price, err := cg.GetERC20Price(addr)
	if err != nil {
		t.Fatalf("GetERC20Price failed: %v", err)
	}
	if price.String() == "0" {
		t.Errorf("GetERC20Price returned zero price")
	}
	t.Log("USDT:", price.String())
}

func TestTestingConverter(t *testing.T) {
	a := tassert.New(t)
	tc := testingConverter{}
	one, _, err := apd.NewFromString("1.25")
	a.NoError(err, "apd.NewFromString failed")
	price := tc.FromFiatToCoin(one)
	a.Equal("2.50", price.String(), "FromFiatToCoin returned wrong price")
	price = tc.FromFiatToERC20(one, common.HexToAddress("0x0"))
	a.Equal("1.25", price.String(), "FromFiatToERC20 returned wrong price")
}
