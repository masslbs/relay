// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"math/big"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	tassert "github.com/stretchr/testify/assert"
)

var demoKey = os.Getenv("COINGECKO_API_KEY")

func TestCoinGeckoCoinPrice(t *testing.T) {
	if !isCIEnv {
		t.Skip("Skipping test unless CI environment is set")
		return
	}
	a := tassert.New(t)
	eth := newEthRPCService(nil)

	cg := newCoinGecko(demoKey, "eur", eth)
	price, err := cg.GetCoinPrice("bitcoin")
	if err != nil {
		t.Fatalf("GetCoinPrice failed: %v", err)
	}
	a.NotEqual("0", price.String())

	t.Log("BTC:", price.String())
}

func TestCoinGeckoERC20(t *testing.T) {
	if !isCIEnv {
		t.Skip("Skipping test unless CI environment is set")
		return
	}
	a := tassert.New(t)
	eth := newEthRPCService(nil)
	cg := newCoinGecko(demoKey, "usd", eth)

	usdt := cachedShopCurrency{
		Addr:    common.HexToAddress("0xdac17f958d2ee523a2206206994597c13d831ec7"),
		ChainID: 1,
	}
	price, err := cg.GetERC20Price(usdt)
	if err != nil {
		t.Fatalf("GetERC20Price failed: %v", err)
	}
	a.NotEqual("0", price.String())
	t.Log("USDT:", price.String())
}

func TestCoinGeckoConvertErc20ToErc20(t *testing.T) {
	if !isCIEnv {
		t.Skip("Skipping test unless CI environment is set")
		return
	}
	a := tassert.New(t)
	eth := newEthRPCService(map[uint64][]string{
		1:   {"https://eth.llamarpc.com"},
		137: {"https://polygon.llamarpc.com"},
	})
	cg := newCoinGecko(demoKey, "usd", eth)

	usdc := cachedShopCurrency{
		Addr:    common.HexToAddress("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
		ChainID: 1,
	}
	matic := cachedShopCurrency{
		Addr:    common.HexToAddress("0x7d1afa7b718fb893db30a3abc0cfc608aacfebb0"),
		ChainID: 1,
	}

	result, err := cg.Convert(usdc, matic, big.NewInt(100))
	a.NoError(err)

	var (
		circa     = big.NewInt(240_000_000_000_000)
		deviation = big.NewInt(050_000_000_000_000)
		diff      = result.Sub(circa, result)
	)
	a.Equal(-1, diff.CmpAbs(deviation), "diff: %s", diff)
}

func TestCoinGeckoConvertCoinToErc20(t *testing.T) {
	if !isCIEnv {
		t.Skip("Skipping test unless CI environment is set")
		return
	}
	a := tassert.New(t)
	e := newEthRPCService(map[uint64][]string{
		1: {"https://eth.llamarpc.com"},
	})
	cg := newCoinGecko(demoKey, "usd", e)

	eth := cachedShopCurrency{
		Addr:    ZeroAddress,
		ChainID: 1,
	}
	usdt := cachedShopCurrency{
		Addr:    common.HexToAddress("0xdac17f958d2ee523a2206206994597c13d831ec7"),
		ChainID: 1,
	}

	halfAnEth := big.NewInt(500_000_000_000_000_000)
	result, err := cg.Convert(eth, usdt, halfAnEth)
	a.NoError(err)
	var (
		// eth is at ~2600usd
		circa     = big.NewInt(1_288_000_000)
		deviation = big.NewInt(030_000_000)
		diff      = result.Sub(circa, result)
	)
	a.Equal(-1, diff.CmpAbs(deviation), "diff: %s", diff)
}

func TestCoinGeckoConvertERC20ToCoin(t *testing.T) {
	if !isCIEnv {
		t.Skip("Skipping test unless CI environment is set")
		return
	}
	a := tassert.New(t)
	e := newEthRPCService(map[uint64][]string{
		1:  {"https://eth.llamarpc.com"},
		10: {"https://optimism.llamarpc.com"},
	})
	cg := newCoinGecko(demoKey, "usd", e)

	op := cachedShopCurrency{
		Addr:    common.HexToAddress("0x4200000000000000000000000000000000000042"),
		ChainID: 10,
	}
	eth := cachedShopCurrency{
		Addr:    ZeroAddress,
		ChainID: 1,
	}

	oneOp := big.NewInt(1_000_000_000_000_000_000)
	result, err := cg.Convert(op, eth, oneOp)
	a.NoError(err)
	var (
		circa     = big.NewInt(522_000_000_000_000)
		deviation = big.NewInt(5_000_000_000_000)
		diff      = result.Sub(circa, result)
	)
	a.Equal(-1, diff.CmpAbs(deviation), "diff: %s", diff)
}
