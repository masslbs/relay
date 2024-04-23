// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/cockroachdb/apd"
	"github.com/ethereum/go-ethereum/common"
)

type priceConverter interface {
	FromFiatToCoin(fiat *apd.Decimal) *apd.Decimal
	FromFiatToERC20(fiat *apd.Decimal, tokenAddress common.Address) *apd.Decimal
}

// testingConverter is side-effect free for unit- and integration testing.
//
//   - does 1 usd is 0.5 coin
//   - does 1 usd is 1 erc20
type testingConverter struct{}

var _ priceConverter = (*testingConverter)(nil)

var decimalTwo = apd.New(2, 0)

func (tc testingConverter) FromFiatToCoin(fiat *apd.Decimal) *apd.Decimal {
	ctx := apd.BaseContext.WithPrecision(10)
	coinAmount := new(apd.Decimal)
	ctx.Mul(coinAmount, fiat, decimalTwo)
	return coinAmount
}

func (tc testingConverter) FromFiatToERC20(fiat *apd.Decimal, _ common.Address) *apd.Decimal {
	return fiat
}

var _ priceConverter = (*coinGecko)(nil)

type coinGecko struct {
	demoKey        string
	fiatCurrency   string
	transferCoin   string
	decimalContext apd.Context
}

func newCoinGecko(demoKey string, fiatCurrency string, transferCoin string) *coinGecko {
	return &coinGecko{
		demoKey:      demoKey,
		fiatCurrency: fiatCurrency,
		transferCoin: transferCoin,
		decimalContext: apd.Context{
			Precision:   10,
			Rounding:    apd.RoundHalfUp,
			MaxExponent: apd.MaxExponent,
			MinExponent: apd.MinExponent,
			Traps:       apd.DefaultTraps,
		},
	}
}

func (cg *coinGecko) GetCoinPrice(coin string) (*apd.Decimal, error) {
	url := fmt.Sprintf("https://api.coingecko.com/api/v3/simple/price?ids=%s&vs_currencies=%s&precision=full", coin, cg.fiatCurrency)
	if cg.demoKey != "" {
		url += fmt.Sprintf("&x_cg_demo_api_key=%s", cg.demoKey)
	}
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result map[string]map[string]json.RawMessage
	// r := io.TeeReader(resp.Body, os.Stderr)
	r := resp.Body
	if err := json.NewDecoder(r).Decode(&result); err != nil {
		return nil, err
	}
	fiatPrices, ok := result[coin]
	if !ok {
		return nil, fmt.Errorf("Coin %s not found", coin)
	}

	price, ok := fiatPrices[cg.fiatCurrency]
	if !ok {
		return nil, fmt.Errorf("fiat %s not found in %v", cg.fiatCurrency, fiatPrices)
	}

	coinPrice, _, err := apd.NewFromString(string(price))
	return coinPrice, err
}

func (cg *coinGecko) GetERC20Price(tokenAddress common.Address) (result *apd.Decimal, err error) {
	url := fmt.Sprintf("https://api.coingecko.com/api/v3/simple/token_price/ethereum?contract_addresses=%s&vs_currencies=%s&precision=full", tokenAddress.Hex(), cg.fiatCurrency)
	if cg.demoKey != "" {
		url += "&x_cg_demo_api_key=" + cg.demoKey
	}

	client := &http.Client{}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("Accept", "application/json")
	resp, err := client.Do(req)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	var data map[string]map[string]json.RawMessage
	// r := io.TeeReader(resp.Body, os.Stderr)
	r := resp.Body
	err = json.NewDecoder(r).Decode(&data)
	if err != nil {
		return nil, err
	}
	fmt.Fprintln(os.Stderr)

	token, ok := data[strings.ToLower(tokenAddress.Hex())]
	if !ok {
		return nil, fmt.Errorf("token %s not in response: %+v", tokenAddress.Hex(), data)
	}

	price, ok := token[strings.ToLower(cg.fiatCurrency)]
	if !ok {
		return nil, fmt.Errorf("fiat %s not in token: %+v", tokenAddress.Hex(), token)
	}

	result, _, err = apd.NewFromString(string(price))
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (cg *coinGecko) FromFiatToCoin(fiat *apd.Decimal) *apd.Decimal {
	coinPrice, err := cg.GetCoinPrice(cg.transferCoin)
	check(err)
	coinAmount := new(apd.Decimal)
	_, err = cg.decimalContext.Quo(coinAmount, fiat, coinPrice)
	check(err)
	return coinAmount
}

func (cg *coinGecko) FromFiatToERC20(fiat *apd.Decimal, tokenAddress common.Address) *apd.Decimal {
	erc20Price, err := cg.GetERC20Price(tokenAddress)
	check(err)
	erc20Amount := new(apd.Decimal)
	_, err = cg.decimalContext.Quo(erc20Amount, fiat, erc20Price)
	check(err)
	return erc20Amount
}
