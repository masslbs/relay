// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"

	"github.com/cockroachdb/apd"
)

type priceConverter interface {
	Convert(a, b cachedShopCurrency, amount *big.Int) (*big.Int, error)
}

// testingConverter is side-effect free for unit- and integration testing.
//
//   - does 1 usd is 0.5 coin
//   - does 1 usd is 1 erc20
type testingConverter struct{}

var _ priceConverter = (*testingConverter)(nil)

var bigTwo = big.NewInt(2)

func (tc testingConverter) Convert(a, b cachedShopCurrency, amount *big.Int) (*big.Int, error) {
	r := new(big.Int).Mul(amount, bigTwo)
	return r, nil
}

var _ priceConverter = (*coinGecko)(nil)

type coinGecko struct {
	demoKey      string
	fiatCurrency string
	//transferCoin   string

	// these shouldn't really invalidate and if so, restart the relay
	platformNamesMu sync.Mutex
	platformNames   coinGeckoPlatformMap

	ethereum *ethRPCService
}

type coinGeckoPlatformMap map[uint64]coinGeckoPlatform

type coinGeckoPlatform struct {
	ID           string  `json:"id"`
	ChainID      *uint64 `json:"chain_identifier"`
	Name         string
	NativeCoinId string
}

func newCoinGecko(demoKey string, fiatCurrency string, ethereum *ethRPCService) *coinGecko {
	assertWithMessage(demoKey != "", "demo api key can't be empty")
	return &coinGecko{
		demoKey:       demoKey,
		fiatCurrency:  fiatCurrency,
		platformNames: make(coinGeckoPlatformMap),
		ethereum:      ethereum,
	}
}

func (cg *coinGecko) lookupPlatform(chainId uint64) (coinGeckoPlatform, error) {
	cg.platformNamesMu.Lock()
	name, has := cg.platformNames[chainId]
	if has {
		cg.platformNamesMu.Unlock()
		return name, nil
	}
	cg.platformNamesMu.Unlock()

	url := "https://api.coingecko.com/api/v3/asset_platforms"
	if cg.demoKey != "" {
		url += fmt.Sprintf("?x_cg_demo_api_key=%s", cg.demoKey)
	}
	resp, err := http.Get(url)
	if err != nil {
		return name, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return name, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	var result []coinGeckoPlatform
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return name, err
	}

	cg.platformNamesMu.Lock()
	for _, p := range result {
		if p.ChainID != nil {
			//fmt.Printf("%s %d\n", p.Name, *p.ChainID)
			cg.platformNames[*p.ChainID] = p
		}
	}
	name, has = cg.platformNames[chainId]
	cg.platformNamesMu.Unlock()

	if !has {
		return name, errors.New("not found")
	}
	return name, nil
}

const coinConversionDecimalBase = 20

func jsonToBigInt(r json.RawMessage) (*big.Int, error) {
	// TODO: in theory we just need to splice the decimal point to a different position.
	// but i had this decimals dependency laying around from the previous price stuff, so..
	decimalCtx := apd.BaseContext.WithPrecision(50)

	result, _, err := apd.NewFromString(string(r))
	if err != nil {
		return nil, err
	}
	_, err = decimalCtx.Mul(result, result, apd.New(1, coinConversionDecimalBase))
	if err != nil {
		return nil, err
	}
	inDecimals := result.Text('f')
	bigResult, ok := new(big.Int).SetString(inDecimals, 10)
	if !ok {
		return nil, fmt.Errorf("failed to convert %q to bigInt: %s", string(r), inDecimals)
	}
	return bigResult, nil
}

func (cg *coinGecko) GetCoinPriceFromNetworkID(id uint64) (*big.Int, error) {
	plat, err := cg.lookupPlatform(id)
	if err != nil {
		return nil, err
	}
	return cg.GetCoinPrice(plat.ID)
}

func (cg *coinGecko) GetCoinPrice(coin string) (*big.Int, error) {
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
	return jsonToBigInt(price)
}

func (cg *coinGecko) GetERC20Price(coin cachedShopCurrency) (*big.Int, error) {
	plat, err := cg.lookupPlatform(coin.ChainID)
	if err != nil {
		return nil, fmt.Errorf("unsupported coingecko platform: %d: %w", coin.ChainID, err)
	}
	url := fmt.Sprintf("https://api.coingecko.com/api/v3/simple/token_price/%s?contract_addresses=%s&vs_currencies=%s&precision=full", plat.ID, coin.Addr.Hex(), cg.fiatCurrency)
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
	r := resp.Body
	err = json.NewDecoder(r).Decode(&data)
	if err != nil {
		return nil, err
	}
	hexAddr := coin.Addr.Hex()
	token, ok := data[strings.ToLower(hexAddr)]
	if !ok {
		return nil, fmt.Errorf("token %s not in response: %+v", hexAddr, data)
	}
	price, ok := token[strings.ToLower(cg.fiatCurrency)]
	if !ok {
		return nil, fmt.Errorf("fiat %s not in token: %+v", hexAddr, token)
	}
	return jsonToBigInt(price)
}

// converts the amount from a (base currency) to b (chosen/target)
func (tc *coinGecko) Convert(a, b cachedShopCurrency, amount *big.Int) (*big.Int, error) {
	var (
		basedInErc20  = ZeroAddress.Cmp(a.Addr) != 0
		decimalsBased uint8
		basePrice     *big.Int

		chosenIsErc20  = ZeroAddress.Cmp(b.Addr) != 0
		decimalsChosen uint8
		chosenPrice    *big.Int

		err error
		tok *erc20Metadata
	)
	// get decimals count for erc20s
	// TODO: since this is a contract we could cache it when adding the token
	if basedInErc20 {
		tok, err = tc.ethereum.GetERC20Metadata(a.ChainID, a.Addr)
		if err != nil {
			return nil, fmt.Errorf("convert: metadata for base %v: %w", a, err)
		}

		// let's not assume these contracts are static code
		if err := tok.validate(); err != nil {
			return nil, err
		}

		decimalsBased = tok.decimals

		basePrice, err = tc.GetERC20Price(a)
		// TODO: convert price to token decimals

	} else {
		// TODO: might need a scary table here for some fringe coins
		decimalsBased = 18
		basePrice, err = tc.GetCoinPriceFromNetworkID(a.ChainID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get coin price for base currency %v: %w", a, err)
	}

	if chosenIsErc20 {
		tok, err = tc.ethereum.GetERC20Metadata(b.ChainID, b.Addr)
		if err != nil {
			return nil, fmt.Errorf("convert: metadata for chosen %v: %w", b, err)
		}

		// let's not assume these contracts are static code
		if err := tok.validate(); err != nil {
			return nil, err
		}

		decimalsChosen = tok.decimals

		chosenPrice, err = tc.GetERC20Price(b)

	} else {
		// TODO: might need a scary table here for some fringe coins
		decimalsChosen = 18
		chosenPrice, err = tc.GetCoinPriceFromNetworkID(b.ChainID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get price for chosen currency %v: %w", b, err)
	}
	result := new(big.Int)

	// convert price to same base
	log("TODO/convert total=%s", amount.String())
	log("TODO/convert based_erc20=%v chosen_erc20=%v", basedInErc20, chosenIsErc20)

	log("TODO/convert/base   dec=%d price_base=%s", decimalsBased, basePrice.String())
	log("TODO/convert/chosen dec=%d price_chosen=%s", decimalsChosen, chosenPrice.String())

	correction := int64(coinConversionDecimalBase) - int64(decimalsBased)
	if correction > 0 {
		result.Mul(amount, new(big.Int).Exp(big.NewInt(10), big.NewInt(correction), nil))
	} else {
		result.Div(amount, new(big.Int).Exp(big.NewInt(10), big.NewInt(-correction), nil))
	}
	log("TODO/convert/shiftIn correction=%d corrected=%s", correction, result.String())

	result.Mul(result, basePrice)
	result.Div(result, chosenPrice)
	log("TODO/convert result=%s", result.String())

	correction = int64(coinConversionDecimalBase) - int64(decimalsChosen)
	if correction < 0 {
		return nil, fmt.Errorf("TODO: add tests")
		result.Mul(result, new(big.Int).Exp(big.NewInt(10), big.NewInt(-correction), nil))
	} else {
		result.Div(result, new(big.Int).Exp(big.NewInt(10), big.NewInt(correction), nil))
	}
	log("TODO/convert/shiftOut correction=%d amount=%s", correction, result.String())

	return result, nil
}
