// SPDX-FileCopyrightText: 2024 - 2025 Mass Labs
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

	"github.com/ethereum/go-ethereum/common"
	"github.com/masslbs/network-schema/go/objects"
)

type priceConverter interface {
	Convert(a, b objects.ChainAddress, amount *big.Int) (*big.Int, error)
}

const coinConversionDecimalBase = 16

// jsonToBigInt converts a JSON-encoded decimal string to a *big.Int by removing the decimal point and adjusting accordingly.
func jsonToBigInt(r json.RawMessage) (*big.Int, error) {
	// Convert JSON raw message to string
	str := string(r)
	str = strings.Trim(str, `"`) // Remove surrounding quotes if present
	str = strings.TrimSpace(str)

	// Split the string into integer and fractional parts
	parts := strings.SplitN(str, ".", 2)
	// intPart := parts[0]
	fracPart := ""
	if len(parts) > 1 {
		fracPart = parts[1]
	}

	str = strings.Replace(str, ".", "", 1)

	// Convert the string to a big.Int
	n, ok := new(big.Int).SetString(str, 10)
	if !ok {
		return nil, fmt.Errorf("invalid number format: %s", str)
	}

	// Adjust to coinConversionDecimalBase
	if len(fracPart) < coinConversionDecimalBase {
		// If we have fewer decimal places than required, multiply
		multiplier := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(coinConversionDecimalBase-len(fracPart))), nil)
		n.Mul(n, multiplier)
	} else if len(fracPart) > coinConversionDecimalBase {
		// If we have more decimal places than required, divide
		divisor := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(len(fracPart)-coinConversionDecimalBase)), nil)
		n.Div(n, divisor)
	}

	return n, nil
}

// testingConverter is side-effect free for unit- and integration testing.
type testingConverter struct {
	factor, divisor *big.Int

	ethereum *ethRPCService
	// used as a fallback for unit testing
	decimals map[objects.ChainAddress]uint8
}

var defaultDecimals = map[objects.ChainAddress]uint8{
	{
		ChainID: 1337,
		EthereumAddress: objects.EthereumAddress{
			Address: common.HexToAddress("0x0000000000000000000000000000000000000000"),
		},
	}: 18,
	{
		ChainID: 1337,
		EthereumAddress: objects.EthereumAddress{
			Address: common.HexToAddress("0x6D3A93d661c8439C7e7782E2B22cbaCB2d8CA05A"),
		},
	}: 2,
}

// if both are empty strings, it will use 1:1 conversion
func newTestingConverter(factor, divisor string, ethereum *ethRPCService) (*testingConverter, error) {
	if factor != "" && divisor != "" {
		factorBig, ok := new(big.Int).SetString(factor, 10)
		if !ok {
			return nil, fmt.Errorf("TESTING_PRICE_CONVERTER_FACTOR is not a valid integer: %s", factor)
		}
		divisorBig, ok := new(big.Int).SetString(divisor, 10)
		if !ok {
			return nil, fmt.Errorf("TESTING_PRICE_CONVERTER_DIVISOR is not a valid integer: %s", divisor)
		}
		return &testingConverter{
			factor:   factorBig,
			divisor:  divisorBig,
			decimals: defaultDecimals,
			ethereum: ethereum,
		}, nil
	}
	return &testingConverter{
		factor:   big.NewInt(1),
		divisor:  big.NewInt(1),
		decimals: defaultDecimals,
		ethereum: ethereum,
	}, nil
}

var _ priceConverter = (*testingConverter)(nil)

// var bigTwo = big.NewInt(2)

// Convert is a testing price converter that applies factor/divisor conversion with proper decimal normalization
func (tc testingConverter) Convert(a, b objects.ChainAddress, amount *big.Int) (*big.Int, error) {
	// Work with a copy to avoid mutating the input
	result := new(big.Int).Set(amount)

	if a.ChainID == b.ChainID && a.Address.Cmp(b.Address) == 0 {
		return result, nil
	}

	// Get decimals for currency A
	var decimalsA uint8
	if a.Address.Cmp(ZeroAddress) == 0 {
		// Native token - assume 18 decimals
		decimalsA = 18
	} else {
		decimals, ok := tc.decimals[a]
		if !ok {
			meta, err := tc.ethereum.GetERC20Metadata(a.ChainID, common.Address(a.Address))
			if err != nil {
				return nil, fmt.Errorf("failed to get metadata for base currency %v: %w", a, err)
			}
			decimals = meta.decimals
		}
		decimalsA = decimals
	}

	// Get decimals for currency B
	var decimalsB uint8
	if b.Address.Cmp(ZeroAddress) == 0 {
		// Native token - assume 18 decimals
		decimalsB = 18
	} else {
		decimals, ok := tc.decimals[b]
		if !ok {
			meta, err := tc.ethereum.GetERC20Metadata(b.ChainID, common.Address(b.Address))
			if err != nil {
				return nil, fmt.Errorf("failed to get metadata for chosen currency %v: %w", b, err)
			}
			decimals = meta.decimals
		}
		decimalsB = decimals
	}

	// Step 1: Convert currency A to coinConversionDecimalBase (same as coinGecko approach)
	correction := int64(coinConversionDecimalBase) - int64(decimalsA)
	if correction > 0 {
		result.Mul(result, new(big.Int).Exp(big.NewInt(10), big.NewInt(correction), nil))
	} else if correction < 0 {
		result.Div(result, new(big.Int).Exp(big.NewInt(10), big.NewInt(-correction), nil))
	}

	// Step 2: Apply the conversion factor (this is the actual price conversion)
	result.Mul(result, tc.factor)
	result.Div(result, tc.divisor)

	// Step 3: Convert from coinConversionDecimalBase to currency B (same as coinGecko approach)
	correction = int64(decimalsB) - int64(coinConversionDecimalBase)
	if correction > 0 {
		result.Mul(result, new(big.Int).Exp(big.NewInt(10), big.NewInt(correction), nil))
	} else if correction < 0 {
		result.Div(result, new(big.Int).Exp(big.NewInt(10), big.NewInt(-correction), nil))
	}

	return result, nil
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
	NativeCoinID string
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

func (cg *coinGecko) lookupPlatform(chainID uint64) (coinGeckoPlatform, error) {
	cg.platformNamesMu.Lock()
	defer cg.platformNamesMu.Unlock()
	name, has := cg.platformNames[chainID]
	if has {
		return name, nil
	}

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

	for _, p := range result {
		if p.ChainID != nil {
			fmt.Printf("%s %d\n", p.Name, *p.ChainID)
			cg.platformNames[*p.ChainID] = p
		}
	}

	name, has = cg.platformNames[chainID]
	if !has {
		return coinGeckoPlatform{}, errors.New("not found")
	}
	return name, nil
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
		return nil, fmt.Errorf("coin %s not found", coin)
	}
	price, ok := fiatPrices[cg.fiatCurrency]
	if !ok {
		return nil, fmt.Errorf("fiat %s not found in %v", cg.fiatCurrency, fiatPrices)
	}
	return jsonToBigInt(price)
}

func (cg *coinGecko) GetERC20Price(coin objects.ChainAddress) (*big.Int, error) {
	plat, err := cg.lookupPlatform(coin.ChainID)
	if err != nil {
		return nil, fmt.Errorf("unsupported coingecko platform: %d: %w", coin.ChainID, err)
	}
	url := fmt.Sprintf("https://api.coingecko.com/api/v3/simple/token_price/%s?contract_addresses=%s&vs_currencies=%s&precision=full",
		plat.ID,
		common.Address(coin.Address).Hex(),
		cg.fiatCurrency,
	)
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
	hexAddr := common.Address(coin.Address).Hex()
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

// Convert converts the amount from a (base currency) to b (chosen/target)
func (cg *coinGecko) Convert(a, b objects.ChainAddress, amount *big.Int) (*big.Int, error) {
	var (
		basedInErc20  = ZeroAddress.Cmp(common.Address(a.Address)) != 0
		decimalsBased uint8
		basePrice     *big.Int

		chosenIsErc20  = ZeroAddress.Cmp(common.Address(b.Address)) != 0
		decimalsChosen uint8
		chosenPrice    *big.Int

		err error
		tok *erc20Metadata
	)
	// get decimals count for erc20s
	// TODO: since this is a contract we should be able cache it when adding the token..?
	if basedInErc20 {
		tok, err = cg.ethereum.GetERC20Metadata(a.ChainID, common.Address(a.Address))
		if err != nil {
			return nil, fmt.Errorf("convert: metadata for base %v: %w", a, err)
		}

		decimalsBased = tok.decimals

		basePrice, err = cg.GetERC20Price(a)
	} else {
		// TODO: might need a scary table here for some fringe coins
		decimalsBased = 18
		basePrice, err = cg.GetCoinPriceFromNetworkID(a.ChainID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get coin price for base currency %v: %w", a, err)
	}

	if chosenIsErc20 {
		tok, err = cg.ethereum.GetERC20Metadata(b.ChainID, common.Address(b.Address))
		if err != nil {
			return nil, fmt.Errorf("convert: metadata for chosen %v: %w", b, err)
		}

		decimalsChosen = tok.decimals

		chosenPrice, err = cg.GetERC20Price(b)
	} else {
		// TODO: might need a scary table here for some fringe coins
		decimalsChosen = 18
		chosenPrice, err = cg.GetCoinPriceFromNetworkID(b.ChainID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get price for chosen currency %v: %w", b, err)
	}
	result := new(big.Int)

	// convert price to same decimal point base
	correction := int64(coinConversionDecimalBase) - int64(decimalsBased)
	if correction > 0 {
		result.Mul(amount, new(big.Int).Exp(big.NewInt(10), big.NewInt(correction), nil))
	} else {
		result.Div(amount, new(big.Int).Exp(big.NewInt(10), big.NewInt(-correction), nil))
	}

	result.Mul(result, basePrice)
	result.Div(result, chosenPrice)

	correction = int64(coinConversionDecimalBase) - int64(decimalsChosen)
	result.Mul(result, new(big.Int).Exp(big.NewInt(10), big.NewInt(correction), nil))

	return result, nil
}
