// SPDX-FileCopyrightText: 2024 - 2025 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"math/big"
	"os"
	"strings"
	"testing"

	"encoding/json"

	"github.com/ethereum/go-ethereum/common"
	"github.com/masslbs/network-schema/go/objects"
	tassert "github.com/stretchr/testify/assert"
)

func TestTestingConverter(t *testing.T) {
	currA := objects.ChainAddress{
		EthereumAddress: objects.EthereumAddress{
			Address: common.HexToAddress("0x0000000000000000000000000000000000000001"),
		},
		ChainID: 1337,
	}
	currB := objects.ChainAddress{
		EthereumAddress: objects.EthereumAddress{
			Address: common.HexToAddress("0x0000000000000000000000000000000000000002"),
		},
		ChainID: 1337,
	}
	currC := objects.ChainAddress{
		EthereumAddress: objects.EthereumAddress{
			Address: common.HexToAddress("0x0000000000000000000000000000000000000003"),
		},
		ChainID: 1337,
	}

	tcSetup := testingConverter{
		ethereum: newEthRPCService(nil), // does not need network
		decimals: map[objects.ChainAddress]uint8{
			currA: 18,
			currB: 2,
			currC: 10,
		},
	}

	baseAmount := big.NewInt(100) // Represents 100 smallest units, or 1 display unit for currB (2d)

	// realistic amounts for conversions involving high decimal differences
	amountA18Equiv10thunits := big.NewInt(10000000000000000)                     // 10^16, 0.01 of 18d token
	amountA18Equiv1Unit, _ := new(big.Int).SetString("1000000000000000000", 10)  // 10^18, 1 of 18d token
	amountA18Equiv5Units, _ := new(big.Int).SetString("5000000000000000000", 10) // 5*10^18, 5 of 18d token
	amountC10Equiv0point002Units := big.NewInt(20000000)                         // 2*10^7, 0.002 of 10d token
	amountC10Equiv1Unit, _ := new(big.Int).SetString("10000000000", 10)          // 10^10, 1 of 10d token

	expectedBtoAFactor100, _ := new(big.Int).SetString("100000000000000000000", 10) // For B(100 units) to A
	expectedBtoCFactor2, _ := new(big.Int).SetString("20000000000", 10)             // For B(100 units) to C
	expectedCtoAFactor3, _ := new(big.Int).SetString("3000000000000000000", 10)     // For C(1 unit) to A

	testCases := []struct {
		name     string
		from     objects.ChainAddress
		to       objects.ChainAddress
		amount   *big.Int
		factor   *big.Int
		divisor  *big.Int
		expected *big.Int
		comment  string
	}{
		{
			name:     "Identity currA to currA",
			from:     currA,
			to:       currA,
			amount:   baseAmount, // 100 smallest units of A
			factor:   big.NewInt(1),
			divisor:  big.NewInt(1),
			expected: baseAmount,
		},
		{
			name:     "Identity currB to currB",
			from:     currB,
			to:       currB,
			amount:   baseAmount, // 100 smallest units of B (1 display unit of B)
			factor:   big.NewInt(1),
			divisor:  big.NewInt(1),
			expected: baseAmount,
		},
		{
			name:     "A(18d) to B(2d), factor 100, amount 0.01 A-units",
			from:     currA,
			to:       currB,
			amount:   amountA18Equiv10thunits, // 10^16
			factor:   big.NewInt(100),
			divisor:  big.NewInt(1),
			expected: big.NewInt(100), // 0.01 A-units * 100 = 1 B-unit = 100 B-smallest-units
			comment:  "0.01 A-units (10^16) to B. Expected 100 B-smallest-units.",
		},
		{
			name:     "A(18d) to B(2d), factor 1/100, amount 1 A-unit",
			from:     currA,
			to:       currB,
			amount:   amountA18Equiv1Unit, // 10^18
			factor:   big.NewInt(1),
			divisor:  big.NewInt(100),
			expected: big.NewInt(1), // 1 A-unit * 0.01 = 0.01 B-units = 1 B-smallest-unit
			comment:  "1 A-unit (10^18) to B. Expected 1 B-smallest-unit.",
		},
		{
			name:     "B(2d) to A(18d), factor 100, amount 1 B-unit",
			from:     currB,
			to:       currA,
			amount:   baseAmount, // 100 B-smallest-units (1 B display unit)
			factor:   big.NewInt(100),
			divisor:  big.NewInt(1),
			expected: expectedBtoAFactor100, // 1e20 A-smallest-units
			comment:  "1 B-unit (100 B-smallest) to A. Expected 1e20 A-smallest-units.",
		},
		{
			name:     "B(2d) to C(10d), factor 2, amount 1 B-unit",
			from:     currB,
			to:       currC,
			amount:   baseAmount, // 100 B-smallest-units (1 B display unit)
			factor:   big.NewInt(2),
			divisor:  big.NewInt(1),
			expected: expectedBtoCFactor2, // 2e10 C-smallest-units
			comment:  "1 B-unit (100 B-smallest) to C. Expected 2e10 C-smallest-units.",
		},
		{
			name:     "C(10d) to B(2d), factor 5, amount 0.002 C-units",
			from:     currC,
			to:       currB,
			amount:   amountC10Equiv0point002Units, // 2*10^7
			factor:   big.NewInt(5),
			divisor:  big.NewInt(1),
			expected: big.NewInt(1), // 0.002 C-units * 5 = 0.01 B-units = 1 B-smallest-unit
			comment:  "0.002 C-units (2*10^7) to B. Expected 1 B-smallest-unit.",
		},
		{
			name:     "C(10d) to A(18d), factor 3, amount 1 C-unit",
			from:     currC,
			to:       currA,
			amount:   amountC10Equiv1Unit, // 10^10
			factor:   big.NewInt(3),
			divisor:  big.NewInt(1),
			expected: expectedCtoAFactor3, // 3*10^18 A-smallest-units
			comment:  "1 C-unit (10^10) to A. Expected 3*10^18 A-smallest-units.",
		},
		{
			name:     "A(18d) to B(2d), factor 1/100, amount 5 A-units",
			from:     currA,
			to:       currB,
			amount:   amountA18Equiv5Units, // 5*10^18
			factor:   big.NewInt(1),
			divisor:  big.NewInt(100),
			expected: big.NewInt(5), // 5 A-units * 0.01 = 0.05 B-units = 5 B-smallest-units
			comment:  "5 A-units (5*10^18) to B. Expected 5 B-smallest-units.",
		},
		{
			name:     "real life example",
			from:     currA,
			to:       currB,
			amount:   big.NewInt(2000000000000000),
			factor:   big.NewInt(1500),
			divisor:  big.NewInt(1),
			expected: big.NewInt(300),
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			a := tassert.New(t)
			t.Log(tt.comment)
			// Make a copy of tcSetup to set factor and divisor for subtest
			tc := tcSetup
			tc.factor = tt.factor
			tc.divisor = tt.divisor

			converted, err := tc.Convert(tt.from, tt.to, tt.amount)
			a.NoError(err)

			a.Equal(converted.Cmp(tt.expected), 0, "Expected %s, got %s", tt.expected, converted)
		})
	}
}

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

	usdt := objects.ChainAddress{
		EthereumAddress: objects.EthereumAddress{
			Address: common.HexToAddress("0xdac17f958d2ee523a2206206994597c13d831ec7"),
		},
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

	usdc := objects.ChainAddress{
		EthereumAddress: objects.EthereumAddress{
			Address: common.HexToAddress("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
		},
		ChainID: 1,
	}
	matic := objects.ChainAddress{
		EthereumAddress: objects.EthereumAddress{
			Address: common.HexToAddress("0x7d1afa7b718fb893db30a3abc0cfc608aacfebb0"),
		},
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

	eth := objects.ChainAddress{
		EthereumAddress: objects.EthereumAddress{
			Address: ZeroAddress,
		},
		ChainID: 1,
	}
	usdt := objects.ChainAddress{
		EthereumAddress: objects.EthereumAddress{
			Address: common.HexToAddress("0xdac17f958d2ee523a2206206994597c13d831ec7"),
		},
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

	op := objects.ChainAddress{
		EthereumAddress: objects.EthereumAddress{
			Address: common.HexToAddress("0x4200000000000000000000000000000000000042"),
		},
		ChainID: 10,
	}
	eth := objects.ChainAddress{
		EthereumAddress: objects.EthereumAddress{
			Address: ZeroAddress,
		},
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

func TestJsonToBigInt(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		hasError bool
	}{
		{`"1"`, "1" + strings.Repeat("0", coinConversionDecimalBase), false},
		{`"12345"`, "12345" + strings.Repeat("0", coinConversionDecimalBase), false},
		{`"0.12345"`, "12345" + strings.Repeat("0", coinConversionDecimalBase-5), false},
		{`".0001"`, "1" + strings.Repeat("0", coinConversionDecimalBase-4), false},

		// Very large number
		{`"1000000000000000000"`, "1000000000000000000" + strings.Repeat("0", coinConversionDecimalBase), false},
		// Negative number
		{`"-123.456"`, "-123456" + strings.Repeat("0", coinConversionDecimalBase-3), false},
		// More decimal places than coinConversionDecimalBase
		{`"0.1234567890123456789"`, "1234567890123456", false},
		// Exactly coinConversionDecimalBase decimal places
		{`"0.1234567890123456"`, "1234567890123456", false},
		// Fewer decimal places than coinConversionDecimalBase
		{`"0.123"`, "123" + strings.Repeat("0", coinConversionDecimalBase-3), false},
		// Integer part with leading zeros
		{`"000123.456"`, "123456" + strings.Repeat("0", coinConversionDecimalBase-3), false},
		// Fractional part with trailing zeros
		{`"123.45600"`, "12345600" + strings.Repeat("0", coinConversionDecimalBase-5), false},

		{`""`, "", true},
		{`"invalid"`, "", true},
		{`"."`, "", true},
		{`"1.2.3"`, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			a := tassert.New(t)
			var raw = json.RawMessage(tt.input)
			result, err := jsonToBigInt(raw)
			if tt.hasError {
				a.Error(err)
			} else {
				a.NoError(err)
				a.Equal(tt.expected, result.String())
			}
		})
	}
}
