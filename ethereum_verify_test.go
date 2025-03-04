// SPDX-FileCopyrightText: 2024 - 2025 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	contractsabi "github.com/masslbs/relay/internal/contractabis"
	"github.com/stretchr/testify/require"
)

// HexString can be used to turn a byteslice into a JSON hexadecimal string
type HexString []byte

// MarshalJSON turns the binary data into a hex string
func (s HexString) MarshalJSON() ([]byte, error) {
	str := hex.EncodeToString([]byte(s))
	return json.Marshal(str)
}

// UnmarshalJSON expects data to be a string with hexadecimal bytes inside
func (s *HexString) UnmarshalJSON(data []byte) error {
	var strData string
	err := json.Unmarshal(data, &strData)
	if err != nil {
		return fmt.Errorf("HexString: json decode of string failed: %w", err)
	}
	strData = strings.TrimPrefix(strData, "0x")

	rawData, err := hex.DecodeString(strData)
	if err != nil {
		return fmt.Errorf("HexString: decoding hex to raw bytes failed: %w", err)
	}

	*s = rawData
	return nil
}

func TestGetPaymentId(t *testing.T) {
	payment := contractsabi.PaymentRequest{
		ChainId: big.NewInt(1337),
		Ttl:     big.NewInt(999999999999999999),
		// Order: see below,
		Currency:          common.HexToAddress("0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00"),
		Amount:            big.NewInt(1000000000000000000),
		PayeeAddress:      common.HexToAddress("0x9876543210987654321098765432109876543210"),
		IsPaymentEndpoint: false,
		ShopId:            big.NewInt(1),
		ShopSignature:     bytes.Repeat([]byte{255}, 65),
	}
	order, err := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	payment.Order = [32]byte(order)

	id, err := GetPaymentId(payment)
	require.NoError(t, err)

	t.Run("Compare with contract implementation", func(t *testing.T) {
		// Skip if not running integration tests
		if testing.Short() {
			t.Skip("Skipping integration test")
		}

		// Create a client connected to local Anvil instance

		kp := newEthKeyPair()
		ec := newEthClient(kp, 1337, []string{"http://localhost:8545"})
		client, err := ec.getRPC(context.Background())
		require.NoError(t, err)
		contractAddress := ec.contractAddresses.Payments
		paymentsByAddress, err := contractsabi.NewPaymentsByAddress(contractAddress, client)
		require.NoError(t, err)

		// Get payment ID from the contract
		contractPaymentId, err := paymentsByAddress.GetPaymentId(nil, payment)
		require.NoError(t, err)

		// Compare the results
		require.Equal(t, contractPaymentId.String(), id.String(),
			"Payment ID from contract doesn't match our implementation")

		// Also test the payment address generation
		// refundAddress := common.HexToAddress("0x0000000000000000000000000000000000000000")
		// ourPaymentAddr, err := paymentsByAddress.GetPaymentAddress(nil, payment, refundAddress)
		// require.NoError(t, err)

		t.Logf("Payment ID: %s", id.String())
		// t.Logf("Payment Address: %s", ourPaymentAddr.String())
	})
}
