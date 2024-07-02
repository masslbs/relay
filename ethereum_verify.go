// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"crypto/ecdsa"
	"crypto/subtle"
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

func ecrecoverEIP191(message, signature []byte) ([]byte, error) {
	if len(signature) != 65 {
		return nil, fmt.Errorf("signature length is not 65")
	}

	sighash := accounts.TextHash(message)

	// update the recovery id
	// https://github.com/ethereum/go-ethereum/blob/55599ee95d4151a2502465e0afc7c47bd1acba77/internal/ethapi/api.go#L442
	signature[64] -= 27

	// get the pubkey used to sign this signature
	recovered, err := crypto.Ecrecover(sighash, signature)
	if err != nil {
		return nil, fmt.Errorf("ecrecover: %w", err)
	}

	return recovered, nil
}

func ecrecoverEIP191AndCompare(message, signature, publicKey []byte) error {
	if len(publicKey) != 64 {
		return fmt.Errorf("publicKey length is not 64")
	}

	recovered, err := ecrecoverEIP191(message, signature)
	if err != nil {
		return err
	}

	if len(recovered) == 65 && recovered[0] == 0x04 {
		// split of encoding bit
		recovered = recovered[1:]
	}

	if subtle.ConstantTimeCompare(recovered, publicKey) != 1 {
		return fmt.Errorf("keys are not equal")
	}
	return nil
}

func verifyChallengeResponse(publicKey, challange, signature []byte) error {
	return ecrecoverEIP191AndCompare(challange, signature, publicKey)
}

var eip712spec = []apitypes.Type{
	{Name: "name", Type: "string"},
	{Name: "version", Type: "string"},
	{Name: "chainId", Type: "uint256"},
	{Name: "verifyingContract", Type: "address"},
}

func verifyKeyCardEnroll(keyCardPublicKey, signature []byte) (common.Address, error) {
	if len(signature) != 65 {
		return common.Address{}, fmt.Errorf("signature length is not 65")
	}

	if len(keyCardPublicKey) != 64 {
		return common.Address{}, fmt.Errorf("keyCardPublicKey length is not 64")
	}

	typedData := apitypes.TypedData{
		Types: map[string][]apitypes.Type{
			"EIP712Domain": eip712spec,
			"Enrollment": {
				{Name: "keyCard", Type: "string"},
			},
		},
		PrimaryType: "Enrollment",
		Domain: apitypes.TypedDataDomain{
			Name:              "MassMarket",
			Version:           "1",
			ChainId:           math.NewHexOrDecimal256(0),
			VerifyingContract: "0x0000000000000000000000000000000000000000",
		},
		Message: map[string]any{
			"keyCard": hex.EncodeToString(keyCardPublicKey),
		},
	}
	// EIP-712 typed data marshalling
	sighash, _, err := apitypes.TypedDataAndHash(typedData)
	if err != nil {
		return common.Address{}, fmt.Errorf("TypedDataAndHash error: %w", err)
	}

	// update the recovery id
	// https://github.com/ethereum/go-ethereum/blob/55599ee95d4151a2502465e0afc7c47bd1acba77/internal/ethapi/api.go#L442
	signature[64] -= 27

	// get the pubkey used to sign this signature
	recovered, err := crypto.Ecrecover(sighash, signature)
	if err != nil {
		return common.Address{}, fmt.Errorf("ecrecover: %w", err)
	}

	pubkey, err := crypto.UnmarshalPubkey(recovered)
	if err != nil {
		return common.Address{}, fmt.Errorf("UnmarshalPubkey failed: %w", err)
	}

	recoveredAddress := crypto.PubkeyToAddress(*pubkey)
	return recoveredAddress, nil
}

func (evt *SignedEvent) Verify(publicKey []byte) error {
	return ecrecoverEIP191AndCompare(evt.Event.Value, evt.Signature, publicKey)
}

func eventSign(evtData []byte, secret *ecdsa.PrivateKey) ([]byte, error) {
	sighash := accounts.TextHash(evtData)

	signature, err := crypto.Sign(sighash, secret)
	if err != nil {
		return nil, fmt.Errorf("signEvent: crypto.Sign failed: %w", err)
	}

	return signature, nil
}
