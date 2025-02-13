// SPDX-FileCopyrightText: 2024 - 2025 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"crypto/ecdsa"
	"crypto/subtle"
	"fmt"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/crypto"

	cbor "github.com/masslbs/network-schema/go/cbor"
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

// Verify verifies the signature of the event
func VerifyPatchSet(pset *cbor.PatchSetHeader, publicKey []byte) error {
	// return ecrecoverEIP191AndCompare(pset.Value, pset.Signature.Raw, publicKey)
	return fmt.Errorf("TODO: verify patch set")
}

func signEIP191(evtData []byte, secret *ecdsa.PrivateKey) (*cbor.Signature, error) {
	sighash := accounts.TextHash(evtData)

	signature, err := crypto.Sign(sighash, secret)
	if err != nil {
		return nil, fmt.Errorf("signEvent: crypto.Sign failed: %w", err)
	}
	if len(signature) != 65 {
		return nil, fmt.Errorf("signEvent: signature length is not 65")
	}
	wrapped := cbor.Signature(signature)
	return &wrapped, nil
}
