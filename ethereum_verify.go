// SPDX-FileCopyrightText: 2024 - 2025 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/crypto"

	cbor "github.com/masslbs/network-schema/go/cbor"
)

func ecrecoverEIP191(message, signature []byte) (*ecdsa.PublicKey, error) {
	if len(signature) != cbor.SignatureSize {
		return nil, fmt.Errorf("signature length is not %d", cbor.SignatureSize)
	}

	sighash := accounts.TextHash(message)

	// update the recovery id
	// https://github.com/ethereum/go-ethereum/blob/55599ee95d4151a2502465e0afc7c47bd1acba77/internal/ethapi/api.go#L442
	signature[cbor.SignatureSize-1] -= 27

	// get the pubkey used to sign this signature
	recovered, err := crypto.Ecrecover(sighash, signature)
	if err != nil {
		return nil, fmt.Errorf("ecrecover: %w", err)
	}
	pk, err := crypto.UnmarshalPubkey(recovered)
	if err != nil {
		return nil, fmt.Errorf("unmarshalPubkey: %w", err)
	}
	return pk, nil
}

func ecrecoverEIP191AndCompare(message, signature, publicKey []byte) error {
	if len(publicKey) != cbor.PublicKeySize {
		return fmt.Errorf("publicKey length is not %d", cbor.PublicKeySize)
	}

	pk, err := crypto.DecompressPubkey(publicKey)
	if err != nil {
		return fmt.Errorf("decompressPubkey failed: %w", err)
	}

	recovered, err := ecrecoverEIP191(message, signature)
	if err != nil {
		return err
	}

	if !pk.Equal(recovered) {
		return fmt.Errorf("keys are not equal")
	}

	return nil
}

func verifyChallengeResponse(publicKey, challange, signature []byte) error {
	return ecrecoverEIP191AndCompare(challange, signature, publicKey)
}

// VerifyPatchSetSignature verifies the signature of the event
func VerifyPatchSetSignature(pset *cbor.SignedPatchSet, publicKey []byte) error {
	headerBytes, err := cbor.Marshal(pset.Header)
	if err != nil {
		return fmt.Errorf("cbor.Marshal failed: %w", err)
	}
	// log("DEBUG.verifyPatchSetSignature headerBytes=%x", headerBytes)
	return ecrecoverEIP191AndCompare(headerBytes, pset.Signature[:], publicKey)
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
