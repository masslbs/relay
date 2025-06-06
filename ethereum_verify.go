// SPDX-FileCopyrightText: 2024 - 2025 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/masslbs/network-schema/go/objects"
	contractsabi "github.com/masslbs/relay/internal/contractabis"
)

func ecrecoverEIP191(message, signature []byte) (*ecdsa.PublicKey, error) {
	if len(signature) != objects.SignatureSize {
		return nil, fmt.Errorf("signature length is not %d", objects.SignatureSize)
	}

	sighash := accounts.TextHash(message)

	// update the recovery id
	// https://github.com/ethereum/go-ethereum/blob/55599ee95d4151a2502465e0afc7c47bd1acba77/internal/ethapi/api.go#L442
	signature[objects.SignatureSize-1] -= 27

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
	if len(publicKey) != objects.PublicKeySize {
		return fmt.Errorf("publicKey length is not %d", objects.PublicKeySize)
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

func verifyChallengeResponse(publicKey, challenge, signature []byte) error {
	return ecrecoverEIP191AndCompare(challenge, signature, publicKey)
}

// VerifyPatchSetSignature verifies the signature of the event
func VerifyPatchSetSignature(op *PatchSetWriteOp, publicKey []byte) error {
	// log("DEBUG.verifyPatchSetSignature headerBytes=%x", headerBytes)
	return ecrecoverEIP191AndCompare(op.headerData, op.decoded.Signature[:], publicKey)
}

func signEIP191(evtData []byte, secret *ecdsa.PrivateKey) (*objects.Signature, error) {
	sighash := accounts.TextHash(evtData)

	signature, err := crypto.Sign(sighash, secret)
	if err != nil {
		return nil, fmt.Errorf("signEvent: crypto.Sign failed: %w", err)
	}
	if len(signature) != 65 {
		return nil, fmt.Errorf("signEvent: signature length is not 65")
	}
	wrapped := objects.Signature(signature)
	return &wrapped, nil
}

// GetPaymentID calculates the payment ID for a given payment request.
//
// This could also be done via a contract api call but that would mean remote I/O
// for what is essentially hash(abi.encode(request)).
func GetPaymentID(payment contractsabi.PaymentRequest) ([]byte, error) {
	genabi, err := contractsabi.PaymentsByAddressMetaData.GetAbi()
	if err != nil {
		return nil, fmt.Errorf("GetPaymentId failed to construct ABI: %w", err)
	}

	encoded, err := genabi.Pack("getPaymentId", payment)
	if err != nil {
		return nil, fmt.Errorf("GetPaymentId failed to pack arguments: %w", err)
	}

	// take of the first 4 bytes (method id)
	encoded = encoded[4:]
	// fmt.Printf("encoded: %x\n", encoded)

	hash := crypto.Keccak256(encoded)
	return hash, nil
}
