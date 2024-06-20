// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"crypto/subtle"
	"fmt"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func (c ethClient) verifyChallengeResponse(publicKey, challange, signature []byte) error {
	sighash := accounts.TextHash(challange)

	// update the recovery id
	// https://github.com/ethereum/go-ethereum/blob/55599ee95d4151a2502465e0afc7c47bd1acba77/internal/ethapi/api.go#L442
	signature[64] -= 27

	// get the pubkey used to sign this signature
	recovered, err := crypto.Ecrecover(sighash, signature)
	if err != nil {
		return fmt.Errorf("ecrecover: %w", err)
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

func (c ethClient) verifyKeyCardEnroll(keyCardPublicKey, signature []byte) (common.Address, error) {
	if len(signature) != 65 {
		return common.Address{}, fmt.Errorf("signature length is not 65")
	}

	if len(keyCardPublicKey) != 64 {
		return common.Address{}, fmt.Errorf("keyCardPublicKey length is not 64")
	}

	sighash := accounts.TextHash(keyCardPublicKey)

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

func (c ethClient) eventVerify(evt *SignedEvent, publicKey []byte) error {
	assert(evt != nil)
	sighash := accounts.TextHash(evt.Event.Value)

	signature := evt.Signature

	// update the recovery id
	// https://github.com/ethereum/go-ethereum/blob/55599ee95d4151a2502465e0afc7c47bd1acba77/internal/ethapi/api.go#L442
	signature[64] -= 27

	// get the pubkey used to sign this signature
	recovered, err := crypto.Ecrecover(sighash, signature)
	if err != nil {
		return fmt.Errorf("verifyEvent: ecrecover failed: %w", err)
	}

	if len(recovered) == 65 && recovered[0] == 0x04 {
		// split of encoding bit
		recovered = recovered[1:]
	}

	if subtle.ConstantTimeCompare(recovered, publicKey) != 1 {
		return fmt.Errorf("verifyEvent: keys are not equal")
	}

	return nil
}

func (c ethClient) eventSign(evtData []byte) ([]byte, error) {
	sighash := accounts.TextHash(evtData)

	signature, err := crypto.Sign(sighash, c.secret)
	if err != nil {
		return nil, fmt.Errorf("signEvent: crypto.Sign failed: %w", err)
	}

	return signature, nil
}
