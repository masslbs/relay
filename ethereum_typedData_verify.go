// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

var eip712spec = []apitypes.Type{
	{Name: "name", Type: "string"},
	{Name: "version", Type: "string"},
	{Name: "chainId", Type: "uint256"},
	{Name: "verifyingContract", Type: "address"},
}

// TODO: extract signed data like with SignedMassEvent
func (c ethClient) verifyChallengeResponse(publicKey, challange, signature []byte) error {
	typedData := apitypes.TypedData{
		Types: map[string][]apitypes.Type{
			"EIP712Domain": eip712spec,
			"Challenge": {
				{Name: "challenge", Type: "string"},
			},
		},
		PrimaryType: "Challenge",
		Domain: apitypes.TypedDataDomain{
			Name:              "MassMarket",
			Version:           "1",
			ChainId:           math.NewHexOrDecimal256(int64(c.chainID)),
			VerifyingContract: c.contractAddresses.StoreRegistry.Hex(),
		},
		Message: map[string]any{"challenge": hex.EncodeToString(challange)},
	}
	// EIP-712 typed data marshalling
	sighash, _, err := apitypes.TypedDataAndHash(typedData)
	if err != nil {
		return fmt.Errorf("TypedDataAndHash error: %w", err)
	}

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
			ChainId:           math.NewHexOrDecimal256(int64(c.chainID)),
			VerifyingContract: c.contractAddresses.StoreRegistry.Hex(),
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

func findEventType(t apitypes.Types) (string, bool) {
	for _, k := range t["MassEvent"] {
		if k.Name == "event" {
			return k.Type, true
		}
	}
	return "", false
}

type typedDataMaper interface {
	typedDataMap() map[string]any
}

//go:embed gen_network_typedData.json
var genNetworkTypedData embed.FS

var eventToTypedData = make(apitypes.Types)

var parseEventToTypedDataOnce sync.Once

func parseEventToTypedData() {
	// check if we can parse the network-schema data into the apitypes struct
	data, err := genNetworkTypedData.ReadFile("gen_network_typedData.json")
	check(err)
	err = json.Unmarshal(data, &eventToTypedData)
	check(err)
}

func (c ethClient) eventHash(evt *Event) ([]byte, error) {
	parseEventToTypedDataOnce.Do(parseEventToTypedData)

	typeName, message := evt.typeAndTypedDataMap()

	tdTypeSpec, ok := eventToTypedData[typeName]
	if !ok {
		return nil, fmt.Errorf("Event.hash: no typed data specification for %s", typeName)
	}

	var usedTypeSpec []apitypes.Type
	// these two types follow the 'field=x oneof value' pattern
	// for these we ned to remove the fields from the spec that are not set
	// since we already omit the values from the message in TypeAndTypedDataMap()
	if um := evt.GetUpdateStoreManifest(); um != nil {
		usedTypeSpec = make([]apitypes.Type, 3)
		copy(usedTypeSpec, tdTypeSpec[:2])
		switch um.Field {
		case UpdateStoreManifest_MANIFEST_FIELD_DOMAIN:
			// keep type: string
			usedTypeSpec[2] = tdTypeSpec[2]
		case UpdateStoreManifest_MANIFEST_FIELD_PUBLISHED_TAG:
			// keep type: id
			usedTypeSpec[2] = tdTypeSpec[3]
		case UpdateStoreManifest_MANIFEST_FIELD_ADD_ERC20:
			// keep type: erc20_addr
			usedTypeSpec[2] = tdTypeSpec[4]
		case UpdateStoreManifest_MANIFEST_FIELD_REMOVE_ERC20:
			// keep type: erc20_addr
			usedTypeSpec[2] = tdTypeSpec[4]
		default:
			panic(fmt.Sprintf("eventHash: unknown updateManifest field: %v", um.Field))
		}
	} else if ui := evt.GetUpdateItem(); ui != nil {
		usedTypeSpec = make([]apitypes.Type, 4)
		copy(usedTypeSpec, tdTypeSpec[:3])
		switch ui.Field {
		case UpdateItem_ITEM_FIELD_PRICE:
			// keep type: price
			usedTypeSpec[3] = tdTypeSpec[3]
		case UpdateItem_ITEM_FIELD_METADATA:
			// keep type: metadata
			usedTypeSpec[3] = tdTypeSpec[4]
		default:
			panic(fmt.Sprintf("eventHash: unknown updateItem field: %v", ui.Field))
		}
	} else if cs := evt.GetChangeStock(); cs != nil && len(cs.CartId) == 0 {
		// for ChangeStock we need to remove the cart_id field if it's not set
		usedTypeSpec = tdTypeSpec[:3]
		delete(message, "cart_id")
		delete(message, "tx_hash")
	} else if cf := evt.GetCartFinalized(); cf != nil && len(cf.Erc20Addr) == 0 {
		// splice out erc20_addr
		usedTypeSpec = make([]apitypes.Type, len(tdTypeSpec)-1)
		copy(usedTypeSpec[:3], tdTypeSpec[:3])
		copy(usedTypeSpec[3:], tdTypeSpec[4:])
		delete(message, "erc20_addr")
	} else {
		usedTypeSpec = tdTypeSpec
	}

	typedData := apitypes.TypedData{
		Types: map[string][]apitypes.Type{
			"EIP712Domain": eip712spec,
			typeName:       usedTypeSpec,
		},
		PrimaryType: typeName,
		Domain: apitypes.TypedDataDomain{
			Name:              "MassMarket",
			Version:           "1",
			ChainId:           math.NewHexOrDecimal256(int64(c.chainID)),
			VerifyingContract: c.contractAddresses.StoreRegistry.Hex(),
		},
		Message: message,
	}

	// EIP-712 typed data marshalling
	sighash, _, err := apitypes.TypedDataAndHash(typedData)
	if err != nil {
		fmt.Printf("M:  %+v\n", message)
		fmt.Printf("used: %+v\n", usedTypeSpec)
		fmt.Printf("total: %+v\n", tdTypeSpec)
		return nil, fmt.Errorf("Event.hash: TypedDataAndHash error: %w", err)
	}

	log("Event.hash eventId=%x hash=%x", message["event_id"], sighash)
	return sighash, nil
}

func (c ethClient) eventVerify(evt *Event, publicKey []byte) error {
	assert(evt != nil)
	sighash, err := c.eventHash(evt)
	if err != nil {
		return err
	}

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

func (c ethClient) eventSign(evt *Event) error {
	sighash, err := c.eventHash(evt)
	if err != nil {
		return err
	}

	signature, err := crypto.Sign(sighash, c.secret)
	if err != nil {
		return fmt.Errorf("signEvent: crypto.Sign failed: %w", err)
	}

	evt.Signature = signature
	return nil
}
