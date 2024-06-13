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
	"reflect"
	"strings"
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
			VerifyingContract: c.contractAddresses.ShopRegistry.Hex(),
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
			VerifyingContract: c.contractAddresses.ShopRegistry.Hex(),
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

type typedDataMaper interface {
	typedDataMap() map[string]any
}

type typedDataFieldDefinition struct {
	apitypes.Type
	Message []apitypes.Type
}

var (

	//go:embed gen_network_typedData.json
	genNetworkTypedData embed.FS

	eventNestedTypes          = make(apitypes.Types)
	eventToTypedData          = make(apitypes.Types)
	parseEventToTypedDataOnce sync.Once
)

func parseEventToTypedData() {
	// check if we can parse the network-schema data into the apitypes struct
	data, err := genNetworkTypedData.ReadFile("gen_network_typedData.json")
	check(err)

	var allTheData map[string][]typedDataFieldDefinition
	err = json.Unmarshal(data, &allTheData)
	check(err)

	var cleanedUp = make(apitypes.Types)

	for typeName, fields := range allTheData {
		var prunedFields []apitypes.Type

		for _, field := range fields {

			if len(field.Message) > 0 {
				eventNestedTypes[field.Name] = field.Message
			} else {
				prunedFields = append(prunedFields, field.Type)
			}
		}

		cleanedUp[typeName] = prunedFields
	}

	eventToTypedData = cleanedUp
}

func (c ethClient) eventHash(evt *ShopEvent) ([]byte, error) {
	parseEventToTypedDataOnce.Do(parseEventToTypedData)

	typeName, message := evt.typeAndTypedDataMap()

	tdTypeSpec, ok := eventToTypedData[typeName]
	if !ok {
		return nil, fmt.Errorf("Event.hash: no typed data specification for %s", typeName)
	}

	var types = map[string][]apitypes.Type{
		"EIP712Domain": eip712spec,
	}

	var usedTypeSpec []apitypes.Type
	// these two types follow the 'field=x oneof value' pattern
	// for these we ned to remove the fields from the spec that are not set
	// since we already omit the values from the message in TypeAndTypedDataMap()
	if um := evt.GetUpdateShopManifest(); um != nil {
		usedTypeSpec = make([]apitypes.Type, 1)
		copy(usedTypeSpec[:1], tdTypeSpec[:1])
		if d := um.Domain; d != nil {
			usedTypeSpec = append(usedTypeSpec, apitypes.Type{
				Name: "domain",
				Type: "string",
			})
		}
		if n := um.Name; n != nil {
			usedTypeSpec = append(usedTypeSpec, apitypes.Type{
				Name: "name",
				Type: "string",
			})

		}
		if d := um.Description; d != nil {
			usedTypeSpec = append(usedTypeSpec, apitypes.Type{
				Name: "description",
				Type: "string",
			})
		}
		if p := um.ProfilePictureUrl; p != nil {
			usedTypeSpec = append(usedTypeSpec, apitypes.Type{
				Name: "profile_picture_url",
				Type: "string",
			})
		}
		if pt := um.PublishedTagId; len(pt) > 0 {
			usedTypeSpec = append(usedTypeSpec, apitypes.Type{
				Name: "published_tag_id",
				Type: "bytes32",
			})
		}
		if id := um.AddErc20Addr; len(id) > 0 {
			usedTypeSpec = append(usedTypeSpec, apitypes.Type{
				Name: "add_erc20_addr",
				Type: "address",
			})
		}
		if id := um.RemoveErc20Addr; len(id) > 0 {
			usedTypeSpec = append(usedTypeSpec, apitypes.Type{
				Name: "remove_erc20_addr",
				Type: "address",
			})
		}
	} else if ui := evt.GetUpdateItem(); ui != nil {
		usedTypeSpec = make([]apitypes.Type, 2)
		copy(usedTypeSpec, tdTypeSpec[:2])
		if p := ui.Price; p != nil {
			usedTypeSpec = append(usedTypeSpec, apitypes.Type{
				Name: "price",
				Type: "string",
			})
		}
		if meta := ui.Metadata; len(meta) > 0 {
			usedTypeSpec = append(usedTypeSpec, apitypes.Type{
				Name: "metadata",
				Type: "bytes",
			})
		}
	} else if ut := evt.GetUpdateTag(); ut != nil {
		usedTypeSpec = make([]apitypes.Type, 2)
		copy(usedTypeSpec, tdTypeSpec[:2])
		if id := ut.AddItemId; len(id) > 0 {
			usedTypeSpec = append(usedTypeSpec, apitypes.Type{
				Name: "add_item_id",
				Type: "bytes32",
			})
		}
		if id := ut.RemoveItemId; len(id) > 0 {
			usedTypeSpec = append(usedTypeSpec, apitypes.Type{
				Name: "remove_item_id",
				Type: "bytes32",
			})
		}
		if r := ut.Rename; r != nil {
			usedTypeSpec = append(usedTypeSpec, apitypes.Type{
				Name: "rename",
				Type: "string",
			})
		}
		if d := ut.Delete; d != nil {
			usedTypeSpec = append(usedTypeSpec, apitypes.Type{
				Name: "delete",
				Type: "bool",
			})
		}
	} else if cs := evt.GetChangeStock(); cs != nil && len(cs.OrderId) == 0 {
		// we need to remove these two fields if the change not related to an order
		usedTypeSpec = tdTypeSpec[:3]
		delete(message, "order_id")
		delete(message, "tx_hash")
	} else if uo := evt.GetUpdateOrder(); uo != nil {
		actionFieldName := uo.schemaFieldName()
		actionFieldSpec := eventNestedTypes[actionFieldName]

		usedTypeSpec = append(tdTypeSpec, apitypes.Type{Name: actionFieldName, Type: actionFieldName})

		fin, ok := uo.Action.(*UpdateOrder_ItemsFinalized_)
		if ok && len(fin.ItemsFinalized.CurrencyAddr) == 0 {
			// splice out currency_addr
			copiedSpec := make([]apitypes.Type, len(actionFieldSpec)-1)
			copy(copiedSpec, actionFieldSpec[:6])
			copy(copiedSpec[6:], actionFieldSpec[7:])
			actionFieldSpec = copiedSpec
		}
		types[actionFieldName] = actionFieldSpec
	} else {
		usedTypeSpec = tdTypeSpec
	}

	types[typeName] = usedTypeSpec

	typedData := apitypes.TypedData{
		Types:       types,
		PrimaryType: typeName,
		Domain: apitypes.TypedDataDomain{
			Name:              "MassMarket",
			Version:           "1",
			ChainId:           math.NewHexOrDecimal256(int64(c.chainID)),
			VerifyingContract: c.contractAddresses.ShopRegistry.Hex(),
		},
		Message: message,
	}

	// EIP-712 typed data marshalling
	sighash, _, err := apitypes.TypedDataAndHash(typedData)
	if err != nil {
		return nil, fmt.Errorf("TypedDataAndHash error: %w", err)
	}

	return sighash, nil
}

// TODO: codegen this mapping. parsing the struct tag every time is hideous
func (uo *UpdateOrder) schemaFieldName() string {
	rt := reflect.TypeOf(uo.Action).Elem()
	tag := rt.Field(0).Tag
	pbtag := tag.Get("protobuf")
	for _, val := range strings.Split(pbtag, ",") {
		if strings.HasPrefix(val, "name=") {
			fn := val[5:]
			return fn
		}
	}
	panic("unreachable")
}

func (c ethClient) eventVerify(evt *ShopEvent, publicKey []byte) error {
	assert(evt != nil)
	sighash, err := c.eventHash(evt)
	if err != nil {
		return fmt.Errorf("verifyEvent: failed to hash %T: %w", evt.Union, err)
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

func (c ethClient) eventSign(evt *ShopEvent) error {
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
