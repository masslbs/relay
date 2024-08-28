// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts"
	tassert "github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"google.golang.org/protobuf/proto"
)

func TestVerifyEventVectors(t *testing.T) {
	r := require.New(t)
	a := tassert.New(t)
	schemaPath := os.Getenv("MASS_SCHEMA")
	if schemaPath == "" {
		t.Skip()
		return
	}

	tvd, err := os.ReadFile(filepath.Join(schemaPath, "testVectors.json"))
	r.NoError(err)

	var vect schemaTestVectors
	err = json.Unmarshal(tvd, &vect)
	r.NoError(err)
	t.Log("events:", len(vect.Events))

	for i, vectEvt := range vect.Events {
		t.Log("event:", i)
		var evt ShopEvent
		err = proto.Unmarshal(vectEvt.Encoded, &evt)
		r.NoError(err)
		t.Logf("type: %T", evt.Union)

		hash := accounts.TextHash(vectEvt.Encoded)

		a.Equal(true, bytes.Equal(vectEvt.Hash, hash))
	}
}

type schemaTestVectors struct {
	Signatures struct {
		ChainID         int       `json:"chain_id"`
		ContractAddress HexString `json:"contract_address"`
		SignerAddress   string    `json:"signer_address"`
	} `json:"signatures"`
	Events []struct {
		Type      string    `json:"type"`
		Signature HexString `json:"signature"`
		Hash      HexString `json:"hash"`
		Encoded   HexString `json:"encoded"`
	}
	Reduced struct{} `json:"reduced"`
}

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
