// SPDX-FileCopyrightText: 2024 - 2025 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
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
