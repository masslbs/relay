// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: MIT

package main

import (
	"testing"

	"github.com/cockroachdb/apd"
)

func TestRounding(t *testing.T) {
	var tcases = []struct {
		In  string
		Out string
	}{
		{"0.123456", "0.12"},
		{"123.456", "123.46"},
	}

	for _, tc := range tcases {
		in, _, err := apd.NewFromString(tc.In)
		if err != nil {
			t.Fatalf("apd.NewFromString(%s) failed: %v", tc.In, err)
		}
		out := roundPrice(in)
		if out.String() != tc.Out {
			t.Errorf("round(%s) = %s, want %s", tc.In, out, tc.Out)
		}
	}
}
