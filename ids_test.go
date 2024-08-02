// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	tassert "github.com/stretchr/testify/assert"
	"testing"
)

func TestCombinedID(t *testing.T) {
	a := tassert.New(t)
	type tcase struct {
		variations []uint64
	}

	tests := []tcase{
		{},
		{[]uint64{1}},
		{[]uint64{1, 2, 3}},
	}

	for _, tc := range tests {
		cid := newCombinedID(42, tc.variations...)
		a.EqualValues(tc.variations, cid.Variations())
	}
}
