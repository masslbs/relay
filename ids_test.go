// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"encoding/binary"
	"slices"
	"testing"

	tassert "github.com/stretchr/testify/assert"
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
		{[]uint64{1, 3, 2}},
		{[]uint64{1, 2, 3, 4, 5}},
		{[]uint64{1, 5, 2, 3, 4}},
	}

	itemId := testObjIDs(42)[0]
	for tci, tc := range tests {
		cid := newCombinedID(itemId, testObjIDs(tc.variations...)...)
		got := cid.Variations()
		a.Len(got, len(tc.variations))
		slices.Sort(tc.variations)
		for i, g := range got {
			a.Equal(tc.variations[i], binary.BigEndian.Uint64(g[:]), "test: %d - var %d", tci, i)
		}
	}
}

func testObjIDs(ids ...uint64) []*ObjectId {
	objs := make([]*ObjectId, len(ids))
	for i, v := range ids {
		objs[i] = &ObjectId{
			Raw: make([]byte, 8),
		}
		binary.BigEndian.PutUint64(objs[i].Raw, v)
	}
	return objs
}
