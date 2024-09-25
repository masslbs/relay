// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/binary"
	"slices"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"golang.org/x/crypto/sha3"
)

type sessionID uint64

// TODO: obsolete?
type keyCardID uint64

type ObjectIdArray [8]byte

func (obj ObjectId) Array() ObjectIdArray {
	assert(len(obj.Raw) == 8)
	return [8]byte(obj.Raw)
}

func (obj ObjectId) Uint64() uint64 {
	assert(len(obj.Raw) == 8)
	return binary.BigEndian.Uint64(obj.Raw)
}

func (obj ObjectId) Equal(other *ObjectId) bool {
	return bytes.Equal(obj.Raw, other.Raw)
}

func (obj ObjectIdArray) Equal(other ObjectIdArray) bool {
	return bytes.Equal(obj[:], other[:])
}

func newShopObjectID(shop, object ObjectIdArray) ShopObjectIDArray {
	var so ShopObjectIDArray
	copy(so[:8], shop[:])
	copy(so[8:], object[:])
	return so
}

// TODO: rename listingWithVarsID
type combinedID struct {
	listingID ObjectIdArray

	// uint64 ids delimited by :
	// side-stepping the problem that you can't have a slice in a comparable struct
	variations string
}

func newCombinedID(listingID *ObjectId, variations ...*ObjectId) combinedID {
	cid := combinedID{
		listingID: listingID.Array(),
	}
	uints := make([]uint64, len(variations))
	varStr := make([]string, len(variations))
	for i, v := range variations {
		uints[i] = v.Uint64()
	}
	slices.Sort(uints)
	for i, v := range uints {
		varStr[i] = strconv.FormatUint(v, 10)
	}
	cid.variations = strings.Join(varStr, ":")
	return cid
}

func (cid combinedID) Variations() []ObjectIdArray {
	if cid.variations == "" {
		return nil
	}
	var (
		varStrs = strings.Split(cid.variations, ":")
		vids    = make([]ObjectIdArray, len(varStrs))
		err     error
		num     uint64
	)
	for i, vidstr := range varStrs {
		num, err = strconv.ParseUint(vidstr, 10, 64)
		check(err)
		binary.BigEndian.PutUint64(vids[i][:], num)
	}
	return vids
}

func (cid combinedID) Hash() common.Hash {
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(cid.listingID[:])

	if cid.variations != "" {
		var buf [8]byte
		varStrs := strings.Split(cid.variations, ":")
		for _, vidStr := range varStrs {
			vid, err := strconv.ParseUint(vidStr, 10, 64)
			check(err)
			binary.BigEndian.PutUint64(buf[:], vid)
			hasher.Write(buf[:])
		}
	}
	return common.Hash(hasher.Sum(nil))
}
