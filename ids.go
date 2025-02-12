// SPDX-FileCopyrightText: 2024 - 2025 Mass Labs
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

// sessionID represents a unique identifier for a session
type sessionID uint64

// keyCardID represents a unique identifier for a key card
type keyCardID uint64

// ObjectIDArray is a fixed-size byte array representing an object ID
type ObjectIDArray [8]byte

var zeroObjectIDArr ObjectIDArray

// NewObjectIDArray converts the ObjectId to an ObjectIDArray
func NewObjectIDArray(obj uint64) ObjectIDArray {
	var arr ObjectIDArray
	binary.BigEndian.PutUint64(arr[:], obj)
	return arr
}

// // Uint64 converts the ObjectId to a uint64
// func (obj *ObjectId) Uint64() uint64 {
// 	assert(len(obj.Raw) == 8)
// 	return binary.BigEndian.Uint64(obj.Raw)
// }

// // Equal checks if two ObjectIds are equal
// func (obj *ObjectId) Equal(other *ObjectId) bool {
// 	return bytes.Equal(obj.Raw, other.Raw)
// }

// Equal checks if two ObjectIDArrays are equal
func (obj ObjectIDArray) Equal(other ObjectIDArray) bool {
	return bytes.Equal(obj[:], other[:])
}

// newShopObjectID creates a new ShopObjectIDArray from shop and object IDs
func newShopObjectID(shop, object ObjectIDArray) ShopObjectIDArray {
	var so ShopObjectIDArray
	copy(so[:8], shop[:])
	copy(so[8:], object[:])
	return so
}

// combinedID represents a listing ID with optional variations
type combinedID struct {
	listingID uint64

	// uint64 ids delimited by :
	// side-stepping the problem that you can't have a slice in a comparable struct
	variations string
}

const variationDelimiter = ":"

// newCombinedID creates a new combinedID from a listing ID and optional variations
func newCombinedID(listingID uint64, variations ...string) combinedID {
	cid := combinedID{
		listingID: listingID,
	}
	slices.Sort(variations)
	cid.variations = strings.Join(variations, variationDelimiter)
	return cid
}

// Variations returns the variation IDs as an array of ObjectIDArray
func (cid combinedID) Variations() []string {
	if cid.variations == "" {
		return nil
	}
	return strings.Split(cid.variations, variationDelimiter)
}

// Hash generates a Keccak256 hash of the combinedID
func (cid combinedID) Hash() common.Hash {
	hasher := sha3.NewLegacyKeccak256()
	binary.Write(hasher, binary.BigEndian, cid.listingID)

	if cid.variations != "" {
		var buf [8]byte
		varStrs := strings.Split(cid.variations, variationDelimiter)
		for _, vidStr := range varStrs {
			vid, err := strconv.ParseUint(vidStr, 10, 64)
			check(err)
			binary.BigEndian.PutUint64(buf[:], vid)
			hasher.Write(buf[:])
		}
	}
	return common.Hash(hasher.Sum(nil))
}
