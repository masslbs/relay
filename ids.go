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

// Array converts the ObjectId to an ObjectIDArray
func (obj *ObjectId) Array() ObjectIDArray {
	assert(len(obj.Raw) == 8)
	return [8]byte(obj.Raw)
}

// Uint64 converts the ObjectId to a uint64
func (obj *ObjectId) Uint64() uint64 {
	assert(len(obj.Raw) == 8)
	return binary.BigEndian.Uint64(obj.Raw)
}

// Equal checks if two ObjectIds are equal
func (obj *ObjectId) Equal(other *ObjectId) bool {
	return bytes.Equal(obj.Raw, other.Raw)
}

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
	listingID ObjectIDArray

	// uint64 ids delimited by :
	// side-stepping the problem that you can't have a slice in a comparable struct
	variations string
}

// newCombinedID creates a new combinedID from a listing ID and optional variations
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

// Variations returns the variation IDs as an array of ObjectIDArray
func (cid combinedID) Variations() []ObjectIDArray {
	if cid.variations == "" {
		return nil
	}
	var (
		varStrs = strings.Split(cid.variations, ":")
		vids    = make([]ObjectIDArray, len(varStrs))
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

// Hash generates a Keccak256 hash of the combinedID
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
