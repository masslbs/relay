// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"encoding/binary"
	"slices"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"golang.org/x/crypto/sha3"
)

type sessionID uint64

type shopID uint64

type keyCardID uint64

type objectID uint64

type combinedID struct {
	listingID uint64

	// uint64 ids delimited by :
	// side-stepping the problem that you can't have a slice in a comparable struct
	variations string
}

func newCombinedID(listingID uint64, variations ...uint64) combinedID {
	slices.Sort(variations)
	varStr := make([]string, len(variations))
	for i, v := range variations {
		varStr[i] = strconv.FormatUint(v, 10)
	}
	return combinedID{
		listingID:  listingID,
		variations: strings.Join(varStr, ":"),
	}
}

func (cid combinedID) Variations() []uint64 {
	if cid.variations == "" {
		return nil
	}
	varStrs := strings.Split(cid.variations, ":")
	vids := make([]uint64, len(varStrs))
	var err error
	for i, vidstr := range varStrs {
		vids[i], err = strconv.ParseUint(vidstr, 10, 64)
		check(err)
	}

	return vids
}

func (cid combinedID) Hash() common.Hash {
	var buf [8]byte
	hasher := sha3.NewLegacyKeccak256()
	binary.BigEndian.PutUint64(buf[:], cid.listingID)
	hasher.Write(buf[:])

	if cid.variations != "" {
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
