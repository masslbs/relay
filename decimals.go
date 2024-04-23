// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: MIT

package main

import "github.com/cockroachdb/apd"

var (
	rounder apd.Rounder
	roundBy *apd.Decimal
)

func init() {
	var err error
	roundBy, _, err = apd.NewFromString("0.01")
	check(err)
	rounder = apd.Roundings[apd.RoundHalfUp]
}

func roundPrice(in *apd.Decimal) *apd.Decimal {
	ctx := apd.BaseContext.WithPrecision(20)
	ctx.Traps = apd.DefaultTraps
	out := new(apd.Decimal)
	_, err := ctx.Quantize(out, in, -2)
	check(err)
	// log("roundPrice: in=%s out=%s cond=%s", in, out, cond)
	return out
}
