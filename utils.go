// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"database/sql/driver"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/ethereum/go-ethereum/common"
)

var (
	isCIEnv  = os.Getenv("CI") != ""
	isDevEnv = os.Getenv("MASS_ENV") == "dev"
	isDebug  = os.Getenv("DEBUG") != ""
)

func logWrite(line string) {
	os.Stdout.Write([]byte(line))
	if isCIEnv {
		err := os.Stdout.Sync()
		check(err)
	}
}

func debug(msg string, args ...interface{}) {
	if !isDebug {
		return
	}
	log(msg, args...)
}

func log(msg string, args ...interface{}) {
	line := fmt.Sprintf(msg+"\n", args...)
	logWrite(line)
}

func logS(sessionID sessionID, msg string, args ...interface{}) {
	expandedMsg := fmt.Sprintf(msg, args...)
	sessionSuffix := fmt.Sprintf("sessionId=%d", sessionID)
	line := expandedMsg + " " + sessionSuffix + "\n"
	logWrite(line)
}

func logSR(msg string, sID sessionID, rID int64, args ...interface{}) {
	args = append(args, sID, rID)
	line := fmt.Sprintf(msg+" sessionId=%d requestId=%d\n", args...)
	logWrite(line)
}

func assert(testing bool) {
	if !testing {
		panic(fmt.Errorf("assertion failed"))
	}
}

func assertWithMessage(testing bool, message string) {
	if !testing {
		panic(fmt.Errorf(message))
	}
}

func assertNilError(err *Error) {
	assertWithMessage(err == nil, fmt.Sprintf("error was not nil: %+v", err))
}

func assertNonemptyString(s string) {
	assertWithMessage(s != "", "string was empty")
}

func validateObjectID(x *ObjectId, field string) *Error {
	if x == nil {
		return &Error{
			Code:    ErrorCodes_INVALID,
			Message: fmt.Sprintf("Field `%s` must be a non-zero objectId", field),
		}
	}
	return validateBytes(x.Raw, field+".id", 8)
}

func validateString(s string, field string, maxLength int) *Error {
	if s == "" {
		return &Error{
			Code:    ErrorCodes_INVALID,
			Message: fmt.Sprintf("Field `%s` must be a non-empty string", field),
		}
	}
	runeCount := utf8.RuneCountInString(s)
	if runeCount > maxLength {
		return &Error{
			Code:    ErrorCodes_INVALID,
			Message: fmt.Sprintf("Field `%s` must be no more than %d characters, got %d", field, maxLength, runeCount),
		}
	}
	return nil
}

const (
	publicKeyBytes = 64
	signatureBytes = 65
)

func validateBytes(val []byte, field string, want uint) *Error {
	if n := len(val); uint(n) != want {
		return &Error{
			Code:    ErrorCodes_INVALID,
			Message: fmt.Sprintf("Field `%s` must have correct amount of bytes, got %d", field, n),
		}
	}
	return nil
}

func validateChainID(val uint64, field string) *Error {
	if val == 0 {
		return &Error{
			Code:    ErrorCodes_INVALID,
			Message: fmt.Sprintf("Field `%s` must be a valid chainID, not 0", field)}

	}
	return nil
}

func (payee *Payee) validate(field string) *Error {
	return coalesce(
		validateString(payee.Name, field+".name", 128),
		payee.Address.validate(field+".address"),
		validateChainID(payee.ChainId, field+".chain_id"),
	)
}

func (pk *PublicKey) validate() *Error {
	return validateBytes(pk.Raw, "public_key", publicKeyBytes)
}

func (sig *Signature) validate() *Error {
	return validateBytes(sig.Raw, "signature", signatureBytes)
}

func (curr *ShopCurrency) validate(field string) *Error {
	return coalesce(
		curr.Address.validate(field+".address"),
		validateChainID(curr.ChainId, field+".chain_id"),
	)
}

func (addr *EthereumAddress) validate(field string) *Error {
	return validateEthAddressBytes(addr.Raw, field)
}

func validateEthAddressBytes(addr []byte, field string) *Error {
	return validateBytes(addr, field, 20)
}

func validateEthAddressHexString(k string, field string) *Error {
	if !common.IsHexAddress(k) {
		return &Error{Code: ErrorCodes_INVALID, Message: fmt.Sprintf("Field `%s` must be a valid ethereum address", field)}
	}
	return nil
}

func (lo *ListingOption) validate(field string) *Error {
	errs := []*Error{
		validateObjectID(lo.Id, field+".id"),
		validateString(lo.Title, field+".title", 512),
	}
	for i, v := range lo.Variations {
		field := field + fmt.Sprintf(".variation[%d]", i)
		errs = append(errs, v.validate(field))
	}
	return coalesce(errs...)
}

func (lv *ListingVariation) validate(field string) *Error {
	errs := []*Error{
		validateObjectID(lv.Id, field+".id"),
		lv.VariationInfo.validate(field + ".variation_info"),
	}
	return coalesce(errs...)

}

func (lm *ListingMetadata) validate(field string) *Error {
	errs := []*Error{
		validateString(lm.Title, field+".title", 512),
		validateString(lm.Description, field+".description", 512),
	}
	for i, img := range lm.Images {
		field := field + fmt.Sprintf(".image[%d]", i)
		errs = append(errs, validateURL(img, field))
	}
	return coalesce(errs...)
}

func (region *ShippingRegion) validate(field string) *Error {
	errs := []*Error{
		validateString(region.Name, field+".name", 128),
	}
	// if city is non-empty, the fields before it also have to be non-empty, etc.
	if region.PostalCode != "" && region.Country == "" {
		errs = append(errs, &Error{Code: ErrorCodes_INVALID, Message: field + ": country needs to be set if postal_code is"})
	}

	if region.City != "" && (region.PostalCode == "" || region.Country == "") {
		errs = append(errs, &Error{Code: ErrorCodes_INVALID, Message: field + ": country and postal_code need to be set if city is"})
	}
	for i, mod := range region.OrderPriceModifiers {
		modField := field + fmt.Sprintf(".order_price_modifier_id[%d]", i)
		errs = append(errs, mod.validate(modField))
	}
	return coalesce(errs...)
}

func (mod *OrderPriceModifier) validate(field string) *Error {
	errs := []*Error{
		validateString(mod.Title, field+".title", 128),
	}
	switch tv := mod.Modification.(type) {
	case *OrderPriceModifier_Absolute:
		abs := tv.Absolute
		errs = append(errs, abs.Diff.validate(field+".modification/absolute.diff"))
	case *OrderPriceModifier_Percentage:
		perc := tv.Percentage
		errs = append(errs, perc.validate(field+".modification/percentage"))
	default:
		errs = append(errs, &Error{Code: ErrorCodes_INVALID, Message: field + fmt.Sprintf(".modification: unhandled type: %T", tv)})
	}

	return coalesce(errs...)
}

func (i *Uint256) validate(field string) *Error {
	return validateBytes(i.Raw, field, 32)
}

func validateURL(k string, field string) *Error {
	if _, err := url.Parse(k); err != nil {
		return &Error{
			Code:    ErrorCodes_INVALID,
			Message: fmt.Sprintf("Field `%s` must be a valid URL", field),
		}
	}
	return nil
}

func assertLTE(v int, max int) {
	assertWithMessage(v <= max, fmt.Sprintf("value was greater than max: %d > %d", v, max))
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

var now = time.Now

func took(t time.Time) int64 {
	return time.Since(t).Milliseconds()
}

func tookF(t time.Time) float64 {
	return float64(time.Since(t).Milliseconds())
}

// ReusableTimer is a wrapper around time.Timer that allows for reusing the timer
type ReusableTimer struct {
	*time.Timer
	d time.Duration
}

// NewReusableTimer creates a new ReusableTimer
func NewReusableTimer(d time.Duration) ReusableTimer {
	return ReusableTimer{time.NewTimer(d), d}
}

// Rewind resets the timer to the duration it was created with
func (rt ReusableTimer) Rewind() {
	if !rt.Stop() {
		select {
		case <-rt.C:
		default:
		}
	}
	rt.Reset(rt.d)
}

// Environment variables

func mustGetEnvString(k string) string {
	v := os.Getenv(k)
	if v == "" {
		panic(fmt.Sprintf("Key not found in env: %s", k))
	}
	return v
}

func mustGetEnvInt(k string) int64 {
	vStr := mustGetEnvString(k)
	v, err := strconv.ParseInt(vStr, 10, 32)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse value in env as int: %s=%s", k, vStr))
	}
	return v
}

func mustGetEnvBool(k string) bool {
	vStr := mustGetEnvString(k)
	switch vStr {
	case "false":
		return false
	case "true":
		return true
	default:
		panic(fmt.Sprintf("Unexpected %s=%s", k, vStr))
	}
}

// SQLStringBigInt is a wrapper around big.Int that implements the sql.Scanner and driver.Valuer interfaces
type SQLStringBigInt struct{ big.Int }

// Value implements the driver.Valuer interface
func (bi SQLStringBigInt) Value() (driver.Value, error) {
	return bi.Int.String(), nil
}

// Scan implements the sql.Scanner interface
func (bi *SQLStringBigInt) Scan(src interface{}) error {
	switch src := src.(type) {
	case int64:
		bi.SetInt64(src)
	case string:
		parsed, _, err := big.ParseFloat(src, 10, 0, big.ToNearestEven)
		if err != nil {
			return fmt.Errorf("failed to parse BIGINT string value: %q", src)
		}
		_, _ = parsed.Int(&bi.Int)
	case []byte:
		bi.SetBytes(src)
	default:
		return fmt.Errorf("unsupported Scan source type: %T", src)
	}
	return nil
}
