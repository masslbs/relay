// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: MIT

package main

import (
	"database/sql/driver"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/cockroachdb/apd"
	"github.com/ethereum/go-ethereum/common"
)

var (
	isCIEnv  = os.Getenv("CI") != ""
	isDevEnv = os.Getenv("MASS_ENV") == "dev"
)

func logWrite(line string) {
	os.Stdout.Write([]byte(line))
	if isCIEnv {
		err := os.Stdout.Sync()
		check(err)
	}
}

func log(msg string, args ...interface{}) {
	line := fmt.Sprintf(msg+"\n", args...)
	logWrite(line)
}

func logS(sessionID requestID, msg string, args ...interface{}) {
	expandedMsg := fmt.Sprintf(msg, args...)
	sessionSuffix := fmt.Sprintf("sessionId=%s", sessionID)
	line := expandedMsg + " " + sessionSuffix + "\n"
	logWrite(line)
}

func logSR(msg string, sID, rID requestID, args ...interface{}) {
	args = append(args, sID, rID)
	line := fmt.Sprintf(msg+" sessionId=%s requestId=%s\n", args...)
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

func validateString(s string, field string, maxLength int) *Error {
	if s == "" {
		return &Error{Code: invalidErrorCode, Message: fmt.Sprintf("Field `%s` must be a non-empty string", field)}
	}
	runeCount := utf8.RuneCountInString(s)
	if runeCount > maxLength {
		return &Error{Code: invalidErrorCode, Message: fmt.Sprintf("Field `%s` must be no more than %d characters, got %d", field, maxLength, runeCount)}
	}
	return nil
}

const (
	publicKeyBytes = 64
	signatureBytes = 65
)

func validateBytes(val []byte, field string, want uint) *Error {
	if n := len(val); uint(n) != want {
		return &Error{Code: invalidErrorCode, Message: fmt.Sprintf("Field `%s` must have correct amount of bytes, got %d", field, n)}
	}
	return nil
}

func validateEventID(k []byte, field string) *Error {
	return validateBytes(k, field, eventIDBytes)
}

func validateEthAddressBytes(addr []byte, field string) *Error {
	return validateBytes(addr, field, 20)
}

func validateEthAddressHexString(k string, field string) *Error {
	if !common.IsHexAddress(k) {
		return &Error{Code: invalidErrorCode, Message: fmt.Sprintf("Field `%s` must be a valid ethereum address", field)}
	}
	return nil
}

func validateURL(k string, field string) *Error {
	if _, err := url.Parse(k); err != nil {
		return &Error{Code: invalidErrorCode, Message: fmt.Sprintf("Field `%s` must be a valid URL", field)}
	}
	return nil
}

// regexp that checks for two decimal places at the end of a string
var decimalRegex = regexp.MustCompile(`^\d+\.\d{2}$`)

func validateDecimalPrice(value string, field string) *Error {
	if !decimalRegex.MatchString(value) {
		return &Error{Code: invalidErrorCode, Message: fmt.Sprintf("Field `%s` does not have two decimal places", field)}
	}
	// check if the value has 8 or less digits before the decimal point
	if len(value) > 11 {
		return &Error{Code: invalidErrorCode, Message: fmt.Sprintf("Field `%s` must have 8 or less digits before the decimal point", field)}
	}
	parsed, _, err := apd.NewFromString(value)
	if err != nil {
		return &Error{Code: invalidErrorCode, Message: fmt.Sprintf("Field `%s` must be a valid decimal number", field)}
	}
	if parsed.Cmp(apd.New(0, 0)) < 0 {
		return &Error{Code: invalidErrorCode, Message: fmt.Sprintf("Field `%s` must be a positive number", field)}
	}
	return nil
}

func assertLTE(v int, max int) {
	assertWithMessage(v <= max, fmt.Sprintf("value was greater than max: %d > %d", v, max))
}

func assertOneOfEvent(es *EventState) {
	has := 0
	if es.storeManifest != nil {
		has++
	}
	if es.updateManifest != nil {
		has++
	}
	if es.createItem != nil {
		has++
	}
	if es.updateItem != nil {
		has++
	}
	if es.createTag != nil {
		has++
	}
	if es.addToTag != nil {
		has++
	}
	if es.removeFromTag != nil {
		has++
	}
	if es.renameTag != nil {
		has++
	}
	if es.deleteTag != nil {
		has++
	}
	if es.createCart != nil {
		has++
	}
	if es.changeCart != nil {
		has++
	}
	if es.cartFinalized != nil {
		has++
	}
	if es.changeStock != nil {
		has++
	}
	if es.cartAbandoned != nil {
		has++
	}
	if es.newKeyCard != nil {
		has++
	}
	assertWithMessage(has == 1, fmt.Sprintf("eventState has %d entries", has))
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
	default:
		return fmt.Errorf("unsupported Scan source type: %T", src)
	}
	return nil
}
