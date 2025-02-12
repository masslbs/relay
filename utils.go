// SPDX-FileCopyrightText: 2024 - 2025 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"database/sql/driver"
	"encoding/binary"
	"fmt"
	"math/big"
	"os"
	"slices"
	"strconv"
	"time"

	"github.com/masslbs/network-schema/go/objects"
	pb "github.com/masslbs/network-schema/go/pb"
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

func assertNilError(err *pb.Error) {
	assertWithMessage(err == nil, fmt.Sprintf("error was not nil: %+v", err))
}

func assertNonemptyString(s string) {
	assertWithMessage(s != "", "string was empty")
}

const (
	publicKeyBytes = objects.PublicKeySize
	signatureBytes = objects.SignatureSize
)

func validateBytes(val []byte, field string, want uint) *pb.Error {
	if n := len(val); uint(n) != want {
		return &pb.Error{
			Code:    pb.ErrorCodes_INVALID,
			Message: fmt.Sprintf("Field `%s` must have correct amount of bytes (got %d, want %d)", field, n, want),
		}
	}
	return nil
}

func validatePublicKey(pk *pb.PublicKey) *pb.Error {
	return validateBytes(pk.Raw, "public_key", publicKeyBytes)
}

func validateSignature(sig *pb.Signature) *pb.Error {
	return validateBytes(sig.Raw, "signature", signatureBytes)
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

// SQLUint64Bytes is a wrapper around big.Int that implements the sql.Scanner and driver.Valuer interfaces
type SQLUint64Bytes struct{ Data ObjectIDArray }

// Value implements the driver.Valuer interface
func (ui SQLUint64Bytes) Value() (driver.Value, error) {
	return ui.Data[:], nil
}

// Scan implements the sql.Scanner interface
func (ui *SQLUint64Bytes) Scan(src interface{}) error {
	switch src := src.(type) {

	case []byte:
		if len(src) != 8 {
			return fmt.Errorf("expected 8 bytes, got %d", len(src))
		}
		copy(ui.Data[:], src)
	default:
		return fmt.Errorf("unsupported Scan source type: %T", src)
	}
	return nil
}

// Uint64 returns the uint64 value of the SQLUint64Bytes
func (ui *SQLUint64Bytes) Uint64() uint64 {
	return binary.BigEndian.Uint64(ui.Data[:])
}

// ScoreRegions compares all configured regions to a chosen address and picks the one most applicable.
func ScoreRegions(configured objects.ShippingRegions, chosen *objects.AddressDetails) (string, error) {
	type score struct {
		Name   string
		Points int
	}
	var scores []score

	for k, r := range configured {
		var s = score{
			Name: k,
		}

		if r.Country == chosen.Country || r.Country == "" {
			if r.Country == "" {
				s.Points++
			} else {
				s.Points += 10
			}
			if r.PostalCode == chosen.PostalCode {
				s.Points += 100
				if r.City == chosen.City {
					s.Points += 1000
				}
			}

			scores = append(scores, s)
		}
	}

	if len(scores) == 0 {
		return "", fmt.Errorf("no shipping region matched")
	}

	//spew.Dump(scores)

	if len(scores) > 1 {
		// sort highest points first
		slices.SortFunc(scores, func(a, b score) int {
			if a.Points > b.Points {
				return -1
			}
			if a.Points < b.Points {
				return 1
			}
			// eq
			return 0
		})
	}

	_, has := configured[scores[0].Name]
	assert(has)
	return scores[0].Name, nil
}
