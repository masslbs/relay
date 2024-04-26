// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"
)

const epoch = uint64(1704067200000) // TZ=UTC python3 -c "import time; print(int(time.mktime(time.strptime('2024-01-01', '%Y-%m-%d')) * 1000))"
const nanosInMilli = 1000000
const requestIDBytes = 16
const timeBytes = 5

type requestID []byte

func newRequestID() requestID {
	bytes := make([]byte, requestIDBytes)
	timeMillis := uint64(time.Now().UnixNano()/nanosInMilli) - epoch
	timeMillisShifted := timeMillis << (64 - (timeBytes * 8))
	binary.BigEndian.PutUint64(bytes, timeMillisShifted)
	_, err := rand.Read(bytes[timeBytes:])
	check(err)
	return bytes
}

func (id requestID) String() string {
	return fmt.Sprintf("reqID:%x", []byte(id))
}

func validateRequestID(id requestID, field string) *Error {
	if !checkRequestID(id) {
		return &Error{Code: ErrorCodes_invalid, Message: fmt.Sprintf("Field `%s` must be an request id", field)}
	}
	return nil
}

func (id requestID) Equal(other requestID) bool {
	id.assert()
	other.assert()
	for i := requestIDBytes - 1; i >= 0; i-- {
		if id[i] != other[i] {
			return false
		}
	}
	return true
}

func checkRequestID(id requestID) bool {
	return len(id) == requestIDBytes
}

func (id requestID) assert() {
	assertWithMessage(checkRequestID(id), fmt.Sprintf("%+v not a valid request id", id))
}

func mustRequestID(id requestID) requestID {
	id.assert()
	return id
}

type eventID []byte

func newEventID() eventID {
	bytes := make([]byte, eventIDBytes)
	_, err := rand.Read(bytes)
	check(err)
	return bytes
}
func (id eventID) String() string {
	return fmt.Sprintf("evtID:%x", []byte(id))
}

func (id eventID) Size() int {
	return eventIDBytes
}

const eventIDBytes = 32

func (id eventID) assert() {
	assertWithMessage(checkEventID(id), fmt.Sprintf("%+v not a valid event id", id))
}

func checkEventID(id eventID) bool {
	return len(id) == eventIDBytes
}

func assertEventIDsEqual(a, b eventID) {
	assertWithMessage(a.Equal(b), fmt.Sprintf("Expected event ids to be equal: %x %x", a, b))
}

func (id eventID) Equal(other eventID) bool {
	id.assert()
	other.assert()
	for i := eventIDBytes - 1; i >= 0; i-- {
		if id[i] != other[i] {
			return false
		}
	}
	return true
}
