// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

// Generated from massmarket-network-schema:network/encoding.txt at network v1 (16b1c68224ff0f7e2e080c83a779d2adeb532217)
//lint:file-ignore U1000 Ignore all unused code, it's generated

package main

import (
	"reflect"
)

const schemaVersion = 1

var typesNumToType = make(map[uint8]reflect.Type)
var typesTypePointerToNum = make(map[reflect.Type]uint8)

func networkMessage(typeNum uint8, typeInstance interface{}) {
	typeType := reflect.TypeOf(typeInstance)
	typeTypePointer := reflect.PtrTo(typeType)
	typesNumToType[typeNum] = typeType
	typesTypePointerToNum[typeTypePointer] = typeNum
}

const typePingRequest = 1

func init() {
	networkMessage(1, PingRequest{})
}
func (r *PingRequest) getRequestID() requestID {
	return r.RequestId
}

func (r *PingRequest) response(err *Error) Message {
	return &PingResponse{RequestId: r.RequestId, Error: err}
}

const typePingResponse = 2

func init() {
	networkMessage(2, PingResponse{})
}
func (r *PingResponse) getRequestID() requestID {
	return r.RequestId
}

func (r *PingResponse) getError() *Error {
	return r.Error
}

const typeAuthenticateRequest = 3

func init() {
	networkMessage(3, AuthenticateRequest{})
}
func (r *AuthenticateRequest) getRequestID() requestID {
	return r.RequestId
}

func (r *AuthenticateRequest) response(err *Error) Message {
	return &AuthenticateResponse{RequestId: r.RequestId, Error: err}
}

const typeAuthenticateResponse = 4

func init() {
	networkMessage(4, AuthenticateResponse{})
}
func (r *AuthenticateResponse) getRequestID() requestID {
	return r.RequestId
}

func (r *AuthenticateResponse) getError() *Error {
	return r.Error
}

const typeChallengeSolvedRequest = 5

func init() {
	networkMessage(5, ChallengeSolvedRequest{})
}
func (r *ChallengeSolvedRequest) getRequestID() requestID {
	return r.RequestId
}

func (r *ChallengeSolvedRequest) response(err *Error) Message {
	return &ChallengeSolvedResponse{RequestId: r.RequestId, Error: err}
}

const typeChallengeSolvedResponse = 6

func init() {
	networkMessage(6, ChallengeSolvedResponse{})
}
func (r *ChallengeSolvedResponse) getRequestID() requestID {
	return r.RequestId
}

func (r *ChallengeSolvedResponse) getError() *Error {
	return r.Error
}

const typeGetBlobUploadURLRequest = 9

func init() {
	networkMessage(9, GetBlobUploadURLRequest{})
}
func (r *GetBlobUploadURLRequest) getRequestID() requestID {
	return r.RequestId
}

func (r *GetBlobUploadURLRequest) response(err *Error) Message {
	return &GetBlobUploadURLResponse{RequestId: r.RequestId, Error: err}
}

const typeGetBlobUploadURLResponse = 10

func init() {
	networkMessage(10, GetBlobUploadURLResponse{})
}
func (r *GetBlobUploadURLResponse) getRequestID() requestID {
	return r.RequestId
}

func (r *GetBlobUploadURLResponse) getError() *Error {
	return r.Error
}

const typeEventWriteRequest = 13

func init() {
	networkMessage(13, EventWriteRequest{})
}
func (r *EventWriteRequest) getRequestID() requestID {
	return r.RequestId
}

func (r *EventWriteRequest) response(err *Error) Message {
	return &EventWriteResponse{RequestId: r.RequestId, Error: err}
}

const typeEventWriteResponse = 14

func init() {
	networkMessage(14, EventWriteResponse{})
}
func (r *EventWriteResponse) getRequestID() requestID {
	return r.RequestId
}

func (r *EventWriteResponse) getError() *Error {
	return r.Error
}

const typeSyncStatusRequest = 15

func init() {
	networkMessage(15, SyncStatusRequest{})
}
func (r *SyncStatusRequest) getRequestID() requestID {
	return r.RequestId
}

func (r *SyncStatusRequest) response(err *Error) Message {
	return &SyncStatusResponse{RequestId: r.RequestId, Error: err}
}

const typeSyncStatusResponse = 16

func init() {
	networkMessage(16, SyncStatusResponse{})
}
func (r *SyncStatusResponse) getRequestID() requestID {
	return r.RequestId
}

func (r *SyncStatusResponse) getError() *Error {
	return r.Error
}

const typeEventPushRequest = 17

func init() {
	networkMessage(17, EventPushRequest{})
}
func (r *EventPushRequest) getRequestID() requestID {
	return r.RequestId
}

func (r *EventPushRequest) response(err *Error) Message {
	return &EventPushResponse{RequestId: r.RequestId, Error: err}
}

const typeEventPushResponse = 18

func init() {
	networkMessage(18, EventPushResponse{})
}
func (r *EventPushResponse) getRequestID() requestID {
	return r.RequestId
}

func (r *EventPushResponse) getError() *Error {
	return r.Error
}

const typeCommitCartRequest = 19

func init() {
	networkMessage(19, CommitCartRequest{})
}
func (r *CommitCartRequest) getRequestID() requestID {
	return r.RequestId
}

func (r *CommitCartRequest) response(err *Error) Message {
	return &CommitCartResponse{RequestId: r.RequestId, Error: err}
}

const typeCommitCartResponse = 20

func init() {
	networkMessage(20, CommitCartResponse{})
}
func (r *CommitCartResponse) getRequestID() requestID {
	return r.RequestId
}

func (r *CommitCartResponse) getError() *Error {
	return r.Error
}

func (op *StartOp) getSessionID() requestID {
	return op.sessionID
}
func (op *StartOp) setErr(err *Error) {
	op.err = err
}

func (op *StopOp) getSessionID() requestID {
	return op.sessionID
}
func (op *StopOp) setErr(err *Error) {
	op.err = err
}

func (op *HeartbeatOp) getSessionID() requestID {
	return op.sessionID
}
func (op *HeartbeatOp) setErr(err *Error) {
	op.err = err
}

func (op *AuthenticateOp) getSessionID() requestID {
	return op.sessionID
}
func (op *AuthenticateOp) setErr(err *Error) {
	op.err = err
}

func (op *ChallengeSolvedOp) getSessionID() requestID {
	return op.sessionID
}
func (op *ChallengeSolvedOp) setErr(err *Error) {
	op.err = err
}

func (op *SyncStatusOp) getSessionID() requestID {
	return op.sessionID
}
func (op *SyncStatusOp) setErr(err *Error) {
	op.err = err
}

func (op *EventWriteOp) getSessionID() requestID {
	return op.sessionID
}
func (op *EventWriteOp) setErr(err *Error) {
	op.err = err
}

func (op *EventPushOp) getSessionID() requestID {
	return op.sessionID
}
func (op *EventPushOp) setErr(err *Error) {
	op.err = err
}

func (op *CommitCartOp) getSessionID() requestID {
	return op.sessionID
}
func (op *CommitCartOp) setErr(err *Error) {
	op.err = err
}

func (op *GetBlobUploadURLOp) getSessionID() requestID {
	return op.sessionID
}
func (op *GetBlobUploadURLOp) setErr(err *Error) {
	op.err = err
}
