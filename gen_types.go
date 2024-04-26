// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

// Generated from massmarket-network-schema:network/encoding.txt at network v2 (64d582e035063484932d49537ca0bb135c1cd36c)
//lint:file-ignore U1000 Ignore all unused code, it's generated

package main

import (
	"reflect"
)

const schemaVersion = 2

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

const typeEventWriteRequest = 3

func init() {
	networkMessage(3, EventWriteRequest{})
}
func (r *EventWriteRequest) getRequestID() requestID {
	return r.RequestId
}

func (r *EventWriteRequest) response(err *Error) Message {
	return &EventWriteResponse{RequestId: r.RequestId, Error: err}
}

const typeEventWriteResponse = 4

func init() {
	networkMessage(4, EventWriteResponse{})
}
func (r *EventWriteResponse) getRequestID() requestID {
	return r.RequestId
}

func (r *EventWriteResponse) getError() *Error {
	return r.Error
}

const typeSyncStatusRequest = 5

func init() {
	networkMessage(5, SyncStatusRequest{})
}
func (r *SyncStatusRequest) getRequestID() requestID {
	return r.RequestId
}

func (r *SyncStatusRequest) response(err *Error) Message {
	return &SyncStatusResponse{RequestId: r.RequestId, Error: err}
}

const typeSyncStatusResponse = 6

func init() {
	networkMessage(6, SyncStatusResponse{})
}
func (r *SyncStatusResponse) getRequestID() requestID {
	return r.RequestId
}

func (r *SyncStatusResponse) getError() *Error {
	return r.Error
}

const typeEventPushRequest = 7

func init() {
	networkMessage(7, EventPushRequest{})
}
func (r *EventPushRequest) getRequestID() requestID {
	return r.RequestId
}

func (r *EventPushRequest) response(err *Error) Message {
	return &EventPushResponse{RequestId: r.RequestId, Error: err}
}

const typeEventPushResponse = 8

func init() {
	networkMessage(8, EventPushResponse{})
}
func (r *EventPushResponse) getRequestID() requestID {
	return r.RequestId
}

func (r *EventPushResponse) getError() *Error {
	return r.Error
}

const typeAuthenticateRequest = 20

func init() {
	networkMessage(20, AuthenticateRequest{})
}
func (r *AuthenticateRequest) getRequestID() requestID {
	return r.RequestId
}

func (r *AuthenticateRequest) response(err *Error) Message {
	return &AuthenticateResponse{RequestId: r.RequestId, Error: err}
}

const typeAuthenticateResponse = 21

func init() {
	networkMessage(21, AuthenticateResponse{})
}
func (r *AuthenticateResponse) getRequestID() requestID {
	return r.RequestId
}

func (r *AuthenticateResponse) getError() *Error {
	return r.Error
}

const typeChallengeSolvedRequest = 22

func init() {
	networkMessage(22, ChallengeSolvedRequest{})
}
func (r *ChallengeSolvedRequest) getRequestID() requestID {
	return r.RequestId
}

func (r *ChallengeSolvedRequest) response(err *Error) Message {
	return &ChallengeSolvedResponse{RequestId: r.RequestId, Error: err}
}

const typeChallengeSolvedResponse = 23

func init() {
	networkMessage(23, ChallengeSolvedResponse{})
}
func (r *ChallengeSolvedResponse) getRequestID() requestID {
	return r.RequestId
}

func (r *ChallengeSolvedResponse) getError() *Error {
	return r.Error
}

const typeGetBlobUploadURLRequest = 30

func init() {
	networkMessage(30, GetBlobUploadURLRequest{})
}
func (r *GetBlobUploadURLRequest) getRequestID() requestID {
	return r.RequestId
}

func (r *GetBlobUploadURLRequest) response(err *Error) Message {
	return &GetBlobUploadURLResponse{RequestId: r.RequestId, Error: err}
}

const typeGetBlobUploadURLResponse = 31

func init() {
	networkMessage(31, GetBlobUploadURLResponse{})
}
func (r *GetBlobUploadURLResponse) getRequestID() requestID {
	return r.RequestId
}

func (r *GetBlobUploadURLResponse) getError() *Error {
	return r.Error
}

const typeCommitItemsToOrderRequest = 32

func init() {
	networkMessage(32, CommitItemsToOrderRequest{})
}
func (r *CommitItemsToOrderRequest) getRequestID() requestID {
	return r.RequestId
}

func (r *CommitItemsToOrderRequest) response(err *Error) Message {
	return &CommitItemsToOrderResponse{RequestId: r.RequestId, Error: err}
}

const typeCommitItemsToOrderResponse = 33

func init() {
	networkMessage(33, CommitItemsToOrderResponse{})
}
func (r *CommitItemsToOrderResponse) getRequestID() requestID {
	return r.RequestId
}

func (r *CommitItemsToOrderResponse) getError() *Error {
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

func (op *CommitItemsToOrderOp) getSessionID() requestID {
	return op.sessionID
}
func (op *CommitItemsToOrderOp) setErr(err *Error) {
	op.err = err
}

func (op *GetBlobUploadURLOp) getSessionID() requestID {
	return op.sessionID
}
func (op *GetBlobUploadURLOp) setErr(err *Error) {
	op.err = err
}
