// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

// Generated from massmarket-network-schema:network/encoding.txt at network v3 (2125585d9649f1fb04379972d958345b093d4da4)
//lint:file-ignore U1000 Ignore all unused code, it's generated

package main

const schemaVersion = 3

func (op *StartOp) getSessionID() sessionID {
	return op.sessionID
}
func (op *StartOp) setErr(err *Error) {
	op.err = err
}

func (op *StopOp) getSessionID() sessionID {
	return op.sessionID
}
func (op *StopOp) setErr(err *Error) {
	op.err = err
}

func (op *HeartbeatOp) getSessionID() sessionID {
	return op.sessionID
}
func (op *HeartbeatOp) setErr(err *Error) {
	op.err = err
}

func (op *AuthenticateOp) getSessionID() sessionID {
	return op.sessionID
}
func (op *AuthenticateOp) setErr(err *Error) {
	op.err = err
}

func (op *ChallengeSolvedOp) getSessionID() sessionID {
	return op.sessionID
}
func (op *ChallengeSolvedOp) setErr(err *Error) {
	op.err = err
}

func (op *SyncStatusOp) getSessionID() sessionID {
	return op.sessionID
}
func (op *SyncStatusOp) setErr(err *Error) {
	op.err = err
}

func (op *EventWriteOp) getSessionID() sessionID {
	return op.sessionID
}
func (op *EventWriteOp) setErr(err *Error) {
	op.err = err
}

func (op *SubscriptionRequestOp) getSessionID() sessionID {
	return op.sessionID
}
func (op *SubscriptionRequestOp) setErr(err *Error) {
	op.err = err
}

func (op *SubscriptionCancelOp) getSessionID() sessionID {
	return op.sessionID
}
func (op *SubscriptionCancelOp) setErr(err *Error) {
	op.err = err
}

func (op *SubscriptionPushOp) getSessionID() sessionID {
	return op.sessionID
}
func (op *SubscriptionPushOp) setErr(err *Error) {
	op.err = err
}

func (op *GetBlobUploadURLOp) getSessionID() sessionID {
	return op.sessionID
}
func (op *GetBlobUploadURLOp) setErr(err *Error) {
	op.err = err
}
