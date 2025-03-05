// SPDX-FileCopyrightText: 2024 - 2025 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	gclone "github.com/huandu/go-clone/generic"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	cbor "github.com/masslbs/network-schema/go/cbor"
	"github.com/masslbs/network-schema/go/objects"
	"github.com/masslbs/network-schema/go/patch"
	pb "github.com/masslbs/network-schema/go/pb"
	contractsabi "github.com/masslbs/relay/internal/contractabis"
)

// SessionOp are operations that are sent to the database and are specific to a session
type SessionOp interface {
	handle(*Session)
}

// RelayOp are operations that are sent to the database
type RelayOp interface {
	process(*Relay)
}

// StartOp starts a session
type StartOp struct {
	sessionID      sessionID
	sessionVersion uint
	sessionOps     chan SessionOp
}

// StopOp stops a session
type StopOp struct {
	sessionID sessionID
}

// HeartbeatOp triggers a PingRequest to the connected client
type HeartbeatOp struct {
	sessionID sessionID
}

// AuthenticateOp starts authentication of a session
type AuthenticateOp struct {
	sessionID sessionID
	requestID *pb.RequestId
	im        *pb.AuthenticateRequest
	err       *pb.Error
	challenge []byte
}

// ChallengeSolvedOp finishes authentication of a session
type ChallengeSolvedOp struct {
	sessionID sessionID
	requestID *pb.RequestId
	im        *pb.ChallengeSolvedRequest
	err       *pb.Error
}

// SyncStatusOp sends a SyncStatusRequest to the client
type SyncStatusOp struct {
	sessionID       sessionID
	subscriptionID  uint16
	unpushedPatches uint64
}

// PatchSetWriteOp processes a write of an event to the database
type PatchSetWriteOp struct {
	sessionID sessionID
	requestID *pb.RequestId
	im        *pb.PatchSetWriteRequest
	// derived from im
	decoded    *patch.SignedPatchSet
	headerData []byte
	proofs     [][]byte
	// response data
	newShopHash objects.Hash
	err         *pb.Error
}

// SubscriptionRequestOp represents an operation to request a subscription.
// It contains the session ID, request ID, subscription request details,
// the ID of the subscription to be created, and an error if any.
type SubscriptionRequestOp struct {
	sessionID      sessionID
	requestID      *pb.RequestId
	im             *pb.SubscriptionRequest
	subscriptionID uint16
	err            *pb.Error
}

// SubscriptionCancelOp represents an operation to cancel a subscription.
// It contains the session ID, request ID, and the subscription cancel request details.
type SubscriptionCancelOp struct {
	sessionID sessionID
	requestID *pb.RequestId
	im        *pb.SubscriptionCancelRequest
	err       *pb.Error
}

// SubscriptionPushOp represents an operation to push events to the client.
// It contains the session ID, subscription ID, and the list of event states to push.
type SubscriptionPushOp struct {
	sessionID      sessionID
	subscriptionID uint16
	pushStates     []*PushStates
}

// GetBlobUploadURLOp processes a GetBlobUploadURLRequest from the client.
type GetBlobUploadURLOp struct {
	sessionID sessionID
	requestID *pb.RequestId
	im        *pb.GetBlobUploadURLRequest
	uploadURL *url.URL
	err       *pb.Error
}

// Internal Ops

// EventLoopPingInternalOp is used by the health check
// to make sure relay.run() is responsive
type EventLoopPingInternalOp struct {
	done chan<- struct{}
}

// NewEventLoopPing creates a new EventLoopPingInternalOp
func NewEventLoopPing() (<-chan struct{}, *EventLoopPingInternalOp) {
	ch := make(chan struct{})
	op := &EventLoopPingInternalOp{
		done: ch,
	}
	return ch, op
}

// KeyCardEnrolledInternalOp is triggered by a successful keycard enrollment.
// It results in a KeyCardEnrolled Event on the shops log
type KeyCardEnrolledInternalOp struct {
	shopNFT          big.Int
	keyCardIsGuest   bool
	keyCardPublicKey objects.PublicKey
	userWallet       objects.EthereumAddress
	done             chan error
}

// OnchainActionInternalOp are the result of on-chain access control changes of a shop
type OnchainActionInternalOp struct {
	shopID ObjectIDArray
	user   common.Address
	add    bool
	txHash common.Hash
}

// PaymentFoundInternalOp is created by payment watchers
type PaymentFoundInternalOp struct {
	orderID   ObjectIDArray
	shopID    ObjectIDArray
	txHash    *common.Hash
	blockHash common.Hash

	done chan struct{}
}

func (op *StopOp) handle(sess *Session) {
	logS(sess.id, "session.stopOp")
	sess.stopping = true
}

func handlePingResponse(sess *Session, _ *pb.RequestId, resp *pb.Envelope_GenericResponse) {
	assertNilError(resp.GetError())
	op := &HeartbeatOp{
		sessionID: sess.id,
	}
	sess.sendDatabaseOp(op)
}

func (op *AuthenticateOp) handle(sess *Session) {
	resp := newGenericResponse(op.err)
	if op.err == nil {
		resp.Response = &pb.Envelope_GenericResponse_Payload{Payload: op.challenge}
	}
	sess.writeResponse(op.requestID, resp)
}

func (op *ChallengeSolvedOp) handle(sess *Session) {
	resp := newGenericResponse(op.err)
	sess.writeResponse(op.requestID, resp)
}

func (op *SyncStatusOp) handle(sess *Session) {
	reqID := sess.nextRequestID()
	msg := &pb.Envelope_SyncStatusRequest{
		SyncStatusRequest: &pb.SyncStatusRequest{
			SubscriptionId:  uint64(op.subscriptionID),
			UnpushedPatches: op.unpushedPatches,
		},
	}
	sess.writeRequest(reqID, msg)
}

func handleSyncStatusResponse(sess *Session, _ *pb.RequestId, resp *pb.Envelope_GenericResponse) {
	assertNilError(resp.GetError())
	op := &HeartbeatOp{sessionID: sess.id}
	sess.sendDatabaseOp(op)
}

func (op *GetBlobUploadURLOp) handle(sess *Session) {
	resp := newGenericResponse(op.err)
	if op.err == nil {
		resp.Response = &pb.Envelope_GenericResponse_Payload{
			Payload: []byte(op.uploadURL.String()),
		}
	}
	sess.writeResponse(op.requestID, resp)
}

func (op *PatchSetWriteOp) handle(sess *Session) {
	om := newGenericResponse(op.err)
	if op.err == nil {
		om.Response = &pb.Envelope_GenericResponse_Payload{
			Payload: op.newShopHash[:],
		}
	}
	sess.writeResponse(op.requestID, om)
}

func (op *SubscriptionPushOp) handle(sess *Session) {
	assertLTE(len(op.pushStates), limitMaxOutBatchSize)
	patches := make([]*pb.SubscriptionPushRequest_SequencedPatch, len(op.pushStates))
	for i, pushState := range op.pushStates {
		assert(pushState.shopSeq != 0)
		patches[i] = &pb.SubscriptionPushRequest_SequencedPatch{
			ShopSeqNo:      pushState.shopSeq,
			PatchLeafIndex: pushState.leafIndex,
			PatchData:      pushState.patchData,
			MmrProof:       pushState.patchInclProof,
		}
	}
	var meta = make(map[uint64]*pb.SubscriptionPushRequest_PatchSetMeta)
	for _, pushState := range op.pushStates {
		_, has := meta[pushState.shopSeq]
		if has {
			continue
		}
		meta[pushState.shopSeq] = &pb.SubscriptionPushRequest_PatchSetMeta{
			Header:    pushState.psHeader,
			Signature: pushState.psSignature,
		}
	}

	spr := &pb.Envelope_SubscriptionPushRequest{
		SubscriptionPushRequest: &pb.SubscriptionPushRequest{
			Patches:      patches,
			PatchSetMeta: meta,
		},
	}
	reqID := sess.nextRequestID()
	sess.activePushes.Set(reqID.Raw, op)
	sess.writeRequest(reqID, spr)
}

func handleSubscriptionPushResponse(sess *Session, reqID *pb.RequestId, resp *pb.Envelope_GenericResponse) {
	assertNilError(resp.GetError())
	op := sess.activePushes.Get(reqID.Raw).(*SubscriptionPushOp)
	sess.activePushes.Delete(reqID.Raw)
	sess.sendDatabaseOp(op)
}

func (op *SubscriptionRequestOp) handle(sess *Session) {
	om := newGenericResponse(op.err)
	if op.err == nil {
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, op.subscriptionID)
		om.Response = &pb.Envelope_GenericResponse_Payload{Payload: buf}
	}
	sess.writeResponse(op.requestID, om)
}

func (op *SubscriptionCancelOp) handle(sess *Session) {
	om := newGenericResponse(op.err)
	sess.writeResponse(op.requestID, om)
}

// database processing

func (op *StartOp) process(r *Relay) {
	assert(!r.sessionIDsToSessionStates.Has(op.sessionID))
	assert(op.sessionVersion != 0)
	assert(op.sessionOps != nil)
	logS(op.sessionID, "relay.startOp.start")
	sessionState := &SessionState{
		keyCardOfAGuest: true,
		version:         op.sessionVersion,
		sessionOps:      op.sessionOps,
		subscriptions:   make(map[uint16]*SubscriptionState),
	}
	r.sessionIDsToSessionStates.Set(op.sessionID, sessionState)
	r.lastSeenAtTouch(sessionState)
}

func (op *StopOp) process(r *Relay) {
	sessionState, sessionExists := r.sessionIDsToSessionStates.GetHas(op.sessionID)
	logS(op.sessionID, "relay.stopOp.start exists=%t", sessionExists)
	if sessionExists {
		r.sessionIDsToSessionStates.Delete(op.sessionID)
		r.sendSessionOp(sessionState, op)
	}
}

func (op *HeartbeatOp) process(r *Relay) {
	sessionState := r.sessionIDsToSessionStates.Get(op.sessionID)
	if sessionState == nil {
		logS(op.sessionID, "relay.heartbeatOp.drain")
		return
	}
	r.lastSeenAtTouch(sessionState)
}

func (op *AuthenticateOp) process(r *Relay) {
	// Make sure the session isn't gone or already authenticated.
	sessionState := r.sessionIDsToSessionStates.Get(op.sessionID)
	if sessionState == nil {
		logS(op.sessionID, "relay.authenticateOp.drain")
		return
	} else if sessionState.keyCardID != 0 {
		logS(op.sessionID, "relay.authenticateOp.alreadyAuthenticated")
		op.err = alreadyAuthenticatedError
		r.sendSessionOp(sessionState, op)
		return
	}

	logS(op.sessionID, "relay.authenticateOp.start")
	authenticateOpStart := now()

	var keyCardID keyCardID
	var shopID uint64
	logS(op.sessionID, "relay.authenticateOp.idsQuery")
	ctx := context.Background()
	// Index: keyCards(publicKey)
	query := `select id, shopId from keyCards
	where cardPublicKey = $1 and unlinkedAt is null`
	err := r.connPool.QueryRow(ctx, query, op.im.PublicKey.Raw).Scan(&keyCardID, &shopID)
	if err == pgx.ErrNoRows {
		logS(op.sessionID, "relay.authenticateOp.idsQuery.noSuchKeyCard")
		op.err = notFoundError
		r.sendSessionOp(sessionState, op)
		return
	}
	check(err)
	logS(op.sessionID, "relay.authenticateOp.ids keyCardId=%d shopId=%d", keyCardID, shopID)

	// Ensure the device isn't already connected via another session.
	// If we find such another session, initiate a stop on it because it is probably
	// a dangling session that only the server side thinks is still alive.
	// Reject this authentication attempt from the second device, but with the stop
	// the client should be able to successfully retry shortly.
	var halt = false
	r.sessionIDsToSessionStates.All(func(otherSessionID sessionID, otherSessionState *SessionState) bool {
		if otherSessionState.keyCardID > 0 && keyCardID == otherSessionState.keyCardID {
			logS(op.sessionID, "relay.authenticateOp.alreadyConnected otherSessionId=%d", otherSessionID)
			stopOp := &StopOp{sessionID: otherSessionID}
			r.sendSessionOp(otherSessionState, stopOp)
			op.err = alreadyConnectedError
			r.sendSessionOp(sessionState, op)
			halt = true
			return true
		}
		return false
	})
	if halt {
		return
	}

	// generate challenge
	ch := make([]byte, 32)
	_, _ = crand.Read(ch)

	op.challenge = ch
	sessionState.authChallenge = ch
	sessionState.keyCardID = keyCardID
	r.sendSessionOp(sessionState, op)
	logS(op.sessionID, "relay.authenticateOp.finish elapsed=%d", took(authenticateOpStart))
}

func (op *ChallengeSolvedOp) process(r *Relay) {
	logS(op.sessionID, "relay.challengeSolvedOp.start")
	challengeSolvedOpStart := now()

	sessionState := r.sessionIDsToSessionStates.Get(op.sessionID)
	if sessionState == nil {
		logS(op.sessionID, "relay.challengeSolvedOp.drain")
		return
	} else if sessionState.keyCardID == 0 {
		logS(op.sessionID, "relay.challengeSolvedOp.invalidSessionState")
		op.err = &pb.Error{Code: pb.ErrorCodes_INVALID, Message: "authentication not started"}
		r.sendSessionOp(sessionState, op)
		return
	} else if !sessionState.shopID.Equal(zeroObjectIDArr) {
		logS(op.sessionID, "relay.challengeSolvedOp.alreadyAuthenticated")
		op.err = alreadyAuthenticatedError
		r.sendSessionOp(sessionState, op)
		return
	}

	var keyCardPublicKey []byte
	var shopDBID uint64
	logS(op.sessionID, "relay.challengeSolvedOp.query")
	ctx := context.Background()
	// Index: keyCards(publicKey)
	query := `select cardPublicKey, shopId from keyCards
	where id = $1 and unlinkedAt is null`
	err := r.connPool.QueryRow(ctx, query, sessionState.keyCardID).Scan(&keyCardPublicKey, &shopDBID)
	if err == pgx.ErrNoRows {
		logS(op.sessionID, "relay.challengeSolvedOp.query.noSuchKeyCard")
		op.err = notFoundError
		r.sendSessionOp(sessionState, op)
		return
	}
	check(err)
	logS(op.sessionID, "relay.challengeSolvedOp.ids keyCardId=%d shopId=%d", sessionState.keyCardID, shopDBID)

	err = verifyChallengeResponse(keyCardPublicKey, sessionState.authChallenge, op.im.Signature.Raw)
	if err != nil {
		logS(op.sessionID, "relay.challengeSolvedOp.verifyFailed err=%s", err)
		op.err = notFoundError
		r.sendSessionOp(sessionState, op)
		return
	}

	// Create or update the device DB record.
	var dbUnlinkedAt *time.Time
	var dbLastAckedSeq uint64
	var dbLastVersion int
	var isGuestKeyCard bool
	instant := now()
	sessionState.lastSeenAt = instant
	sessionState.lastSeenAtFlushed = instant

	// Index: keyCards(id)
	query = `select unlinkedAt, lastAckedSeq, lastVersion, isGuest from keyCards where id = $1`
	err = r.connPool.QueryRow(ctx, query, sessionState.keyCardID).Scan(&dbUnlinkedAt, &dbLastAckedSeq, &dbLastVersion, &isGuestKeyCard)
	if err != nil {
		panic(err)
	} else if dbUnlinkedAt != nil {
		logS(op.sessionID, "relay.challengeSolvedOp.unlinkedDevice")
		op.err = unlinkedKeyCardError
		r.sendSessionOp(sessionState, op)
		return
	}

	logS(op.sessionID, "relay.challengeSolvedOp.existingDevice")
	// update sessionState
	sessionState.keyCardOfAGuest = isGuestKeyCard
	query = `update keyCards set lastVersion = $1, lastSeenAt = $2 where id = $3`
	_, err = r.connPool.Exec(ctx, query, sessionState.version, sessionState.lastSeenAt, sessionState.keyCardID)
	check(err)

	binary.BigEndian.PutUint64(sessionState.shopID[:], shopDBID)
	sessionState.keyCardPublicKey = keyCardPublicKey

	// At this point we know authentication was successful and seqs validated, so indicate by removing authChallenge.
	sessionState.authChallenge = nil

	r.sendSessionOp(sessionState, op)
	logS(op.sessionID, "relay.challengeSolvedOp.finish elapsed=%d", took(challengeSolvedOpStart))
}

func (op *PatchSetWriteOp) process(r *Relay) {
	ctx := context.Background()
	sessionID := op.sessionID
	requestID := op.requestID.Raw
	sessionState := r.sessionIDsToSessionStates.Get(sessionID)
	if sessionState == nil {
		logSR("relay.patchSetWriteOp.drain", sessionID, requestID)
		return
	} else if sessionState.shopID.Equal(zeroObjectIDArr) {
		logSR("relay.patchSetWriteOp.notAuthenticated", sessionID, requestID)
		op.err = notAuthenticatedError
		r.sendSessionOp(sessionState, op)
		return
	}
	start := now()
	logSR("relay.patchSetWriteOp.process", sessionID, requestID)
	r.lastSeenAtTouch(sessionState)

	// check nonce reuse
	var writtenNonce *uint64
	var usedNonce = op.decoded.Header.KeyCardNonce
	const maxNonceQry = `select max(keycardNonce) from patchSets where createdByShopID = $1 and  createdByKeyCardId = $2`
	err := r.connPool.QueryRow(ctx, maxNonceQry, sessionState.shopID[:], sessionState.keyCardID).Scan(&writtenNonce)
	check(err)
	if writtenNonce != nil && *writtenNonce >= usedNonce {
		logSR("relay.patchSetWriteOp.nonceReuse keyCard=%d written=%d new=%d", sessionID, requestID, sessionState.keyCardID, *writtenNonce, usedNonce)
		op.err = &pb.Error{Code: pb.ErrorCodes_INVALID, Message: "event nonce re-use"}
		r.sendSessionOp(sessionState, op)
		return
	}

	// check signature
	if err := VerifyPatchSetSignature(op, sessionState.keyCardPublicKey); err != nil {
		logSR("relay.patchSetWriteOp.verifySignatureFailed err=%s", sessionID, requestID, err.Error())
		op.err = &pb.Error{Code: pb.ErrorCodes_INVALID, Message: "invalid signature"}
		r.sendSessionOp(sessionState, op)
		return
	}

	r.hydrateShops(NewSetInts(sessionState.shopID))

	// start patching shop state
	shopState := r.shopIDsToShopState.MustGet(sessionState.shopID)

	// clone shop state to avoid mutating the original
	// TODO: this is a hack/placeholder until we have copy-on-write functionality
	proposal := gclone.Clone(shopState.data)

	assert(r.validator != nil)
	patcher := patch.NewPatcher(r.validator, proposal)

	// we dont apply these to the shop state yet.
	// this happens in commitTx to be more orthogonal with other places the relay creates patch sets
	var relayPatches []patch.Patch
	for i, p := range op.decoded.Patches {
		// TODO: check who is allowed to write to which patch.path
		if sessionState.keyCardOfAGuest {
			if p.Path.Type != patch.ObjectTypeOrder {
				logSR("relay.patchSetWriteOp.guestKeycardWriteNotAllowed path=%+v", sessionID, requestID, p.Path)
				op.err = &pb.Error{Code: pb.ErrorCodes_NOT_FOUND, Message: "not allowed"}
				r.sendSessionOp(sessionState, op)
				return
			}
			// TODO: check if the order is new or theirs
		}

		// change proposedshop state
		if err := patcher.ApplyPatch(p); err != nil {
			logSR("relay.patchSetWriteOp.applyPatchFailed patch=%d err=%s errType=%T", sessionID, requestID, i, err.Error(), err)
			var notFoundError patch.ObjectNotFoundError
			var outOfStockError patch.OutOfStockError
			if errors.As(err, &notFoundError) {
				op.err = &pb.Error{Code: pb.ErrorCodes_NOT_FOUND, Message: notFoundError.Error()}
			} else if errors.As(err, &outOfStockError) {
				op.err = &pb.Error{Code: pb.ErrorCodes_OUT_OF_STOCK, Message: outOfStockError.Error()}
			} else {
				op.err = &pb.Error{Code: pb.ErrorCodes_INVALID, Message: "invalid patch"}
			}
			r.sendSessionOp(sessionState, op)
			return
		}

		// processing for side-effects
		// - variation removal needs to cancel orders with them
		// - commit starts the payment timer
		// - payment choice starts the watcher
		if isListingVariationRemoved(p) {
			patches := r.processRemoveVariation(sessionID, p)
			relayPatches = append(relayPatches, patches...)
		}
		if isOrderStateCommited(p) {
			err := r.processOrderItemsCommitment(sessionID, proposal, p)
			if err != nil {
				op.err = err
				r.sendSessionOp(sessionState, op)
				return
			}
		}
		if isOrderStatePaymentChoice(p) {
			patches, err := r.processOrderPaymentChoice(sessionID, proposal, p)
			if err != nil {
				op.err = err
				r.sendSessionOp(sessionState, op)
				return
			}
			relayPatches = append(relayPatches, patches...)
		}
	}

	// all patches applied successfully, update shop state
	shopState.data = proposal

	// update shop
	r.beginSyncTransaction()
	meta := newMetadata(sessionState.keyCardID, sessionState.shopID, uint16(sessionState.version))
	r.queuePatchSet(meta, op.decoded, op.headerData, op.proofs)

	if len(relayPatches) > 0 {
		r.createRelayPatchSet(sessionState.shopID, relayPatches...)
	}

	setCount := len(r.queuedPatchSetInserts)

	// compute resulting hash
	op.newShopHash, err = shopState.data.Hash()
	if err != nil {
		logSR("relay.patchSetWriteOp.hashFailed err=%s", sessionID, requestID, err.Error())
		op.err = &pb.Error{Code: pb.ErrorCodes_INVALID, Message: "unable to hash shop state"}
		r.sendSessionOp(sessionState, op)
		return
	}
	r.commitSyncTransaction()

	r.sendSessionOp(sessionState, op)
	logSR("relay.patchSetWriteOp.finish new_events=%d took=%d", sessionID, requestID, setCount, took(start))
}

// isListingVariationRemoved returns true if the patch is a variation removal (either option or variation)
func isListingVariationRemoved(p patch.Patch) bool {
	if !(p.Path.Type == patch.ObjectTypeListing &&
		len(p.Path.Fields) >= 1 &&
		p.Path.Fields[0] == "options") {
		return false
	}
	return p.Op == patch.RemoveOp
}

// if we remove a variation from an unpayed order, we need to cancel open orders for it to avoid edge cases
func (r *Relay) processRemoveVariation(sessionID sessionID, p patch.Patch) []patch.Patch {
	ctx := context.Background()
	sessionState := r.sessionIDsToSessionStates.Get(sessionID)
	listingID := *p.Path.ObjectID
	// this shop state is the prior state to the patch
	// we destil the needed change from the passed patch
	shop := r.shopIDsToShopState.MustGet(sessionState.shopID).data
	listing, has := shop.Listings.Get(listingID)
	assert(has)

	// collect all variation IDs from both removed options and removed removedVariations
	removedVariations := NewSetInts[string]()
	if len(p.Path.Fields) == 2 && p.Path.Fields[0] == "options" {
		optName := p.Path.Fields[1]
		opt, has := listing.Options[optName]
		assert(has)
		for varName, _ := range opt.Variations {
			removedVariations.Add(varName)
		}
	} else if len(p.Path.Fields) == 4 && p.Path.Fields[0] == "options" && p.Path.Fields[2] == "variations" {
		varName := p.Path.Fields[3]
		removedVariations.Add(varName)
	}

	start := now()
	logS(sessionID, "relay.removeVariation.process listing=%d variations=%v", uint64(listingID), removedVariations.Slice())

	otherOrderRows, err := r.connPool.Query(ctx, `select orderId from payments
	where shopId = $1
		and payedAt is null
		and itemsLockedAt >= now() - interval '1 day'`, sessionState.shopID[:])
	check(err)

	otherOrderIDs := NewMapInts[uint64, objects.Order]()
	for otherOrderRows.Next() {
		var otherOrderID SQLUint64Bytes
		check(otherOrderRows.Scan(&otherOrderID))
		otherOrder, has := shop.Orders.Get(otherOrderID.Uint64())
		assert(has)
		otherOrderIDs.Set(otherOrderID.Uint64(), otherOrder)
	}
	check(otherOrderRows.Err())
	otherOrderRows.Close()

	// see if any orders include this listing and variation
	matchingOrders := NewSetInts[uint64]()
	otherOrderIDs.All(func(orderID uint64, order objects.Order) bool {
		for _, item := range order.Items {
			if item.ListingID == listingID { // matched the listing that is being edited
			itemLoop:
				// go through all variations of the item
				for _, vid := range item.VariationIDs {
					if removedVariations.Has(vid) {
						matchingOrders.Add(orderID)
						// we can break here because we know there is only one item per variation
						break itemLoop
					}
				}
			}
		}
		return false
	})

	if matchingOrders.Size() == 0 {
		logS(sessionID, "relay.removeVariation.noMatchingOrders took=%d", took(start))
		return nil
	}

	// cancel open orders
	canceledAt := now()
	var orderIDslice = matchingOrders.Slice()
	// sadly go can't deal with []driver.Value directly
	var ordersAsBytes = make([][]byte, matchingOrders.Size())
	for i, oid := range orderIDslice {
		ordersAsBytes[i] = make([]byte, 8)
		binary.BigEndian.PutUint64(ordersAsBytes[i], oid)
	}
	const paymentsUpdateQry = `update payments set canceledAt=$3 where shopId=$1 and orderId=any($2)`
	_, err = r.connPool.Exec(ctx, paymentsUpdateQry, sessionState.shopID[:], ordersAsBytes, canceledAt)
	check(err)
	var patches []patch.Patch
	cborCanceledAt, err := cbor.Marshal(canceledAt)
	check(err)
	cborCanceledState, err := cbor.Marshal(objects.OrderStateCanceled)
	check(err)
	for _, orderID := range orderIDslice {
		patches = append(patches,
			patch.Patch{
				Path: patch.PatchPath{
					Type:     patch.ObjectTypeOrder,
					ObjectID: &orderID,
					Fields:   []string{"canceledAt"},
				},
				Op:    patch.ReplaceOp,
				Value: cborCanceledAt,
			},
			patch.Patch{
				Path: patch.PatchPath{
					Type:     patch.ObjectTypeOrder,
					ObjectID: &orderID,
					Fields:   []string{"state"},
				},
				Op:    patch.ReplaceOp,
				Value: cborCanceledState,
			},
		)
	}

	logS(sessionID, "relay.removeVariation.finish orders=%d took=%d", len(orderIDslice), took(start))
	return patches
}

func isOrderStateCommited(p patch.Patch) bool {
	if !(p.Path.Type == patch.ObjectTypeOrder &&
		len(p.Path.Fields) == 1 &&
		p.Path.Fields[0] == "state") {
		return false
	}
	if p.Op != patch.ReplaceOp {
		return false
	}
	if p.Value == nil {
		return false
	}
	var orderState objects.OrderState
	if err := cbor.Unmarshal(p.Value, &orderState); err != nil {
		return false
	}
	return orderState == objects.OrderStateCommitted
}

func (r *Relay) processOrderItemsCommitment(sessionID sessionID, shop *objects.Shop, p patch.Patch) *pb.Error {
	start := now()
	ctx := context.Background()
	sessionState := r.sessionIDsToSessionStates.MustGet(sessionID)

	orderID := *p.Path.ObjectID
	logS(sessionID, "relay.orderCommitItemsOp.process order=%d", orderID)

	// load related data
	// this shop state is the prior state to the patch
	// we destil the needed change from the passed patch
	order, has := shop.Orders.Get(orderID)
	assert(has)

	// get all other orders that haven't been paid yet
	// TODO: configure timeout
	var orderDBID ObjectIDArray
	binary.BigEndian.PutUint64(orderDBID[:], orderID)
	otherOrderRows, err := r.connPool.Query(ctx, `select orderId from payments
where shopId = $1
	  and orderId != $2
	  and payedAt is null
	  and itemsLockedAt >= now() - interval '1 day'`,
		sessionState.shopID[:],
		orderDBID[:],
	)
	check(err)
	var otherOrderIDBytes [][]byte
	// first we need to drain all the otherOrderRows
	for otherOrderRows.Next() {
		var otherOrderID SQLUint64Bytes
		err := otherOrderRows.Scan(&otherOrderID)
		check(err)
		otherOrderIDBytes = append(otherOrderIDBytes, otherOrderID.Data[:])
	}
	check(otherOrderRows.Err())
	otherOrderRows.Close()
	// now we can use the ordersByOrderID to reduce the orders
	// (this can load in data from psql and if we did it in the same loop would lead to conn busy errors)
	otherOrderIDs := NewMapInts[uint64, objects.Order]()
	for _, orderIDBytes := range otherOrderIDBytes {
		orderID := binary.BigEndian.Uint64(orderIDBytes)
		otherOrder, has := shop.Orders.Get(orderID)
		assert(has)
		otherOrderIDs.Set(orderID, otherOrder)
	}
	// for convenience, sum up all items in the other orders
	otherOrderItemQuantities := NewMapInts[combinedID, uint32]()
	otherOrderIDs.All(func(_ uint64, order objects.Order) bool {
		if order.CanceledAt != nil { // skip canceled orders
			return false
		}
		for _, item := range order.Items {
			combinedID := newCombinedID(item.ListingID, item.VariationIDs...)
			current := otherOrderItemQuantities.Get(combinedID)
			current += item.Quantity
			otherOrderItemQuantities.Set(combinedID, current)
		}
		return false
	})

	// iterate over this order
	var invalidErr *pb.Error
	for _, item := range order.Items {
		stockItems, has := shop.Inventory.Get(item.ListingID, item.VariationIDs)
		if !has {
			invalidErr = notEnoughStockError
			break
		}
		combinedID := newCombinedID(item.ListingID, item.VariationIDs...)
		usedInOtherOrders := otherOrderItemQuantities.Get(combinedID)
		if stockItems < 0 || uint32(stockItems)-usedInOtherOrders < item.Quantity {
			invalidErr = notEnoughStockError
			break
		}
	}
	if invalidErr != nil {
		return invalidErr
	}

	shopState := r.shopIDsToShopState.MustGet(sessionState.shopID)
	const insertPaymentQuery = `insert into payments (shopSeqNo, shopId, orderId, itemsLockedAt)
		VALUES ($1, $2, $3, now())`
	_, err = r.connPool.Exec(ctx, insertPaymentQuery,
		shopState.lastUsedSeq,
		sessionState.shopID[:],
		orderDBID[:],
	)
	check(err)

	logS(sessionID, "relay.orderCommitItemsOp.finish took=%d", took(start))
	return nil
}

// TODO: we might want to introduce another state..?
func isOrderStatePaymentChoice(p patch.Patch) bool {
	if !(p.Path.Type == patch.ObjectTypeOrder &&
		len(p.Path.Fields) == 1 &&
		p.Path.Fields[0] == "chosenCurrency") {
		return false
	}
	return p.Op == patch.ReplaceOp
}

var big100 = new(big.Int).SetInt64(100)

func (r *Relay) processOrderPaymentChoice(sessionID sessionID, shop *objects.Shop, p patch.Patch) ([]patch.Patch, *pb.Error) {
	ctx := context.Background()
	sessionState := r.sessionIDsToSessionStates.Get(sessionID)
	shopID := sessionState.shopID

	start := now()
	orderID := *p.Path.ObjectID

	logS(sessionID, "relay.orderPaymentChoiceOp.process order=%x", orderID)

	// load related data
	order, has := shop.Orders.Get(orderID)
	assert(has)

	shippingAddr := order.ShippingAddress
	if shippingAddr == nil {
		shippingAddr = order.InvoiceAddress
	}

	if shippingAddr == nil {
		return nil, &pb.Error{Code: pb.ErrorCodes_INVALID, Message: "no shipping address"}
	}

	// check if shipping regions are set
	if len(shop.Manifest.ShippingRegions) == 0 {
		return nil, &pb.Error{Code: pb.ErrorCodes_INVALID, Message: "no shipping regions"}
	}

	region, err := ScoreRegions(shop.Manifest.ShippingRegions, shippingAddr)
	if err != nil {
		logS(sessionID, "relay.orderPaymentChoiceOp.scoreRegions regions=%d err=%s", len(shop.Manifest.ShippingRegions), err)
		return nil, &pb.Error{Code: pb.ErrorCodes_INVALID, Message: "unable to determin shipping region"}
	}
	shippingRegion := shop.Manifest.ShippingRegions[region]

	// determain total price and create snapshot of items
	var (
		bigSubtotal = new(big.Int)
		orderHash   [32]byte
		done        = make(chan struct{})
	)

	snapshotter, savedItems, err := newListingSnapshotter(r.metric, shopID)
	if err != nil {
		logS(sessionID, "relay.orderPaymentChoiceOp.ipfsClientFailed error=%s", err)
		return nil, &pb.Error{Code: pb.ErrorCodes_INVALID, Message: "internal ipfs error"}
	}

	// iterate over this order
	for _, ordered := range order.Items {
		listing, has := shop.Listings.Get(ordered.ListingID)
		if !has {
			return nil, notFoundError
		}

		cid := newCombinedID(ordered.ListingID, ordered.VariationIDs...)
		snapshotter.save(cid, &listing)

		// total += quantity * price
		bigQuant := big.NewInt(int64(ordered.Quantity))

		bigPrice := new(big.Int)
		bigPrice.Set(&listing.Price)

		chosenVars := cid.Variations()
		found := 0
		for _, chosen := range chosenVars {
			// TODO: faster lookup of variations
			for _, availableOption := range listing.Options {
				for varName, variation := range availableOption.Variations {
					if varName == chosen {
						if variation.PriceModifier.ModificationAbsolute != nil {
							found++
							bigPriceDiff := new(big.Int)
							bigPriceDiff.Set(&variation.PriceModifier.ModificationAbsolute.Amount)

							if variation.PriceModifier.ModificationAbsolute.Plus {
								bigPrice.Add(bigPrice, bigPriceDiff)
							} else {
								bigPrice.Sub(bigPrice, bigPriceDiff)
							}
						}
					}
				}
			}
		}
		if len(chosenVars) != found {
			return nil, &pb.Error{Code: pb.ErrorCodes_OUT_OF_STOCK, Message: "variation no longer available"}
		}

		logS(sessionID, "relay.orderPaymentChoiceOp.subTotal current=%s | quant=%s price=%s", bigSubtotal, bigQuant, bigPrice)
		bigQuant.Mul(bigQuant, bigPrice)

		bigSubtotal.Add(bigSubtotal, bigQuant)
		logS(sessionID, "relay.orderPaymentChoiceOp.subTotal new=%s = oldSubTotal + quant_times_price(%s)", bigSubtotal, bigQuant)
	}
	// worker to consume snapshot jobs
	var items []savedItem
	go func() {
		for it := range savedItems {
			items = append(items, it)
		}

		// previously used to get the orderHash

		close(done)
	}()
	err = snapshotter.Wait() // also closes saveItems channel
	if err != nil {
		logS(sessionID, "relay.orderPaymentChoiceOp.itemSnapshots err=%s", err)
		return nil, &pb.Error{Code: pb.ErrorCodes_INVALID, Message: "failed to snapshot items"}
	}
	<-done // wait for consumer to create orderHash

	// add taxes and shipping
	bigTotal := new(big.Int).Set(bigSubtotal)
	diff := new(big.Int)
	logS(sessionID, "relay.orderPaymentChoiceOp.total beforeModifiers=%s", bigTotal)
	for _, mod := range shippingRegion.PriceModifiers {
		if mod.ModificationPrecents != nil {
			perc := mod.ModificationPrecents
			diff.Set(perc)
			bigTotal.Mul(bigTotal, diff)
			bigTotal.Div(bigTotal, big100)
		} else if mod.ModificationAbsolute != nil {
			abs := mod.ModificationAbsolute
			diff.Set(&abs.Amount)
			if abs.Plus {
				bigTotal.Add(bigTotal, diff)
			} else {
				bigTotal.Sub(bigTotal, diff)
			}
		} else {
			logS(sessionID, "relay.orderPaymentChoiceOp.unknownPriceModifier mod=%v", mod)
			panic("unknown price modifier")
		}
	}

	logS(sessionID, "relay.orderPaymentChoiceOp.total after=%s", bigTotal)

	if n := len(bigTotal.Bytes()); n > 32 {
		logS(sessionID, "relay.orderPaymentChoiceOp.totalTooBig got=%d", n)
		return nil, &pb.Error{Code: pb.ErrorCodes_INVALID, Message: "payment amount exceeded uint256"}
	}

	// create payment address for order content
	var chosenCurrency = order.ChosenCurrency
	assert(chosenCurrency != nil)
	if !chosenCurrency.Equal(shop.Manifest.PricingCurrency) {
		// convert base to chosen currency
		bigTotal, err = r.prices.Convert(shop.Manifest.PricingCurrency, *chosenCurrency, bigTotal)
		if err != nil {
			logS(sessionID, "relay.orderPaymentChoiceOp.priceConversion err=%s", err)
			return nil, &pb.Error{Code: pb.ErrorCodes_INVALID, Message: "failed to establish conversion price"}
		}
	}

	// fallback for paymentAddr
	ownerAddr, err := r.ethereum.GetOwnerOfShop(&shop.Manifest.ShopID)
	if err != nil {
		logS(sessionID, "relay.orderPaymentChoiceOp.shopOwnerFailed err=%s", err)
		return nil, &pb.Error{Code: pb.ErrorCodes_INVALID, Message: "failed to get shop owner"}
	}

	// ttl
	blockNo, err := r.ethereum.GetCurrentBlockNumber(chosenCurrency.ChainID)
	if err != nil {
		logS(sessionID, "relay.orderPaymentChoiceOp.blockNumberFailed err=%s", err)
		return nil, &pb.Error{Code: pb.ErrorCodes_INVALID, Message: "failed to get current block number"}
	}
	bigBlockNo := new(big.Int).SetInt64(int64(blockNo))

	block, err := r.ethereum.GetBlockByNumber(chosenCurrency.ChainID, bigBlockNo)
	if err != nil {
		logS(sessionID, "relay.orderPaymentChoiceOp.blockByNumberFailed block=%d err=%s", blockNo, err)
		return nil, &pb.Error{Code: pb.ErrorCodes_INVALID, Message: "failed to get block by number"}
	}

	// construct payment request for ID and pay-by-address
	var pr = contractsabi.PaymentRequest{}
	pr.ChainId = new(big.Int).SetUint64(chosenCurrency.ChainID)
	pr.Ttl = new(big.Int).SetUint64(block.Time() + DefaultPaymentTTL)
	pr.Order = orderHash
	commonChosenCurrency := common.Address(chosenCurrency.Address)
	pr.Currency = commonChosenCurrency
	pr.Amount = bigTotal
	pr.PayeeAddress = common.Address(ownerAddr)
	pr.IsPaymentEndpoint = false
	pr.ShopId = &shop.Manifest.ShopID
	// TODO: calculate signature
	pr.ShopSignature = bytes.Repeat([]byte{0}, 64)

	paymentID, paymentAddr, err := r.ethereum.GetPaymentIDAndAddress(chosenCurrency.ChainID, &pr, ownerAddr)
	if err != nil {
		logS(sessionID, "relay.orderPaymentChoiceOp.paymentIDandAddrFailed order=%x err=%s", orderID, err)
		return nil, &pb.Error{Code: pb.ErrorCodes_INVALID, Message: "failed to get paymentID"}
	}

	logS(sessionID, "relay.orderPaymentChoiceOp.paymentRequest id=%x addr=%x total=%s currentBlock=%d order_hash=%x", paymentID, paymentAddr, bigTotal.String(), blockNo, orderHash)

	// mark order as finalized by creating the event and updating payments table
	var fin objects.PaymentDetails
	copy(fin.PaymentID[:], paymentID)
	fin.TTL = pr.Ttl.Uint64()

	fin.ListingHashes = make([][]byte, len(items))
	for i, it := range items {
		fin.ListingHashes[i] = it.cborHash[:]
	}

	fin.Total = objects.Uint256(*bigTotal)
	copy(fin.ShopSignature[:], pr.ShopSignature)

	finBytes, err := cbor.Marshal(fin)
	check(err)

	// TODO: once
	unpaidBytes, err := cbor.Marshal(objects.OrderStateUnpaid)
	check(err)

	patches := []patch.Patch{
		{
			Path: patch.PatchPath{
				Type:     patch.ObjectTypeOrder,
				ObjectID: &orderID,
				Fields:   []string{"paymentDetails"},
			},
			Op:    patch.AddOp,
			Value: finBytes,
		},
		{
			Path: patch.PatchPath{
				Type:     patch.ObjectTypeOrder,
				ObjectID: &orderID,
				Fields:   []string{"state"},
			},
			Op:    patch.ReplaceOp,
			Value: unpaidBytes,
		},
	}

	var w PaymentWaiter
	w.shopID = shopID
	var dbOrderID ObjectIDArray
	binary.BigEndian.PutUint64(dbOrderID[:], orderID)
	w.orderID = dbOrderID
	w.paymentChosenAt = now()
	w.purchaseAddr = paymentAddr
	w.chainID = chosenCurrency.ChainID
	w.lastBlockNo.SetInt64(int64(blockNo))
	w.coinsTotal.Set(bigTotal)
	w.paymentID = paymentID

	var chosenIsErc20 = ZeroAddress.Cmp(commonChosenCurrency) != 0
	if chosenIsErc20 {
		w.erc20TokenAddr = &commonChosenCurrency
	}

	const insertPaymentWaiterQuery = `update payments set

paymentChosenAt = $3,
purchaseAddr = $4,
lastBlockNo = $5,
coinsTotal = $6,
erc20TokenAddr = $7,
paymentID = $8,
chainId = $9
WHERE shopId = $1
AND orderId = $2`

	_, err = r.connPool.Exec(ctx, insertPaymentWaiterQuery,
		// where
		w.shopID[:],
		w.orderID[:],
		// set
		w.paymentChosenAt,
		w.purchaseAddr.Bytes(),
		w.lastBlockNo,
		w.coinsTotal,
		w.erc20TokenAddr,
		w.paymentID,
		w.chainID)
	check(err)

	logS(sessionID, "relay.orderPaymentChoiceOp.finish took=%d", took(start))
	return patches, nil
}

var publicDefaultFilters = []*pb.SubscriptionRequest_Filter{
	{ObjectType: pb.ObjectType_OBJECT_TYPE_MANIFEST},
	{ObjectType: pb.ObjectType_OBJECT_TYPE_ACCOUNT},
	{ObjectType: pb.ObjectType_OBJECT_TYPE_TAG},
	{ObjectType: pb.ObjectType_OBJECT_TYPE_LISTING},
}

func (op *SubscriptionRequestOp) process(r *Relay) {
	start := now()
	ctx := context.Background()
	sessionID := op.sessionID
	requestID := op.requestID.Raw
	session := r.sessionIDsToSessionStates.Get(sessionID)
	if session == nil {
		logSR("relay.subscriptionRequestOp.drain", sessionID, requestID)
		return
	}

	var (
		verifyOrderIDs [][]byte

		startSeqNo   = op.im.StartShopSeqNo
		subscription SubscriptionState

		shopDBID    uint64
		shopTokenID = new(big.Int).SetBytes(op.im.ShopId.Raw)
	)

	err := r.connPool.QueryRow(ctx, `select id from shops where tokenId = $1`, shopTokenID.String()).Scan(&shopDBID)
	if err != nil {
		if err == pgx.ErrNoRows {
			op.err = notFoundError
			r.sendSessionOp(session, op)
			return
		}
		check(err)
	}
	binary.BigEndian.PutUint64(subscription.shopID[:], shopDBID)
	logSR("relay.subscriptionRequestOp.process shopDBID=%d", sessionID, requestID, shopDBID)
	r.lastSeenAtTouch(session)

	subscription.lastStatusedSeq = startSeqNo
	subscription.lastBufferedSeq = startSeqNo
	subscription.lastPushedSeq = startSeqNo
	subscription.lastAckedSeq = startSeqNo
	subscription.lastAckedSeqFlushed = startSeqNo

	subscription.initialStatus = false
	subscription.nextPushIndex = 0

	// enforce public default filters for guest users
	if len(op.im.Filters) == 0 && session.keyCardOfAGuest {
		if session.shopID.Equal(zeroObjectIDArr) { // not enrolled with a keycard
			op.im.Filters = publicDefaultFilters
		} else {
			op.im.Filters = append(publicDefaultFilters,
				&pb.SubscriptionRequest_Filter{
					ObjectType: pb.ObjectType_OBJECT_TYPE_ORDER},
			)
		}
	}

	// Build WHERE fragment used for pushing events
	var wheres []string
	for _, filter := range op.im.Filters {
		// Ensure that non-authenticated sessions can only access public content
		if !subscription.shopID.Equal(session.shopID) &&
			(filter.ObjectType == pb.ObjectType_OBJECT_TYPE_INVENTORY ||
				filter.ObjectType == pb.ObjectType_OBJECT_TYPE_ORDER) {
			logSR("relay.subscriptionRequestOp.notAllowed why=\"other shop\" filter=%s",
				sessionID, requestID, filter.ObjectType.String())
			op.err = &pb.Error{Code: pb.ErrorCodes_INVALID, Message: "not allowed"}
			r.sendSessionOp(session, op)
			return
		}

		// Restrict guest access to their own orders
		if session.keyCardOfAGuest {
			switch filter.ObjectType {
			case pb.ObjectType_OBJECT_TYPE_ORDER:
				// Collect order IDs for verification
				if id := filter.GetObjectId(); id != nil {
					verifyOrderIDs = append(verifyOrderIDs, id.Raw)
				}
			case pb.ObjectType_OBJECT_TYPE_INVENTORY:
				logSR("relay.subscriptionRequestOp.notAllowed filter=%s",
					sessionID, requestID, filter.ObjectType.String())
				op.err = &pb.Error{Code: pb.ErrorCodes_INVALID, Message: "not allowed"}
				r.sendSessionOp(session, op)
				return
			}
		}

		// Construct WHERE clause based on object type
		var where string
		switch filter.ObjectType {
		case pb.ObjectType_OBJECT_TYPE_MANIFEST:
			where = ` (p.objectType='manifest')`
		case pb.ObjectType_OBJECT_TYPE_ACCOUNT:
			where = ` (p.objectType='account')`
		case pb.ObjectType_OBJECT_TYPE_INVENTORY:
			where = ` (p.objectType='inventory')`
		case pb.ObjectType_OBJECT_TYPE_LISTING:
			where = ` (p.objectType='listing')`
		case pb.ObjectType_OBJECT_TYPE_TAG:
			where = ` (p.objectType='tag')`
		case pb.ObjectType_OBJECT_TYPE_ORDER:
			where = ` (p.objectType='order')`
			// Add additional constraint for guest users
			if session.keyCardOfAGuest {
				// we need to include all orders created by the guest
				// this includes updates to orders created by the relay or clerks
				where = fmt.Sprintf(`(%s AND (ps.createdByKeyCardId=%d OR (
p.objectId in (select distinct patch2.objectId 
	from patchSets pset2
	join patches patch2 on patch2.patchSetServerSeq = pset2.serverSeq
	where patch2.objectType='order' and pset2.createdByKeyCardID=%d)
	)
)
)`, where, session.keyCardID, session.keyCardID)
			}
		}

		// Add object ID constraint if provided
		if id := filter.ObjectId; id != nil {
			where = "(" + where + fmt.Sprintf(" AND p.objectId = '\\x%x')", id.Raw)
		}
		wheres = append(wheres, where)
	}

	if len(wheres) == 0 {
		if session.keyCardOfAGuest {
			logSR("relay.subscriptionRequestOp.noFilters", sessionID, requestID)
			op.err = &pb.Error{Code: pb.ErrorCodes_INVALID, Message: "no filters"}
			r.sendSessionOp(session, op)
			return
		}
		subscription.whereFragment = "True"
	} else {
		subscription.whereFragment = strings.Join(wheres, " OR ")
	}

	logSR("relay.subscriptionRequestOp.whereFragment whereFragment=%s guest=%t", sessionID, requestID, subscription.whereFragment, session.keyCardOfAGuest)

	if n := len(verifyOrderIDs); n > 0 {
		// check that all orders belong to the same person
		var count int
		const checkQry = `select count(*) from patchSets
where objectType="order"
and createdByShopId = $1
and createdByKeyCardId = $2
and objectId = any($3)`
		err = r.connPool.QueryRow(ctx, checkQry, session.shopID, session.keyCardID, verifyOrderIDs).Scan(&count)
		check(err)
		if count != n {
			logSR("relay.subscriptionRequestOp.notAuthenticated", sessionID, requestID)
			op.err = notAuthenticatedError
			r.sendSessionOp(session, op)
			return
		}
	}

	// Establish shop seq.
	r.hydrateShops(NewSetInts(subscription.shopID))
	shopState := r.shopIDsToShopState.MustGet(subscription.shopID)

	// Verify we have valid seq cursor relationships. We will check this whenever we move a cursor.
	err = r.checkCursors(op.sessionID, shopState, &subscription)
	logS(op.sessionID, "relay.subscriptionRequestOp.checkCursors lastWrittenSeq=%d lastUsedSeq=%d lastStatusedSeq=%d lastBufferedSeq=%d lastPushedSeq=%d lastAckedSeq=%d error=%t",
		shopState.lastWrittenSeq, shopState.lastUsedSeq, subscription.lastStatusedSeq, subscription.lastBufferedSeq, subscription.lastPushedSeq, subscription.lastAckedSeq, err != nil)
	if err != nil {
		logS(op.sessionID, "relay.subscriptionRequestOp.brokenCursor err=%s", err.Error())
		op.err = notFoundError
		r.sendSessionOp(session, op)
		return
	}

	// catalog subscriptionID and save it
	op.subscriptionID = uint16(len(session.subscriptions) + 1)
	session.subscriptions[op.subscriptionID] = &subscription

	r.sendSessionOp(session, op)
	logS(op.sessionID, "relay.subscriptionRequestOp.finish took=%d", took(start))
}

func (op *SubscriptionPushOp) process(r *Relay) {
	sessionState := r.sessionIDsToSessionStates.Get(op.sessionID)
	if sessionState == nil {
		logS(op.sessionID, "relay.subscriptionPushOp.drain")
		return
	}
	r.lastSeenAtTouch(sessionState)
	for _, state := range op.pushStates {
		state.acked = true
	}
}

func (op *SubscriptionCancelOp) process(r *Relay) {
	start := now()
	ctx := context.Background()
	_ = ctx
	sessionID := op.sessionID
	requestID := op.requestID.Raw
	session := r.sessionIDsToSessionStates.Get(sessionID)
	if session == nil {
		logSR("relay.subscriptionCancelOp.drain", sessionID, requestID)
		return
	}
	logSR("relay.subscriptionCancelOp.process", sessionID, requestID)
	r.lastSeenAtTouch(session)

	// check if the subscription id exists
	subID := binary.BigEndian.Uint16(op.im.SubscriptionId)
	_, has := session.subscriptions[subID]
	if !has {
		op.err = notFoundError
		r.sendSessionOp(session, op)
		return
	}

	delete(session.subscriptions, subID)

	r.sendSessionOp(session, op)
	logS(op.sessionID, "relay.subscriptionCancelOp.finish took=%d", took(start))
}

func (op *GetBlobUploadURLOp) process(r *Relay) {
	sessionID := op.sessionID
	requestID := op.requestID.Raw
	sessionState := r.sessionIDsToSessionStates.Get(sessionID)
	if sessionState == nil {
		logS(sessionID, "relay.getBlobUploadURLOp.drain")
		return
	} else if sessionState.shopID.Equal(zeroObjectIDArr) {
		logSR("relay.getBlobUploadURLOp.notAuthenticated", sessionID, requestID)
		op.err = notAuthenticatedError
		r.sendSessionOp(sessionState, op)
		return
	}
	logSR("relay.getBlobUploadURLOp.process", sessionID, requestID)
	start := r.lastSeenAtTouch(sessionState)

	r.blobUploadTokensMu.Lock()
	i := 10
	var token string
	var buf [32]byte
	for {
		_, _ = crand.Read(buf[:])
		token = base64.URLEncoding.EncodeToString(buf[:])
		if _, has := r.blobUploadTokens[token]; !has {
			r.blobUploadTokens[token] = struct{}{}
			break
		}
		i--
		assertWithMessage(i > 0, "too many tokens?")
	}
	r.blobUploadTokensMu.Unlock()

	uploadURL := *r.baseURL
	uploadURL.Path = fmt.Sprintf("/v%d/upload_blob", currentRelayVersion)
	uploadURL.RawQuery = "token=" + token
	op.uploadURL = &uploadURL

	r.sendSessionOp(sessionState, op)
	logSR("relay.getBlobUploadURLOp.finish token=%s took=%d", sessionID, requestID, token, took(start))
}

// Internal ops

func (op *KeyCardEnrolledInternalOp) process(r *Relay) {
	log("relay.keyCardEnrolledOp.start shopNFT=%s", op.shopNFT.String())
	start := now()

	r.beginSyncTransaction()

	dbCtx := context.Background()

	shopID, shopDBID, isNewShop := r.getOrCreateInternalShopID(op.shopNFT)
	r.hydrateShops(NewSetInts(shopID))

	var patches []patch.Patch
	if isNewShop {
		manifest := objects.Manifest{
			ShopID:             op.shopNFT,
			Payees:             make(objects.Payees),
			AcceptedCurrencies: make(objects.ChainAddresses),
			PricingCurrency: objects.ChainAddress{
				ChainID: r.ethereum.registryChainID,
			},
		}
		manifestBytes, err := cbor.Marshal(manifest)
		check(err)
		// emit a manifest patch
		patches = append(patches, patch.Patch{
			Op: patch.ReplaceOp,
			Path: patch.PatchPath{
				Type: patch.ObjectTypeManifest,
			},
			Value: manifestBytes,
		})
	}

	const insertKeyCard = `insert into keyCards (shopId, cardPublicKey, userWalletAddr, isGuest, lastVersion,  lastAckedSeq, linkedAt, lastSeenAt)
		VALUES ($1, $2, $3, $4, 0, 0, now(), now() )`
	_, err := r.syncTx.Exec(dbCtx, insertKeyCard, shopDBID, op.keyCardPublicKey[:], op.userWallet.Address[:], op.keyCardIsGuest)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			// fmt.Fprintf(os.Stderr, "relay.keyCardEnrolledOp.debug pgErr.Code=%s pgErr.ConstraintName=%s\n", pgErr.Code, pgErr.ConstraintName)
			if pgErr.Code == pgerrcode.UniqueViolation && pgErr.ConstraintName == "keycardsonpublickey" {
				op.done <- errors.New("keycard already enrolled")
				r.rollbackSyncTransaction()
				return
			}
		}
		check(err)
	}
	var value interface{}
	var fields []string
	_, has := r.shopIDsToShopState.MustGet(shopID).data.Accounts.Get(op.userWallet.Address[:])
	if has {
		value = op.keyCardPublicKey
		fields = []string{"keycards", "-"}
	} else {
		value = objects.Account{
			Guest: op.keyCardIsGuest,
			KeyCards: []objects.PublicKey{
				op.keyCardPublicKey,
			},
		}
	}
	valueBytes, err := cbor.Marshal(value)
	check(err)

	patches = append(patches, patch.Patch{
		Op: patch.AddOp,
		Path: patch.PatchPath{
			Type:        patch.ObjectTypeAccount,
			AccountAddr: &op.userWallet,
			Fields:      fields,
		},
		Value: valueBytes,
	})
	r.createRelayPatchSet(shopID, patches...)

	r.commitSyncTransaction()
	close(op.done)
	log("relay.KeyCardEnrolledOp.finish shopId=%d took=%d", shopDBID, took(start))
}

func (op *OnchainActionInternalOp) process(r *Relay) {
	assert(!op.shopID.Equal(zeroObjectIDArr))
	assert(op.user.Cmp(ZeroAddress) != 0)
	log("db.onchainActionInternalOp.start shopID=%x user=%s", op.shopID, op.user)
	start := now()

	// TODO: we are not including the on-chain transactoin hash here yet

	var user objects.EthereumAddress
	copy(user.Address[:], op.user.Bytes())
	var action patch.OpString
	var value []byte
	if op.add {
		action = patch.AddOp

		account := objects.Account{
			Guest:    false,
			KeyCards: nil,
		}
		var err error
		value, err = cbor.Marshal(account)
		check(err)
	} else {
		action = patch.RemoveOp
	}

	userPatch := patch.Patch{
		Op: action,
		Path: patch.PatchPath{
			Type:        patch.ObjectTypeAccount,
			AccountAddr: &user,
		},
		Value: value,
	}

	r.beginSyncTransaction()
	r.hydrateShops(NewSetInts(op.shopID))
	r.createRelayPatchSet(op.shopID, userPatch)
	r.commitSyncTransaction()

	log("db.onchainActionInternalOp.finish took=%d", took(start))
}

func (op *PaymentFoundInternalOp) process(r *Relay) {
	shopID := op.shopID
	assert(!shopID.Equal(zeroObjectIDArr))
	ordeDBID := op.orderID
	assert(!ordeDBID.Equal(zeroObjectIDArr))

	log("db.paymentFoundInternalOp.start shopID=%x orderID=%x", shopID, ordeDBID)
	start := now()

	paid := &objects.OrderPaid{
		BlockHash: objects.Hash(op.blockHash),
	}
	var txHash, blockHash *[]byte // for sql
	bh := op.blockHash.Bytes()
	blockHash = &bh
	if t := op.txHash; t != nil { // we only get the tx hash for non-internal tx's
		txHashBytes := t.Bytes()
		txHash = &txHashBytes
		paid.TxHash = &objects.Hash{}
		copy(paid.TxHash[:], txHashBytes)
	}

	const markOrderAsPayedQuery = `UPDATE payments SET
payedAt = NOW(),
payedTx = $1,
payedBlock = $2
WHERE shopID = $3 and orderId = $4;`
	commandTag, err := r.connPool.Exec(context.Background(), markOrderAsPayedQuery, txHash, blockHash, op.shopID[:], op.orderID[:])
	check(err)
	// check that the command tag is 1 row affected
	if commandTag.RowsAffected() != 1 {
		log("db.paymentFoundInternalOp.error commandTag=%d", commandTag.RowsAffected())
		close(op.done)
		return
	}

	r.beginSyncTransaction()
	r.hydrateShops(NewSetInts(shopID))

	shopState := r.shopIDsToShopState.MustGet(shopID).data

	order, has := shopState.Orders.Get(ordeDBID.Uint64())
	assertWithMessage(has, fmt.Sprintf("order not found for orderId=%x", ordeDBID))

	var inventoryPatches []patch.Patch
	// emit inventory decrement patches for each item
	for _, item := range order.Items {
		// Create a patch to decrement inventory for each item
		listingID := item.ListingID

		// Prepare the patch path with variations in the fields
		patchPath := patch.PatchPath{
			Type:     patch.ObjectTypeInventory,
			ObjectID: &listingID,
			Fields:   item.VariationIDs,
		}

		// Create the decrement patch
		inventoryPatches = append(inventoryPatches, patch.Patch{
			Path:  patchPath,
			Op:    patch.DecrementOp,
			Value: []byte{byte(item.Quantity)}, // Decrement by the item quantity
		})
	}

	orderID := objects.ObjectId(ordeDBID.Uint64())

	paidBytes, err := cbor.Marshal(paid)
	check(err)

	// TODO: only once
	orderStateBytes, err := cbor.Marshal(objects.OrderStatePaid)
	check(err)

	inventoryPatches = append(inventoryPatches,
		patch.Patch{
			Op: patch.AddOp,
			Path: patch.PatchPath{
				Type:     patch.ObjectTypeOrder,
				ObjectID: &orderID,
				Fields:   []string{"txDetails"},
			},
			Value: paidBytes,
		},
		patch.Patch{
			Op: patch.ReplaceOp,
			Path: patch.PatchPath{
				Type:     patch.ObjectTypeOrder,
				ObjectID: &orderID,
				Fields:   []string{"state"},
			},
			Value: orderStateBytes,
		})

	r.createRelayPatchSet(shopID, inventoryPatches...)

	r.commitSyncTransaction()
	log("db.paymentFoundInternalOp.finish orderID=%x took=%d", ordeDBID, took(start))
	close(op.done)
}

func (op *EventLoopPingInternalOp) process(_ *Relay) {
	close(op.done)
}
