// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v4"
	contractsabi "github.com/masslbs/relay/internal/contractabis"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
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
	requestID *RequestId
	im        *AuthenticateRequest
	err       *Error
	challenge []byte
}

// ChallengeSolvedOp finishes authentication of a session
type ChallengeSolvedOp struct {
	sessionID sessionID
	requestID *RequestId
	im        *ChallengeSolvedRequest
	err       *Error
}

// SyncStatusOp sends a SyncStatusRequest to the client
type SyncStatusOp struct {
	sessionID      sessionID
	subscriptionID uint16
	unpushedEvents uint64
}

// EventWriteOp processes a write of an event to the database
type EventWriteOp struct {
	sessionID      sessionID
	requestID      *RequestId
	im             *EventWriteRequest
	decodedShopEvt *ShopEvent
	newShopHash    []byte
	err            *Error
}

// SubscriptionRequestOp represents an operation to request a subscription.
// It contains the session ID, request ID, subscription request details,
// the ID of the subscription to be created, and an error if any.
type SubscriptionRequestOp struct {
	sessionID      sessionID
	requestID      *RequestId
	im             *SubscriptionRequest
	subscriptionID uint16
	err            *Error
}

// SubscriptionCancelOp represents an operation to cancel a subscription.
// It contains the session ID, request ID, and the subscription cancel request details.
type SubscriptionCancelOp struct {
	sessionID sessionID
	requestID *RequestId
	im        *SubscriptionCancelRequest
	err       *Error
}

// SubscriptionPushOp represents an operation to push events to the client.
// It contains the session ID, subscription ID, and the list of event states to push.
type SubscriptionPushOp struct {
	sessionID      sessionID
	subscriptionID uint16
	eventStates    []*EventState
}

// GetBlobUploadURLOp processes a GetBlobUploadURLRequest from the client.
type GetBlobUploadURLOp struct {
	sessionID sessionID
	requestID *RequestId
	im        *GetBlobUploadURLRequest
	uploadURL *url.URL
	err       *Error
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
	keyCardPublicKey []byte
	userWallet       common.Address
	done             chan struct{}
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
	txHash    *Hash
	blockHash *Hash

	done chan struct{}
}

type requestMessage interface {
	validate(uint) *Error
}

func (e *Envelope) isRequest() (requestMessage, bool) {
	switch tv := e.Message.(type) {

	case *Envelope_Response:
		return nil, false

	case *Envelope_SubscriptionRequest:
		return tv.SubscriptionRequest, true
	case *Envelope_SubscriptionCancelRequest:
		return tv.SubscriptionCancelRequest, true

	case *Envelope_EventWriteRequest:
		return tv.EventWriteRequest, true

	case *Envelope_AuthRequest:
		return tv.AuthRequest, true
	case *Envelope_ChallengeSolutionRequest:
		return tv.ChallengeSolutionRequest, true
	case *Envelope_GetBlobUploadUrlRequest:
		return tv.GetBlobUploadUrlRequest, true

	default:
		panic(fmt.Sprintf("Envelope.isRequest: unhandeled type: %T", tv))
	}
}

// App/Client Sessions
type responseHandler func(*Session, *RequestId, *Envelope_GenericResponse)

func (op *StopOp) handle(sess *Session) {
	logS(sess.id, "session.stopOp")
	sess.stopping = true
}

func handlePingResponse(sess *Session, _ *RequestId, resp *Envelope_GenericResponse) {
	assertNilError(resp.GetError())
	op := &HeartbeatOp{
		sessionID: sess.id,
	}
	sess.sendDatabaseOp(op)
}

func (im *AuthenticateRequest) validate(version uint) *Error {
	if version < 3 {
		return minimumVersionError
	}
	return im.PublicKey.validate()
}

func (im *AuthenticateRequest) handle(sess *Session, reqID *RequestId) {
	op := &AuthenticateOp{
		requestID: reqID,
		sessionID: sess.id,
		im:        im,
	}
	sess.sendDatabaseOp(op)
}

func (op *AuthenticateOp) handle(sess *Session) {
	resp := newGenericResponse(op.err)
	if op.err == nil {
		resp.Response = &Envelope_GenericResponse_Payload{op.challenge}
	}
	sess.writeResponse(op.requestID, resp)
}

func (im *ChallengeSolvedRequest) validate(version uint) *Error {
	if version < 3 {
		return minimumVersionError
	}
	return im.Signature.validate()
}

func (im *ChallengeSolvedRequest) handle(sess *Session, reqID *RequestId) {
	op := &ChallengeSolvedOp{
		sessionID: sess.id,
		requestID: reqID,
		im:        im,
	}
	sess.sendDatabaseOp(op)
}

func (op *ChallengeSolvedOp) handle(sess *Session) {
	resp := newGenericResponse(op.err)
	sess.writeResponse(op.requestID, resp)
}

func (op *SyncStatusOp) handle(sess *Session) {
	reqID := sess.nextRequestID()
	msg := &Envelope_SyncStatusRequest{
		&SyncStatusRequest{
			UnpushedEvents: op.unpushedEvents,
		},
	}
	sess.writeRequest(reqID, msg)
}

func handleSyncStatusResponse(sess *Session, _ *RequestId, resp *Envelope_GenericResponse) {
	assertNilError(resp.GetError())
	op := &HeartbeatOp{sessionID: sess.id}
	sess.sendDatabaseOp(op)
}

func (im *GetBlobUploadURLRequest) validate(version uint) *Error {
	if version < 3 {
		return minimumVersionError
	}
	return nil // req id is checked seperatly
}

func (im *GetBlobUploadURLRequest) handle(sess *Session, reqID *RequestId) {
	op := &GetBlobUploadURLOp{
		requestID: reqID,
		sessionID: sess.id,
		im:        im,
	}
	sess.sendDatabaseOp(op)
}

func (op *GetBlobUploadURLOp) handle(sess *Session) {
	resp := newGenericResponse(op.err)
	if op.err == nil {
		resp.Response = &Envelope_GenericResponse_Payload{[]byte(op.uploadURL.String())}
	}
	sess.writeResponse(op.requestID, resp)
}

func (op *SubscriptionPushOp) handle(sess *Session) {
	assertLTE(len(op.eventStates), limitMaxOutBatchSize)
	events := make([]*SubscriptionPushRequest_SequencedEvent, len(op.eventStates))
	for i, eventState := range op.eventStates {
		assert(eventState.seq != 0)
		events[i] = &SubscriptionPushRequest_SequencedEvent{
			Event: &eventState.encodedEvent,
			SeqNo: eventState.seq,
		}
		assert(eventState.encodedEvent.Event != nil)
	}
	spr := &Envelope_SubscriptionPushRequest{
		&SubscriptionPushRequest{Events: events},
	}
	reqID := sess.nextRequestID()
	sess.activePushes.Set(reqID.Raw, op)
	sess.writeRequest(reqID, spr)
}

func handleSubscriptionPushResponse(sess *Session, reqID *RequestId, resp *Envelope_GenericResponse) {
	assertNilError(resp.GetError())
	op := sess.activePushes.Get(reqID.Raw).(*SubscriptionPushOp)
	sess.activePushes.Delete(reqID.Raw)
	sess.sendDatabaseOp(op)
}

// event write validation

func validateShopManifest(_ uint, event *Manifest) *Error {
	errs := []*Error{
		validateBytes(event.TokenId.Raw, "token_id", 32),
	}
	for i, curr := range event.AcceptedCurrencies {
		field := fmt.Sprintf("accepted_currency[%d].addr", i)
		errs = append(errs, curr.Address.validate(field))
	}
	if base := event.PricingCurrency; base != nil {
		errs = append(errs, base.Address.validate("pricing_currencty.addr"))
	} else {
		errs = append(errs, &Error{Code: ErrorCodes_INVALID, Message: "pricing_currency is required"})
	}
	for i, payee := range event.Payees {
		field := fmt.Sprintf("payee[%d].addr", i)
		errs = append(errs, payee.validate(field))
	}
	for i, region := range event.ShippingRegions {
		field := fmt.Sprintf("shipping_region[%d]", i)
		errs = append(errs, region.validate(field))
	}
	return coalesce(errs...)
}

func validateUpdateManifest(_ uint, event *UpdateManifest) *Error {
	errs := []*Error{}
	hasOpt := false
	if adds := event.AddAcceptedCurrencies; len(adds) > 0 {
		// TODO: chain id allow list..?
		for i, add := range adds {
			field := fmt.Sprintf("add_accepted_currency[%d].addr", i)
			errs = append(errs, add.Address.validate(field))
		}
		hasOpt = true
	}
	if removes := event.RemoveAcceptedCurrencies; len(removes) > 0 {
		for i, remove := range removes {
			field := fmt.Sprintf("remove_accepted_currency[%d].addr", i)
			errs = append(errs, remove.Address.validate(field))
		}
		hasOpt = true
	}
	if base := event.SetPricingCurrency; base != nil {
		errs = append(errs, base.Address.validate("set_pricing_currencty.addr"))
		hasOpt = true
	}
	if base := event.AddPayee; base != nil {
		errs = append(errs, base.validate("add_payee"))
		hasOpt = true
	}
	if base := event.RemovePayee; base != nil {
		errs = append(errs, base.validate("remove_payee"))
		hasOpt = true
	}
	if adds := event.AddShippingRegions; len(adds) > 0 {
		for i, add := range adds {
			field := fmt.Sprintf("add_shipping_region[%d]", i)
			errs = append(errs, add.validate(field))
		}
		hasOpt = true
	}
	if removes := event.RemoveShippingRegions; len(removes) > 0 {
		for i, remove := range removes {
			field := fmt.Sprintf("remove_shipping_region[%d]", i)
			errs = append(errs, validateString(remove, field, 128))
		}
		hasOpt = true
	}

	if !hasOpt {
		errs = append(errs, &Error{Code: ErrorCodes_INVALID, Message: "updateManifest has no options set"})
	}
	return coalesce(errs...)
}

func validateListing(_ uint, event *Listing) *Error {
	errs := []*Error{
		validateObjectID(event.Id, "id"),
		event.Price.validate("base_price"),
		validateString(event.Metadata.Title, "base_info.title", 512),
		validateString(event.Metadata.Description, "base_info.description", 16*1024),
	}
	for i, u := range event.Metadata.Images {
		errs = append(errs, validateURL(u, fmt.Sprintf("base_info.images[%d]: invalid url", i)))
	}
	return coalesce(errs...)
}

func validateUpdateListing(_ uint, event *UpdateListing) *Error {
	errs := []*Error{
		validateObjectID(event.Id, "id"),
	}
	hasOpt := false
	if pr := event.Price; pr != nil {
		errs = append(errs, validateBytes(event.Price.Raw, "base_price", 32))
		hasOpt = true
	}
	if meta := event.Metadata; meta != nil {
		if meta.Title != "" {
			errs = append(errs, validateString(event.Metadata.Title, "base_info.title", 512))
		}
		if meta.Description != "" {
			errs = append(errs, validateString(event.Metadata.Description, "base_info.description", 16*1024))
		}
		for i, u := range meta.Images {
			errs = append(errs, validateURL(u, fmt.Sprintf("base_info.images[%d]: invalid url", i)))
		}
		hasOpt = true
	}
	if vs := event.ViewState; vs != nil {
		if *vs > ListingViewState_LISTING_VIEW_STATE_DELETED {
			errs = append(errs, &Error{Code: ErrorCodes_INVALID, Message: "invalid view_state"})
		}
		hasOpt = true
	}
	for i, ao := range event.AddOptions {
		field := fmt.Sprintf("add_options[%d]", i)
		errs = append(errs, ao.validate(field))
		hasOpt = true
	}
	for i, av := range event.AddVariations {
		field := fmt.Sprintf("add_variations[%d]", i)
		errs = append(errs,
			validateObjectID(av.OptionId, field+".option_id"),
			av.Variation.validate(field+".variation"),
		)
		hasOpt = true
	}
	for i, ro := range event.RemoveOptionIds {
		field := fmt.Sprintf("remove_options[%d]", i)
		errs = append(errs, validateObjectID(ro, field))
		hasOpt = true
	}
	for i, rv := range event.RemoveVariationIds {
		field := fmt.Sprintf("remove_variations[%d]", i)
		errs = append(errs, validateObjectID(rv, field))
		hasOpt = true
	}
	if !hasOpt {
		errs = append(errs, &Error{Code: ErrorCodes_INVALID, Message: "has no options set"})
	}
	return coalesce(errs...)
}

func validateChangeInventory(_ uint, event *ChangeInventory) *Error {
	errs := []*Error{
		validateObjectID(event.Id, "id"),
	}
	if event.Diff == 0 {
		errs = append(errs, &Error{Code: ErrorCodes_INVALID, Message: "diff can't be zero"})
	}
	return coalesce(errs...)
}

func validateCreateTag(_ uint, event *Tag) *Error {
	return coalesce(
		validateObjectID(event.Id, "id"),
		validateString(event.Name, "name", 64),
	)
}

func validateUpdateTag(_ uint, event *UpdateTag) *Error {
	errs := []*Error{
		validateObjectID(event.Id, "id"),
	}
	hasOpt := false
	if add := event.AddListingIds; len(add) > 0 {
		hasOpt = true
	}
	if rm := event.RemoveListingIds; len(rm) > 0 {
		hasOpt = true
	}
	if rename := event.Rename; rename != nil {
		errs = append(errs, validateString(*rename, "rename", 64))
		hasOpt = true
	}
	if event.Delete != nil {
		hasOpt = true
	}
	if !hasOpt {
		errs = append(errs, &Error{Code: ErrorCodes_INVALID, Message: "has no options set"})
	}
	return coalesce(errs...)
}

func validateCreateOrder(_ uint, event *CreateOrder) *Error {
	return validateObjectID(event.Id, "id")
}

func validateUpdateShippingDetails(_ uint, event *AddressDetails) *Error {
	errs := []*Error{
		validateString(event.Name, "name", 1024),
		validateString(event.Address1, "address1", 128),
		validateString(event.City, "city", 128),
		validateString(event.PostalCode, "postal_code", 25),
		validateString(event.Country, "country", 50),
		validateString(event.EmailAddress, "email_address", 320),
	}
	if event.PhoneNumber != nil {
		errs = append(errs, validateString(*event.PhoneNumber, "phone_number", 20))
	}
	return coalesce(errs...)
}

func validateUpdateOrder(v uint, event *UpdateOrder) *Error {
	errs := []*Error{
		validateObjectID(event.Id, "id"),
	}
	switch tv := event.Action.(type) {
	case *UpdateOrder_ChangeItems_:
		ci := tv.ChangeItems
		for i, change := range ci.Adds {
			errs = append(errs, validateObjectID(change.ListingId, fmt.Sprintf("change_items.adds[%d]", i)))
			for j, v := range change.VariationIds {
				errs = append(errs, validateObjectID(v, fmt.Sprintf("change_items.adds[%d].variation[%d]", i, j)))
			}
		}
		for i, change := range ci.Removes {
			errs = append(errs, validateObjectID(change.ListingId, fmt.Sprintf("change_items.removes[%d]", i)))
			for j, v := range change.VariationIds {
				errs = append(errs, validateObjectID(v, fmt.Sprintf("change_items.removes[%d].variation[%d]", i, j)))
			}
		}
	case *UpdateOrder_Cancel_:
		errs = append(errs, validateOrderCancel(v, tv.Cancel))
	case *UpdateOrder_SetInvoiceAddress:
		errs = append(errs, validateUpdateShippingDetails(v, tv.SetInvoiceAddress))
	case *UpdateOrder_SetShippingAddress:
		errs = append(errs, validateUpdateShippingDetails(v, tv.SetShippingAddress))
	case *UpdateOrder_CommitItems_:
		// noop
	case *UpdateOrder_ChoosePayment:
		errs = append(errs, validateUpdateOrderPaymentMenthod(v, tv.ChoosePayment))
	case *UpdateOrder_SetPaymentDetails:
		errs = append(errs, &Error{Code: ErrorCodes_INVALID, Message: "PaymentDetails can only be created by relays"})
	}
	return coalesce(errs...)
}

func validateOrderCancel(_ uint, _ *UpdateOrder_Cancel) *Error {
	return nil
}

func validateUpdateOrderPaymentMenthod(version uint, im *UpdateOrder_ChoosePaymentMethod) *Error {
	if version < 3 {
		return minimumVersionError
	}
	errs := []*Error{}
	if im.Currency == nil {
		errs = append(errs, &Error{
			Code:    ErrorCodes_INVALID,
			Message: "commit items needs to know the selected currency",
		})
	} else {
		errs = append(errs, im.Currency.validate("currency"))
	}
	if im.Payee == nil {
		errs = append(errs, &Error{
			Code:    ErrorCodes_INVALID,
			Message: "commit items needs to know the selected payee",
		})

	} else {
		errs = append(errs, im.Payee.validate("payee"))
	}
	return coalesce(errs...)
}

const shopEventTypeURL = "type.googleapis.com/market.mass.ShopEvent"

func (im *EventWriteRequest) validate(version uint) *Error {
	if version < 3 {
		return minimumVersionError
	}
	if len(im.Events) != 1 {
		return &Error{Code: ErrorCodes_INVALID, Message: "TODO: multiple writes"}
	}
	event := im.Events[0]
	// TODO: somehow fix double decode
	var decodedEvt ShopEvent
	if u := event.Event.TypeUrl; u != shopEventTypeURL {
		log("eventWriteRequest.validate: unexpected anypb typeURL: %s", u)
		return &Error{Code: ErrorCodes_INVALID, Message: "unsupported typeURL for event"}
	}
	if pberr := event.Event.UnmarshalTo(&decodedEvt); pberr != nil {
		log("eventWriteRequest.validate: anypb unmarshal failed: %s", pberr.Error())
		return &Error{Code: ErrorCodes_INVALID, Message: "invalid protobuf encoding"}
	}
	if err := event.Signature.validate(); err != nil {
		return err
	}
	if decodedEvt.Nonce == 0 {
		return &Error{Code: ErrorCodes_INVALID, Message: "missing nonce on shopEvent"}
	}
	if decodedEvt.Timestamp == nil {
		return &Error{Code: ErrorCodes_INVALID, Message: "timestamp can't be unset"}
	}
	if decodedEvt.Timestamp.Seconds == 0 {
		return &Error{Code: ErrorCodes_INVALID, Message: "timestamp can't be 0"}
	}
	var err *Error
	switch union := decodedEvt.Union.(type) {
	case *ShopEvent_Manifest:
		err = validateShopManifest(version, union.Manifest)
	case *ShopEvent_UpdateManifest:
		err = validateUpdateManifest(version, union.UpdateManifest)
	case *ShopEvent_Listing:
		err = validateListing(version, union.Listing)
	case *ShopEvent_UpdateListing:
		err = validateUpdateListing(version, union.UpdateListing)
	case *ShopEvent_ChangeInventory:
		err = validateChangeInventory(version, union.ChangeInventory)
	case *ShopEvent_Tag:
		err = validateCreateTag(version, union.Tag)
	case *ShopEvent_UpdateTag:
		err = validateUpdateTag(version, union.UpdateTag)
	case *ShopEvent_CreateOrder:
		err = validateCreateOrder(version, union.CreateOrder)
	case *ShopEvent_UpdateOrder:
		err = validateUpdateOrder(version, union.UpdateOrder)
	case *ShopEvent_Account:
		err = &Error{Code: ErrorCodes_INVALID, Message: "Account is not allowed in EventWriteRequest"}
	default:
		log("eventWriteRequest.validate: unrecognized event type: %T", decodedEvt.Union)
		return &Error{Code: ErrorCodes_INVALID, Message: "Unrecognized event type"}
	}
	if err != nil {
		return err
	}
	return nil
}

func (im *EventWriteRequest) handle(sess *Session, reqID *RequestId) {
	var decodedEvt ShopEvent
	if pberr := im.Events[0].Event.UnmarshalTo(&decodedEvt); pberr != nil {
		// TODO: somehow fix double decode
		// cant attach decodedEvt to EWR, since it's generate protobuf schema code
		check(pberr)
	}
	op := &EventWriteOp{
		requestID:      reqID,
		sessionID:      sess.id,
		im:             im,
		decodedShopEvt: &decodedEvt}
	sess.sendDatabaseOp(op)
}

func (op *EventWriteOp) handle(sess *Session) {
	om := newGenericResponse(op.err)
	if op.err == nil {
		om.Response = &Envelope_GenericResponse_Payload{op.newShopHash}
	}
	sess.writeResponse(op.requestID, om)
}

func (im *SubscriptionRequest) validate(_ uint) *Error {
	errs := []*Error{
		validateBytes(im.ShopId.Raw, "shop_id", 32),
	}
	for _, f := range im.Filters {
		if f.ObjectType == ObjectType_OBJECT_TYPE_UNSPECIFIED {
			errs = append(errs, &Error{Code: ErrorCodes_INVALID, Message: "filter object type invalid"})
		}
	}
	return coalesce(errs...)
}

func (im *SubscriptionRequest) handle(sess *Session, reqID *RequestId) {
	op := &SubscriptionRequestOp{
		requestID: reqID,
		sessionID: sess.id,
		im:        im,
	}
	sess.sendDatabaseOp(op)
}

func (op *SubscriptionRequestOp) handle(sess *Session) {
	om := newGenericResponse(op.err)
	if op.err == nil {
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, op.subscriptionID)
		om.Response = &Envelope_GenericResponse_Payload{buf}
	}
	sess.writeResponse(op.requestID, om)
}

func (im *SubscriptionCancelRequest) validate(_ uint) *Error {
	return validateBytes(im.SubscriptionId, "subscription_id", 2)
}

func (im *SubscriptionCancelRequest) handle(sess *Session, reqID *RequestId) {
	op := &SubscriptionCancelOp{
		requestID: reqID,
		sessionID: sess.id,
		im:        im,
	}
	sess.sendDatabaseOp(op)
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
		version:       op.sessionVersion,
		sessionOps:    op.sessionOps,
		subscriptions: make(map[uint16]*SubscriptionState),
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
		op.err = &Error{Code: ErrorCodes_INVALID, Message: "authentication not started"}
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
		if sessionState.version >= 8 {
			op.err = unlinkedKeyCardError
		} else {
			op.err = notFoundError
		}
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

// compute current shop hash
//
// until we need to verify proofs this is a pretty simple merkle tree with three intermediary nodes
// 1. the manifest
// 2. all published items
// 3. the stock counts
func (r *Relay) shopRootHash(_ ObjectIDArray) []byte {
	//start := now()
	//log("relay.shopRootHash shopId=%s", shopID)
	/* TODO: merklization definition
	shopManifest, has := r.shopManifestsByShopID.get(shopID)
	assertWithMessage(has, "no manifest for shopId")

	// 1. the manifest
	manifestHash := sha3.NewLegacyKeccak256()
	manifestHash.Write(shopManifest.shopTokenID)
	_, _ = fmt.Fprint(manifestHash, shopManifest.domain)
	manifestHash.Write(shopManifest.publishedTagID)
	//log("relay.shopRootHash manifest=%x", manifestHash.Sum(nil))

	// 2. all items in tags

	// 3. the stock
	stockHash := sha3.NewLegacyKeccak256()
	stock, has := r.stockByShopID.get(shopID)
	//assertWithMessage(has, "stock unavailable")
	if has {
		//log("relay.shopRootHash.hasStock shopId=%s", shopID)
		// see above
		stockIds := stock.inventory.Keys()
		sort.Sort(stockIds)

		for _, id := range stockIds {
			count := stock.inventory.MustGet(id)
			stockHash.Write(id)
			_, _ = fmt.Fprintf(stockHash, "%d", count)
		}
	}
	//log("relay.shopRootHash stock=%x", stockHash.Sum(nil))

	// final root hash of the three nodes
	rootHash := sha3.NewLegacyKeccak256()
	rootHash.Write(manifestHash.Sum(nil))
	rootHash.Write(publishedItemsHash.Sum(nil))
	rootHash.Write(stockHash.Sum(nil))

	digest := rootHash.Sum(nil)
	took := took(start)
	log("relay.shopRootHash.hash shop=%s digest=%x took=%d", shopID, digest, took)
	r.metric.counterAdd("shopRootHash_took", float64(took))
	return digest
	*/
	return bytes.Repeat([]byte("todo"), 8)
}

func (op *EventWriteOp) process(r *Relay) {
	ctx := context.Background()
	sessionID := op.sessionID
	requestID := op.requestID.Raw
	sessionState := r.sessionIDsToSessionStates.Get(sessionID)
	if sessionState == nil {
		logSR("relay.eventWriteOp.drain", sessionID, requestID)
		return
	} else if sessionState.shopID.Equal(zeroObjectIDArr) {
		logSR("relay.eventWriteOp.notAuthenticated", sessionID, requestID)
		op.err = notAuthenticatedError
		r.sendSessionOp(sessionState, op)
		return
	}
	start := now()
	logSR("relay.eventWriteOp.process", sessionID, requestID)
	r.lastSeenAtTouch(sessionState)

	// check nonce reuse
	var writtenNonce *uint64
	const maxNonceQry = `select max(eventNonce) from events where createdByShopID = $1 and  createdByKeyCardId = $2`
	err := r.connPool.QueryRow(ctx, maxNonceQry, sessionState.shopID[:], sessionState.keyCardID).Scan(&writtenNonce)
	check(err)
	if writtenNonce != nil && *writtenNonce >= op.decodedShopEvt.Nonce {
		logSR("relay.eventWriteOp.nonceReuse keyCard=%d written=%d new=%d", sessionID, requestID, sessionState.keyCardID, *writtenNonce, op.decodedShopEvt.Nonce)
		op.err = &Error{Code: ErrorCodes_INVALID, Message: "event nonce re-use"}
		r.sendSessionOp(sessionState, op)
		return
	}

	// check signature
	if err := op.im.Events[0].Verify(sessionState.keyCardPublicKey); err != nil {
		logSR("relay.eventWriteOp.verifyEventFailed err=%s", sessionID, requestID, err.Error())
		op.err = &Error{Code: ErrorCodes_INVALID, Message: "invalid signature"}
		r.sendSessionOp(sessionState, op)
		return
	}

	// check related event data exists, etc.
	meta := newMetadata(sessionState.keyCardID, sessionState.shopID, uint16(sessionState.version))
	if err := r.checkShopEventWriteConsistency(op.decodedShopEvt, meta, sessionState); err != nil {
		logSR("relay.eventWriteOp.checkEventFailed type=%T code=%s msg=%s", sessionID, requestID, op.decodedShopEvt.Union, err.Code, err.Message)
		op.err = err
		r.sendSessionOp(sessionState, op)
		return
	}

	// update shop
	r.beginSyncTransaction()
	r.writeEvent(op.decodedShopEvt, meta, op.im.Events[0])

	// processing for side-effects
	// - variation removal needs to cancel orders with them
	// - commit starts the payment timer
	// - payment choice starts the watcher
	{
		var err *Error
		if ul := op.decodedShopEvt.GetUpdateListing(); ul != nil &&
			(len(ul.RemoveVariationIds) > 0 || len(ul.RemoveOptionIds) > 0) {
			err = r.processRemoveVariation(sessionID, ul)
		}
		if uo := op.decodedShopEvt.GetUpdateOrder(); uo != nil {
			if ci := uo.GetCommitItems(); ci != nil {
				err = r.processOrderItemsCommitment(sessionID, uo.Id.Array())
			}
			if p := uo.GetChoosePayment(); p != nil {
				err = r.processOrderPaymentChoice(sessionID, uo.Id.Array(), p)
			}
		}
		if err != nil {
			op.err = err
			r.sendSessionOp(sessionState, op)
			r.rollbackSyncTransaction()
			return
		}
	}
	eventCount := len(r.queuedEventInserts)
	r.commitSyncTransaction()

	// compute resulting hash
	shopSeq := r.shopIDsToShopState.MustGet(sessionState.shopID)
	if shopSeq.lastUsedSeq >= 3 {
		hash := r.shopRootHash(sessionState.shopID)
		op.newShopHash = hash
	}
	r.sendSessionOp(sessionState, op)

	logSR("relay.eventWriteOp.finish new_events=%d took=%d", sessionID, requestID, eventCount, took(start))
}

func (r *Relay) checkShopEventWriteConsistency(union *ShopEvent, m CachedMetadata, sess *SessionState) *Error {
	manifest, shopExists := r.shopManifestsByShopID.get(m.createdByShopID, m.createdByShopID)
	shopManifestExists := shopExists && len(manifest.shopTokenID) > 0

	switch tv := union.Union.(type) {

	case *ShopEvent_Manifest:
		if sess.keyCardOfAGuest {
			return notFoundError
		}
		if shopManifestExists {
			return &Error{Code: ErrorCodes_INVALID, Message: "shop already exists"}
		}
		m := tv.Manifest
		usedNames := make(map[string]struct{})
		for _, payee := range m.Payees {
			_, has := usedNames[payee.Name]
			if has {
				return &Error{Code: ErrorCodes_INVALID, Message: "duplicate payee: " + payee.Name}
			}
			usedNames[payee.Name] = struct{}{}
		}
		usedCurrencies := make(map[cachedShopCurrency]struct{})
		for _, curr := range m.AcceptedCurrencies {
			k := curr.cached()
			_, has := usedCurrencies[k]
			if has {
				return &Error{
					Code:    ErrorCodes_INVALID,
					Message: fmt.Sprintf("duplicate currency: %v", k),
				}
			}
			usedCurrencies[k] = struct{}{}
		}
		usedNames = make(map[string]struct{})
		for _, region := range m.ShippingRegions {
			_, has := usedNames[region.Name]
			if has {
				return &Error{Code: ErrorCodes_INVALID, Message: fmt.Sprintf("duplicate region name: %q", region.Name)}
			}
			usedNames[region.Name] = struct{}{}
		}

	case *ShopEvent_UpdateManifest:
		if !shopManifestExists {
			return notFoundError
		}
		if sess.keyCardOfAGuest {
			return notFoundError
		}
		um := tv.UpdateManifest
		// this feels like a pre-op validation step but we dont have access to the relay there
		if p := um.AddPayee; p != nil {
			if _, has := manifest.payees[p.Name]; has {
				return &Error{Code: ErrorCodes_INVALID, Message: "payee nickname already taken"}
			}
			for name, payee := range manifest.payees {
				if bytes.Equal(payee.Address.Raw[:], p.Address.Raw) && payee.ChainId == p.ChainId {
					return &Error{Code: ErrorCodes_INVALID, Message: "conflicting payee: " + name}
				}
			}
		}
		if p := um.RemovePayee; p != nil {
			if _, has := manifest.payees[p.Name]; !has {
				return notFoundError
			}
		}
		for _, add := range um.AddAcceptedCurrencies {
			// check if already assigned
			c := cachedShopCurrency{
				common.Address(add.Address.Raw),
				add.ChainId,
			}
			if _, has := manifest.acceptedCurrencies[c]; has {
				return &Error{Code: ErrorCodes_INVALID, Message: "currency already in use"}
			}
			if !bytes.Equal(ZeroAddress[:], add.Address.Raw) {
				// validate existance of contract
				err := r.ethereum.CheckValidERC20Metadata(add.ChainId, common.Address(add.Address.Raw))
				if err != nil {
					return err
				}
			}
		}
		if curr := um.SetPricingCurrency; curr != nil {
			if !bytes.Equal(ZeroAddress[:], curr.Address.Raw) {
				err := r.ethereum.CheckValidERC20Metadata(curr.ChainId, common.Address(curr.Address.Raw))
				if err != nil {
					return err
				}
			}
		}
		for _, add := range um.AddShippingRegions {
			_, has := manifest.shippingRegions[add.Name]
			if has {
				return &Error{
					Code:    ErrorCodes_INVALID,
					Message: "name for shipping region already taken",
				}
			}
		}
		for _, rm := range um.RemoveShippingRegions {
			_, has := manifest.shippingRegions[rm]
			if !has {
				return &Error{
					Code:    ErrorCodes_INVALID,
					Message: "unknown shipping region",
				}
			}
		}

	case *ShopEvent_Listing:
		if !shopManifestExists || sess.keyCardOfAGuest {
			log("relay.checkEventWrite.createItem manifestExists=%v isGuest=%v", shopManifestExists, sess.keyCardOfAGuest)
			return notFoundError
		}
		evt := tv.Listing
		_, itemExists := r.listingsByListingID.get(m.createdByShopID, evt.Id.Array())
		if itemExists {
			return &Error{Code: ErrorCodes_INVALID, Message: "item already exists"}
		}

	case *ShopEvent_UpdateListing:
		if !shopManifestExists || sess.keyCardOfAGuest {
			log("relay.checkEventWrite.updateItem manifestExists=%v isGuest=%v", shopManifestExists, sess.keyCardOfAGuest)
			return notFoundError
		}
		evt := tv.UpdateListing
		item, itemExists := r.listingsByListingID.get(m.createdByShopID, evt.Id.Array())
		if !itemExists {
			return notFoundError
		}
		if !item.createdByShopID.Equal(sess.shopID) { // not allow to alter data from other shop
			return notFoundError
		}
		for _, opt := range evt.AddOptions {
			if _, has := item.options[opt.Id.Array()]; has {
				return &Error{Code: ErrorCodes_INVALID, Message: "option id already taken"}
			}
		}
		for _, opt := range evt.RemoveOptionIds {
			if _, has := item.options[opt.Array()]; !has {
				return &Error{Code: ErrorCodes_NOT_FOUND, Message: "option id not found"}
			}
		}
		for _, a := range evt.AddVariations {
			if _, has := item.options[a.OptionId.Array()]; !has {
				return notFoundError
			}
			// TODO: find a better mechanism to make variation IDs unique per item
			// so that we dont have to check all of them every time
			for _, vars := range item.options {
				if _, has := vars[a.Variation.Id.Array()]; has {
					return &Error{Code: ErrorCodes_INVALID, Message: "variation id already taken"}
				}
			}
		}
		for _, varid := range evt.RemoveVariationIds {
			var found bool
			for _, vars := range item.options {
				if _, has := vars[varid.Array()]; has {
					found = true
				}
			}
			if !found {
				return &Error{Code: ErrorCodes_NOT_FOUND, Message: "variation id not found"}
			}
		}

	case *ShopEvent_ChangeInventory:
		if !shopManifestExists || sess.keyCardOfAGuest {
			log("relay.checkEventWrite.changeStock manifestExists=%v isGuest=%v", shopManifestExists, sess.keyCardOfAGuest)
			return notFoundError
		}
		evt := tv.ChangeInventory
		itemID := evt.Id
		change := evt.Diff
		item, itemExists := r.listingsByListingID.get(m.createdByShopID, itemID.Array())
		if !itemExists {
			return notFoundError
		}
		if !item.createdByShopID.Equal(sess.shopID) { // not allow to alter data from other shops
			return notFoundError
		}
		// check wether variation is valid (all variations belong to different options)
		optUsed := make(map[ObjectIDArray]struct{})
		for _, wantVarID := range evt.VariationIds {
			var foundVarID ObjectIDArray
			var found bool
			// find option for variation
		lookForVar:
			for _, opt := range item.options {
				for varID := range opt {
					if bytes.Equal(wantVarID.Raw, varID[:]) {
						found = true
						foundVarID = varID
						break lookForVar
					}
				}
			}
			if !found {
				return &Error{Code: ErrorCodes_NOT_FOUND, Message: "option not found"}
			}
			if _, has := optUsed[foundVarID]; has {
				return &Error{Code: ErrorCodes_INVALID, Message: "option used more then once"}
			}
			optUsed[foundVarID] = struct{}{}
		}
		shopStock, shopStockExists := r.stockByShopID.get(m.createdByShopID, m.createdByShopID)
		if shopStockExists {
			if shopStock.inventory == nil && change < 0 {
				return &Error{Code: ErrorCodes_OUT_OF_STOCK, Message: "not enough stock"}
			}
			if shopStock.inventory != nil && change < 0 {
				items, has := shopStock.inventory.GetHas(newCombinedID(itemID, evt.VariationIds...))
				if has && items+change < 0 {
					return &Error{Code: ErrorCodes_OUT_OF_STOCK, Message: "not enough stock"}
				}
			}
		} else { // this might be the first changeStock event
			if change < 0 {
				return &Error{Code: ErrorCodes_OUT_OF_STOCK, Message: "not enough stock"}
			}
		}

	case *ShopEvent_Tag:
		if !shopManifestExists || sess.keyCardOfAGuest {
			return notFoundError
		}
		evt := tv.Tag
		_, tagExists := r.tagsByTagID.get(m.createdByShopID, evt.Id.Array())
		if tagExists {
			return &Error{Code: ErrorCodes_INVALID, Message: "tag already exists"}
		}

	case *ShopEvent_UpdateTag:
		if !shopManifestExists || sess.keyCardOfAGuest {
			return notFoundError
		}
		evt := tv.UpdateTag
		tag, tagExists := r.tagsByTagID.get(m.createdByShopID, evt.Id.Array())
		if !tagExists {
			return notFoundError
		}
		if !tag.createdByShopID.Equal(sess.shopID) { // not allow to alter data from other shops
			return notFoundError
		}
		for _, id := range evt.AddListingIds {
			item, itemExists := r.listingsByListingID.get(m.createdByShopID, id.Array())
			if !itemExists {
				return notFoundError
			}
			if item.createdByShopID != sess.shopID { // not allow to alter data from other shops
				return notFoundError
			}
		}
		for _, id := range evt.RemoveListingIds {
			item, itemExists := r.listingsByListingID.get(m.createdByShopID, id.Array())
			if !itemExists {
				return notFoundError
			}
			if item.createdByShopID != sess.shopID { // not allow to alter data from other shops
				return notFoundError
			}
		}
		if d := evt.Delete; d != nil && !*d {
			return &Error{Code: ErrorCodes_INVALID, Message: "Can't undelete a tag"}
		}

	case *ShopEvent_CreateOrder:
		if !shopManifestExists {
			return notFoundError
		}
		evt := union.GetCreateOrder()
		_, orderExists := r.ordersByOrderID.get(m.createdByShopID, evt.Id.Array())
		if orderExists {
			return &Error{Code: ErrorCodes_INVALID, Message: "order already exists"}
		}

	case *ShopEvent_UpdateOrder:
		if !shopManifestExists {
			return notFoundError
		}
		evt := tv.UpdateOrder
		order, orderExists := r.ordersByOrderID.get(m.createdByShopID, evt.Id.Array())
		if !orderExists {
			return notFoundError
		}
		if !order.createdByShopID.Equal(sess.shopID) { // not allow to alter data from other shops
			return notFoundError
		}

		if sess.keyCardOfAGuest && order.createdByKeyCardID != sess.keyCardID {
			return notFoundError
		}

		switch act := evt.Action.(type) {
		case *UpdateOrder_ChangeItems_:
			ci := act.ChangeItems
			if order.order.CommitedAt != nil {
				return &Error{Code: ErrorCodes_INVALID, Message: "order already finalized"}
			}
			changes := NewMapInts[combinedID, int64]()
			for _, item := range ci.Adds {
				obj, itemExists := r.listingsByListingID.get(m.createdByShopID, item.ListingId.Array())
				if !itemExists {
					return notFoundError
				}
				// not allow to use items from other shops
				if obj.createdByShopID != sess.shopID {
					return notFoundError
				}
				// check variation exists
				if n := len(item.VariationIds); n > 0 {
					var found int
					for _, want := range item.VariationIds {
						// TODO: find a better way to index these
						for _, opt := range obj.value.Options {
							for _, has := range opt.Variations {
								// TODO: ignore linting. 'Id' comes from proto
								if has.Id.Equal(want) {
									found++
								}
							}
						}
					}
					if found != n {
						return notFoundError
					}
				}
				sid := newCombinedID(item.ListingId, item.VariationIds...)
				changes.Set(sid, int64(item.Quantity))
			}
			for _, item := range ci.Removes {
				obj, itemExists := r.listingsByListingID.get(m.createdByShopID, item.ListingId.Array())
				if !itemExists {
					return notFoundError
				}
				// not allow to use items from other shops
				if !obj.createdByShopID.Equal(sess.shopID) {
					return notFoundError
				}
				sid := newCombinedID(item.ListingId, item.VariationIds...)
				changes.Set(sid, -int64(item.Quantity))
			}

		case *UpdateOrder_CommitItems_:
			stock, has := r.stockByShopID.get(m.createdByShopID, m.createdByShopID)
			if !has {
				return &Error{Code: ErrorCodes_INVALID, Message: "no stock for shop"}
			}
			items := order.items.Keys()
			if len(items) == 0 {
				return &Error{Code: ErrorCodes_INVALID, Message: "order is empty"}
			}
			for _, stockID := range items {
				_, has := r.listingsByListingID.get(m.createdByShopID, stockID.listingID)
				if !has {
					return notFoundError
				}
				// TODO: check variation exists?
				inStock, has := stock.inventory.GetHas(stockID)
				if !has || inStock == 0 {
					return &Error{Code: ErrorCodes_INVALID, Message: "not in stock"}
				}
				inOrder := order.items.Get(stockID)
				if inOrder > uint32(inStock) {
					return &Error{Code: ErrorCodes_INVALID, Message: "not enough items in stock for order"}
				}
			}

		case *UpdateOrder_SetInvoiceAddress:
			// noop

		case *UpdateOrder_SetShippingAddress:
			// noop

		case *UpdateOrder_Cancel_:
			if order.order.CommitedAt == nil {
				return &Error{Code: ErrorCodes_INVALID, Message: "order is not yet commited"}
			}

		case *UpdateOrder_ChoosePayment:
			if order.order.CommitedAt == nil {
				return &Error{Code: ErrorCodes_INVALID, Message: "order is not yet commited"}
			}
			if order.order.ShippingAddress == nil && order.order.InvoiceAddress == nil {
				return &Error{Code: ErrorCodes_INVALID, Message: "no shipping address chosen"}
			}
			if order.items.Size() == 0 {
				return &Error{Code: ErrorCodes_INVALID, Message: "order is empty"}
			}
			method := act.ChoosePayment
			p, has := manifest.payees[method.Payee.Name]
			if !has {
				return &Error{Code: ErrorCodes_INVALID, Message: "no such payee"}
			}
			if p.ChainId != method.Payee.ChainId || !bytes.Equal(p.Address.Raw, method.Payee.Address.Raw) {
				return &Error{Code: ErrorCodes_INVALID, Message: "payee missmatch"}
			}
			if method.Payee.ChainId != method.Currency.ChainId {
				return &Error{Code: ErrorCodes_INVALID, Message: "payee and chosenCurrency chain_id mismatch"}
			}
			chosenCurrency := cachedShopCurrency{
				common.Address(method.Currency.Address.Raw),
				method.Currency.ChainId,
			}
			_, has = manifest.acceptedCurrencies[chosenCurrency]
			if !has {
				return &Error{Code: ErrorCodes_INVALID, Message: "chosen currency not available"}
			}

		default:
			log("relay.checkEventWrite.updateOrder action=%T", act)
			return &Error{Code: ErrorCodes_INVALID, Message: "no action on updateOrder"}

		}

	default:
		panic(fmt.Errorf("eventWriteOp.validateWrite.unrecognizeType eventType=%T", union.Union))
	}
	return nil
}

// if we remove a variation from an unpayed order, we need to cancel open orders for it to avoid edge cases
func (r *Relay) processRemoveVariation(sessionID sessionID, listingUpdate *UpdateListing) *Error {
	ctx := context.Background()
	sessionState := r.sessionIDsToSessionStates.Get(sessionID)
	listingID := listingUpdate.Id
	listing, has := r.listingsByListingID.get(sessionState.shopID, listingID.Array())
	assert(has)

	// collect all variation IDs from both remove option(s) and remove variation(s)
	variations := NewSetInts[ObjectIDArray]()
	for _, vid := range listingUpdate.RemoveVariationIds {
		variations.Add(vid.Array())
	}
	for _, optID := range listingUpdate.RemoveOptionIds {
		for _, opt := range listing.value.Options {
			if opt.Id.Equal(optID) {
				for _, variation := range opt.Variations {
					variations.Add(variation.Id.Array())
				}
			}
		}
	}

	start := now()
	logS(sessionID, "relay.removeVariation.process listing=%x variations=%v", listingID.Raw, variations.Slice())

	otherOrderRows, err := r.syncTx.Query(ctx, `select orderId from payments
where shopId = $1
  and payedAt is null
  and itemsLockedAt >= now() - interval '1 day'`, sessionState.shopID[:])
	check(err)
	defer otherOrderRows.Close()

	otherOrderIDs := NewMapInts[ObjectIDArray, *CachedOrder]()
	for otherOrderRows.Next() {
		var otherOrderID ObjectIDArray
		var buf []byte
		check(otherOrderRows.Scan(&buf))
		assert(len(buf) == 8)
		otherOrderID = ObjectIDArray(buf)
		otherOrder, has := r.ordersByOrderID.get(sessionState.shopID, otherOrderID)
		assert(has)
		otherOrderIDs.Set(otherOrderID, otherOrder)
	}
	check(otherOrderRows.Err())

	// see if any orders include this listing and variation
	matchingOrders := NewSetInts[ObjectIDArray]()
	otherOrderIDs.All(func(orderID ObjectIDArray, order *CachedOrder) bool {
		order.items.All(func(ci combinedID, _ uint32) bool {
			if bytes.Equal(ci.listingID[:], listingID.Raw) {
				for _, vid := range ci.Variations() {
					if variations.Has(vid) {
						matchingOrders.Add(orderID)
						return true
					}
				}
			}
			return false
		})
		return false
	})

	if matchingOrders.Size() == 0 {
		logS(sessionID, "relay.removeVariation.noMatchingOrders took=%d", took(start))
		return nil
	}

	// cancel open orders
	now := timestamppb.Now()
	var orderIDslice = matchingOrders.Slice()
	// sadly go can't deal with []driver.Value directly
	var ordersAsBytes = make([][]byte, matchingOrders.Size())
	for i, oid := range orderIDslice {
		ordersAsBytes[i] = oid[:]
	}
	const paymentsUpdateQry = `update payments set canceledAt=$3 where shopId=$1 and orderId=any($2)`
	_, err = r.syncTx.Exec(ctx, paymentsUpdateQry, sessionState.shopID[:], ordersAsBytes, now.AsTime())
	check(err)
	for _, orderID := range orderIDslice {
		r.createRelayEvent(sessionState.shopID,
			&ShopEvent_UpdateOrder{
				&UpdateOrder{
					Id: &ObjectId{Raw: orderID[:]},
					Action: &UpdateOrder_Cancel_{
						&UpdateOrder_Cancel{},
					},
				},
			},
		)
	}

	logS(sessionID, "relay.removeVariation.finish orders=%d took=%d", len(orderIDslice), took(start))
	return nil
}

func (r *Relay) processOrderItemsCommitment(sessionID sessionID, orderID ObjectIDArray) *Error {
	ctx := context.Background()
	sessionState := r.sessionIDsToSessionStates.Get(sessionID)

	start := now()
	logS(sessionID, "relay.orderCommitItemsOp.process order=%x", orderID)

	// load realted data
	order, has := r.ordersByOrderID.get(sessionState.shopID, orderID)
	assert(has)

	shopID := order.createdByShopID

	stock, has := r.stockByShopID.get(shopID, shopID)
	assert(has)

	// get all other orders that haven't been paid yet
	// TODO: configure timeout
	otherOrderRows, err := r.syncTx.Query(ctx, `select orderId from payments
where shopId = $1
  and orderId != $2
  and payedAt is null
  and itemsLockedAt >= now() - interval '1 day'`,
		sessionState.shopID[:],
		orderID[:],
	)
	check(err)
	defer otherOrderRows.Close()

	otherOrderIDs := NewMapInts[ObjectIDArray, *CachedOrder]()
	for otherOrderRows.Next() {
		var buf []byte
		var otherOrderID ObjectIDArray
		check(otherOrderRows.Scan(&buf))
		assert(len(buf) == 8)
		otherOrderID = ObjectIDArray(buf)

		otherOrder, has := r.ordersByOrderID.get(sessionState.shopID, otherOrderID)
		assert(has)
		otherOrderIDs.Set(otherOrderID, otherOrder)
	}
	check(otherOrderRows.Err())

	// for convenience, sum up all items in the other orders
	otherOrderItemQuantities := NewMapInts[combinedID, uint32]()
	otherOrderIDs.All(func(_ ObjectIDArray, order *CachedOrder) bool {
		if order.order.CanceledAt != nil { // skip canceled orders
			return false
		}
		order.items.All(func(stockID combinedID, quantity uint32) bool {
			current := otherOrderItemQuantities.Get(stockID)
			current += quantity
			otherOrderItemQuantities.Set(stockID, current)
			return false
		})
		return false
	})

	// iterate over this order
	var invalidErr *Error
	order.items.All(func(cid combinedID, quantity uint32) bool {
		stockItems, has := stock.inventory.GetHas(cid)
		if !has {
			invalidErr = &Error{Code: ErrorCodes_OUT_OF_STOCK, Message: "not enough stock"}
			return true
		}

		usedInOtherOrders := otherOrderItemQuantities.Get(cid)
		if stockItems < 0 || uint32(stockItems)-usedInOtherOrders < quantity {
			invalidErr = &Error{Code: ErrorCodes_OUT_OF_STOCK, Message: "not enough stock"}
			return true
		}

		return false
	})
	if invalidErr != nil {
		return invalidErr
	}

	shopState := r.shopIDsToShopState.MustGet(sessionState.shopID)
	const insertPaymentQuery = `insert into payments (shopSeqNo, shopId, orderId, itemsLockedAt)
	VALUES ($1, $2, $3, now())`
	_, err = r.syncTx.Exec(ctx, insertPaymentQuery,
		shopState.lastUsedSeq,
		shopID[:],
		orderID[:],
	)
	check(err)

	logS(sessionID, "relay.orderCommitItemsOp.finish took=%d", took(start))
	return nil
}

var big100 = new(big.Int).SetInt64(100)

func (r *Relay) processOrderPaymentChoice(sessionID sessionID, orderID ObjectIDArray, method *UpdateOrder_ChoosePaymentMethod) *Error {
	ctx := context.Background()
	sessionState := r.sessionIDsToSessionStates.Get(sessionID)
	shopID := sessionState.shopID

	start := now()
	logS(sessionID, "relay.orderPaymentChoiceOp.process order=%x", orderID)

	// load related data
	order, has := r.ordersByOrderID.get(sessionState.shopID, orderID)
	assert(has)

	shop, has := r.shopManifestsByShopID.get(shopID, shopID)
	assert(has)

	shippingAddr := order.order.ShippingAddress
	if shippingAddr == nil {
		shippingAddr = order.order.InvoiceAddress
	}

	region, err := ScoreRegions(shop.shippingRegions, shippingAddr)
	if err != nil {
		logS(sessionID, "relay.orderPaymentChoiceOp.scoreRegions regions=%d err=%s", len(shop.shippingRegions), err)
		return &Error{Code: ErrorCodes_INVALID, Message: "unable to determin shipping region"}
	}

	// determain total price and create snapshot of items
	var (
		bigSubtotal = new(big.Int)
		invalidErr  *Error

		orderHash [32]byte

		done = make(chan struct{})
	)

	snapshotter, savedItems, err := newListingSnapshotter(r.metric, shopID)
	if err != nil {
		logS(sessionID, "relay.orderPaymentChoiceOp.ipfsClientFailed error=%s", err)
		return &Error{Code: ErrorCodes_INVALID, Message: "internal error"}
	}

	// iterate over this order
	order.items.All(func(cid combinedID, quantity uint32) bool {
		item, has := r.listingsByListingID.get(shopID, cid.listingID)
		if !has {
			invalidErr = notFoundError
			return true
		}

		snapshotter.save(cid, item)

		// total += quantity * price
		bigQuant := big.NewInt(int64(quantity))

		bigPrice := new(big.Int)
		bigPrice.SetBytes(item.value.Price.Raw)

		chosenVars := cid.Variations()
		found := 0
		for _, chosen := range chosenVars {
			// TODO: faster lookup of variations
			for _, availableVars := range item.options {
				for varID, variation := range availableVars {
					if varID.Equal(chosen) {
						if diff := variation.Diff; diff != nil {
							found++
							bigPriceDiff := new(big.Int)
							bigPriceDiff.SetBytes(diff.Diff.Raw)

							if variation.Diff.PlusSign {
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
			invalidErr = &Error{Code: ErrorCodes_OUT_OF_STOCK, Message: "variation no longer available"}
			return true
		}

		logS(sessionID, "relay.orderPaymentChoiceOp.subTotal current=%s | quant=%s price=%s", bigSubtotal, bigQuant, bigPrice)
		bigQuant.Mul(bigQuant, bigPrice)

		bigSubtotal.Add(bigSubtotal, bigQuant)
		logS(sessionID, "relay.orderPaymentChoiceOp.subTotal new=%s = oldSubTotal + quant_times_price(%s)", bigSubtotal, bigQuant)

		return false
	})
	if invalidErr != nil {
		return invalidErr
	}
	// worker to consume snapshot jobs
	var items []savedItem
	go func() {
		for it := range savedItems {
			items = append(items, it)
		}
		// create a sorting to make a deterministic order_hash
		slices.SortFunc(items, func(a, b savedItem) int {
			if a.cid.listingID != b.cid.listingID {
				return bytes.Compare(a.cid.listingID[:], b.cid.listingID[:])
			}
			return strings.Compare(a.cid.variations, b.cid.variations)
		})
		/* TODO: merkleization
		for _, it := range items {
			h := it.cid.Hash()
			//debug("DEBUG/itemHash id=%v hash=%s ipfs=%s", it.cid, h.Hex(), it.versioned)
			hasher.Write(h.Bytes())
		}
		hs := hasher.Sum(nil)
		copy(orderHash[:], hs)
		*/
		close(done)
	}()
	err = snapshotter.Wait() // also closes saveItems channel
	if err != nil {
		logS(sessionID, "relay.orderPaymentChoiceOp.itemSnapshots err=%s", err)
		return &Error{Code: ErrorCodes_INVALID, Message: "failed to snapshot items"}
	}
	<-done // wait for consumer to create orderHash

	// add taxes and shipping
	bigTotal := new(big.Int).Set(bigSubtotal)
	diff := new(big.Int)
	logS(sessionID, "relay.orderPaymentChoiceOp.total beforeModifiers=%s", bigTotal)
	for _, mod := range region.OrderPriceModifiers {
		switch tv := mod.Modification.(type) {
		case *OrderPriceModifier_Absolute:
			abs := tv.Absolute
			diff.SetBytes(abs.Diff.Raw)
			if abs.PlusSign {
				bigTotal.Add(bigTotal, diff)
			} else {
				bigTotal.Sub(bigTotal, diff)
			}
		case *OrderPriceModifier_Percentage:
			perc := tv.Percentage
			diff.SetBytes(perc.Raw)
			bigTotal.Mul(bigTotal, diff)
			bigTotal.Div(bigTotal, big100)
		}
	}

	logS(sessionID, "relay.orderPaymentChoiceOp.total after=%s", bigTotal)

	if n := len(bigTotal.Bytes()); n > 32 {
		logS(sessionID, "relay.orderPaymentChoiceOp.totalTooBig got=%d", n)
		return &Error{Code: ErrorCodes_INVALID, Message: ""}
	}

	// create payment address for order content
	var (
		chosenCurrency = cachedShopCurrency{
			common.Address(method.Currency.Address.Raw),
			method.Currency.ChainId,
		}
	)
	if !chosenCurrency.Equal(shop.pricingCurrency) {
		// convert base to chosen currency
		bigTotal, err = r.prices.Convert(shop.pricingCurrency, chosenCurrency, bigTotal)
		if err != nil {
			logS(sessionID, "relay.orderPaymentChoiceOp.priceConversion err=%s", err)
			return &Error{Code: ErrorCodes_INVALID, Message: "failed to establish conversion price"}
		}
	}

	bigShopTokenID := new(big.Int).SetBytes(shop.shopTokenID)

	// fallback for paymentAddr
	ownerAddr, err := r.ethereum.GetOwnerOfShop(bigShopTokenID)
	if err != nil {
		logS(sessionID, "relay.orderPaymentChoiceOp.shopOwnerFailed err=%s", err)
		return &Error{Code: ErrorCodes_INVALID, Message: "failed to get shop owner"}
	}

	// ttl
	blockNo, err := r.ethereum.GetCurrentBlockNumber(chosenCurrency.ChainID)
	if err != nil {
		logS(sessionID, "relay.orderPaymentChoiceOp.blockNumberFailed err=%s", err)
		return &Error{Code: ErrorCodes_INVALID, Message: "failed to get current block number"}
	}
	bigBlockNo := new(big.Int).SetInt64(int64(blockNo))

	block, err := r.ethereum.GetBlockByNumber(chosenCurrency.ChainID, bigBlockNo)
	if err != nil {
		logS(sessionID, "relay.orderPaymentChoiceOp.blockByNumberFailed block=%d err=%s", blockNo, err)
		return &Error{Code: ErrorCodes_INVALID, Message: "failed to get block by number"}
	}

	var pr = contractsabi.PaymentRequest{}
	pr.ChainId = new(big.Int).SetUint64(method.Payee.ChainId)
	pr.Ttl = new(big.Int).SetUint64(block.Time() + DefaultPaymentTTL)
	pr.Order = orderHash
	pr.Currency = chosenCurrency.Addr
	pr.Amount = bigTotal
	pr.PayeeAddress = common.Address(method.Payee.Address.Raw)
	pr.IsPaymentEndpoint = method.Payee.CallAsContract
	pr.ShopId = bigShopTokenID
	// TODO: calculate signature
	pr.ShopSignature = bytes.Repeat([]byte{0}, 64)

	paymentID, paymentAddr, err := r.ethereum.GetPaymentIDAndAddress(chosenCurrency.ChainID, &pr, ownerAddr)
	if err != nil {
		logS(sessionID, "relay.orderPaymentChoiceOp.paymentIDandAddrFailed order=%x err=%s", orderID, err)
		return &Error{Code: ErrorCodes_INVALID, Message: "failed to get paymentID"}
	}

	logS(sessionID, "relay.orderPaymentChoiceOp.paymentRequest id=%x addr=%x total=%s currentBlock=%d order_hash=%x", paymentID, paymentAddr, bigTotal.String(), blockNo, orderHash)

	// mark order as finalized by creating the event and updating payments table
	var (
		fin PaymentDetails
		w   PaymentWaiter
	)
	fin.PaymentId = &Hash{Raw: paymentID}
	fin.ShippingRegion = region
	fin.Ttl = pr.Ttl.String()

	fin.ListingHashes = make([]*IPFSAddress, len(items))
	for i, it := range items {
		fin.ListingHashes[i] = &IPFSAddress{Cid: it.versioned.RootCid().String()}
	}

	var pbTotal = &Uint256{Raw: make([]byte, 32)}
	bigTotal.FillBytes(pbTotal.Raw)
	fin.Total = pbTotal
	fin.ShopSignature = &Signature{Raw: pr.ShopSignature}

	r.createRelayEvent(shopID,
		&ShopEvent_UpdateOrder{
			&UpdateOrder{
				Id:     &ObjectId{Raw: orderID[:]},
				Action: &UpdateOrder_SetPaymentDetails{&fin},
			},
		})

	w.shopID = shopID
	w.orderID = order.order.Id.Array()
	w.paymentChosenAt = now()
	w.purchaseAddr = paymentAddr
	w.chainID = chosenCurrency.ChainID
	w.lastBlockNo.SetInt64(int64(blockNo))
	w.coinsTotal.Set(bigTotal)
	w.paymentID = paymentID

	var chosenIsErc20 = ZeroAddress.Cmp(chosenCurrency.Addr) != 0
	if chosenIsErc20 {
		w.erc20TokenAddr = &chosenCurrency.Addr
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
	_, err = r.syncTx.Exec(ctx, insertPaymentWaiterQuery,
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

	ctx = context.Background()
	if !chosenIsErc20 {
		r.watcherContextEtherCancel()
		r.watcherContextEther, r.watcherContextEtherCancel = context.WithCancel(ctx)
	}

	logS(sessionID, "relay.orderPaymentChoiceOp.finish took=%d", took(start))
	return nil
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
	logSR("relay.subscriptionRequestOp.process", sessionID, requestID)
	r.lastSeenAtTouch(session)

	if len(session.subscriptions) > 0 {
		// To not yield confusing ordering of events, until we have a better implementation, we only support one at a time
		// https://www.notion.so/massmarket/V3-Subscription-Constraints-54de7804cc504e5d8caf43b85002b5b2?pvs=4
		op.err = &Error{Code: ErrorCodes_INVALID, Message: "only one subscription"}
		r.sendSessionOp(session, op)
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

	subscription.lastStatusedSeq = startSeqNo
	subscription.lastBufferedSeq = startSeqNo
	subscription.lastPushedSeq = startSeqNo
	subscription.lastAckedSeq = startSeqNo
	subscription.lastAckedSeqFlushed = startSeqNo

	subscription.initialStatus = false
	subscription.nextPushIndex = 0
	// Build WHERE fragment used for pushing events
	var wheres []string
	for _, filter := range op.im.Filters {
		// Ensure that non-authenticated sessions can only access public content
		if !subscription.shopID.Equal(session.shopID) &&
			(filter.ObjectType == ObjectType_OBJECT_TYPE_INVENTORY ||
				filter.ObjectType == ObjectType_OBJECT_TYPE_ORDER) {
			logSR("relay.subscriptionRequestOp.notAllowed why=\"other shop\" filter=%s",
				sessionID, requestID, filter.ObjectType.String())
			op.err = &Error{Code: ErrorCodes_INVALID, Message: "not allowed"}
			r.sendSessionOp(session, op)
			return
		}

		// Restrict guest access to their own orders
		if session.keyCardOfAGuest {
			switch filter.ObjectType {
			case ObjectType_OBJECT_TYPE_ORDER:
				// Collect order IDs for verification
				if id := filter.GetObjectId(); id != nil {
					verifyOrderIDs = append(verifyOrderIDs, id.Raw)
				}
			case ObjectType_OBJECT_TYPE_INVENTORY:
				logSR("relay.subscriptionRequestOp.notAllowed filter=%s",
					sessionID, requestID, filter.ObjectType.String())
				op.err = &Error{Code: ErrorCodes_INVALID, Message: "not allowed"}
				r.sendSessionOp(session, op)
				return
			}
		}

		// Construct WHERE clause based on object type
		var where string
		switch filter.ObjectType {
		case ObjectType_OBJECT_TYPE_MANIFEST:
			where = ` (eventType='manifest' OR eventType='updateManifest')`
		case ObjectType_OBJECT_TYPE_ACCOUNT:
			where = ` (eventType='account')`
		case ObjectType_OBJECT_TYPE_INVENTORY:
			where = ` (eventType='changeInventory')`
		case ObjectType_OBJECT_TYPE_LISTING:
			where = ` (eventType='listing' OR eventType='updateListing')`
		case ObjectType_OBJECT_TYPE_TAG:
			where = ` (eventType='tag' OR eventType='updateTag')`
		case ObjectType_OBJECT_TYPE_ORDER:
			where = ` (eventType='createOrder' OR eventType='updateOrder')`
			// Add additional constraint for guest users
			if session.keyCardOfAGuest {
				where = where + fmt.Sprintf(" AND createdByKeyCardId=%d", session.keyCardID)
			}
		}

		// Add object ID constraint if provided
		if id := filter.ObjectId; id != nil {
			where = "(" + where + fmt.Sprintf(" AND objectId = '\\x%x')", id.Raw)
		}
		wheres = append(wheres, where)
	}

	// Combine all WHERE clauses with OR
	subscription.whereFragment = strings.Join(wheres, " OR ")

	if n := len(verifyOrderIDs); n > 0 {
		// check that all orders belong to the same person
		var count int
		const checkQry = `select count(*) from events
where eventType="createOrder"
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
		logS(op.sessionID, "relay.eventPushOp.drain")
		return
	}
	r.lastSeenAtTouch(sessionState)
	for _, entryState := range op.eventStates {
		entryState.acked = true
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

	shopID, shopDBID := r.getOrCreateInternalShopID(op.shopNFT)
	r.hydrateShops(NewSetInts(shopID))

	const insertKeyCard = `insert into keyCards (shopId, cardPublicKey, userWalletAddr, isGuest, lastVersion,  lastAckedSeq, linkedAt, lastSeenAt)
		VALUES ($1, $2, $3, $4, 0, 0, now(), now() )`
	_, err := r.syncTx.Exec(dbCtx, insertKeyCard, shopDBID, op.keyCardPublicKey, op.userWallet.Bytes(), op.keyCardIsGuest)
	check(err)

	// emit new keycard event
	r.createRelayEvent(shopID,
		&ShopEvent_Account{
			Account: &Account{
				Action: &Account_EnrollKeycard{
					&Account_KeyCardEnroll{
						KeycardPubkey: &PublicKey{Raw: op.keyCardPublicKey},
						UserWallet:    &EthereumAddress{Raw: op.userWallet[:]},
					},
				},
			},
		},
	)

	r.commitSyncTransaction()
	close(op.done)
	log("relay.KeyCardEnrolledOp.finish shopId=%d took=%d", shopDBID, took(start))
}

func (op *OnchainActionInternalOp) process(r *Relay) {
	assert(!op.shopID.Equal(zeroObjectIDArr))
	assert(op.user.Cmp(ZeroAddress) != 0)
	log("db.onchainActionInternalOp.start shopID=%x user=%s", op.shopID, op.user)
	start := now()

	var action isAccount_Action
	if op.add {
		action = &Account_Add{
			Add: &Account_OnchainAction{
				AccountAddress: &EthereumAddress{
					Raw: op.user.Bytes(),
				},
				Tx: &Hash{Raw: op.txHash.Bytes()},
			},
		}
	} else {
		action = &Account_Remove{
			Remove: &Account_OnchainAction{
				AccountAddress: &EthereumAddress{
					Raw: op.user.Bytes(),
				},
				Tx: &Hash{Raw: op.txHash.Bytes()},
			},
		}
	}

	r.beginSyncTransaction()
	r.hydrateShops(NewSetInts(op.shopID))
	r.createRelayEvent(op.shopID,
		&ShopEvent_Account{
			&Account{
				Action: action,
			},
		},
	)
	r.commitSyncTransaction()

	log("db.onchainActionInternalOp.finish took=%d", took(start))
}

func (op *PaymentFoundInternalOp) process(r *Relay) {
	shopID := op.shopID
	assert(!shopID.Equal(zeroObjectIDArr))
	orderID := op.orderID
	assert(!orderID.Equal(zeroObjectIDArr))
	assert(op.blockHash != nil)

	log("db.paymentFoundInternalOp.start shopID=%x orderID=%x", shopID, orderID)
	start := now()

	order, has := r.ordersByOrderID.get(shopID, orderID)
	assertWithMessage(has, fmt.Sprintf("order not found for orderId=%x", orderID))

	r.beginSyncTransaction()

	paid := &OrderTransaction{
		BlockHash: op.blockHash,
	}
	var txHash, blockHash *[]byte // for sql
	blockHash = &op.blockHash.Raw
	if t := op.txHash; t != nil { // we only get the tx hash for non-internal tx's
		paid.TxHash = t
		txHash = &t.Raw
	}

	const markOrderAsPayedQuery = `UPDATE payments SET
payedAt = NOW(),
payedTx = $1,
payedBlock = $2
WHERE shopID = $3 and orderId = $4;`
	_, err := r.syncTx.Exec(context.Background(), markOrderAsPayedQuery, txHash, blockHash, op.shopID[:], op.orderID[:])
	check(err)

	r.hydrateShops(NewSetInts(shopID))

	// emit changeInventory events for each item
	order.items.All(func(cid combinedID, quantity uint32) bool {
		assert(quantity < math.MaxInt32)
		varIDArrs := cid.Variations()
		varIDs := make([]*ObjectId, len(varIDArrs))
		for i, v := range varIDArrs {
			varIDs[i] = &ObjectId{Raw: v[:]}
		}
		r.createRelayEvent(shopID, &ShopEvent_ChangeInventory{
			&ChangeInventory{
				Id:           &ObjectId{Raw: cid.listingID[:]},
				VariationIds: varIDs,
				Diff:         -int32(quantity),
			},
		})
		return false
	})

	r.createRelayEvent(shopID,
		&ShopEvent_UpdateOrder{
			&UpdateOrder{
				Id: &ObjectId{Raw: orderID[:]},
				Action: &UpdateOrder_AddPaymentTx{
					paid,
				},
			},
		},
	)

	r.commitSyncTransaction()
	log("db.paymentFoundInternalOp.finish orderID=%x took=%d", orderID, took(start))
	close(op.done)
}

func (op *EventLoopPingInternalOp) process(_ *Relay) {
	close(op.done)
}
