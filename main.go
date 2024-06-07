// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

// Package main implements the relay server for a massMarket store
package main

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	sync "sync"
	"time"

	"github.com/cockroachdb/apd"
	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	ipfsFiles "github.com/ipfs/boxo/files"
	ipfsRpc "github.com/ipfs/kubo/client/rpc"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/miolini/datacounter"
	"github.com/multiformats/go-multiaddr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/cors"
	"github.com/ssgreg/repeat"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// Server configuration.
const (
	sessionPingInterval             = 5 * time.Second
	sessionKickTimeout              = 6 * sessionPingInterval
	sessionLastSeenAtFlushLimit     = 30 * time.Second
	sessionLastAckedKCSeqFlushLimit = 4096
	sessionBufferSizeRefill         = limitMaxOutRequests * limitMaxOutBatchSize
	sessionBufferSizeMax            = limitMaxOutRequests * limitMaxOutBatchSize * 2

	watcherTimeout           = 5 * time.Second
	databaseDebounceInterval = 100 * time.Millisecond
	tickStatsInterval        = 1 * time.Second
	tickBlockThreshold       = 50 * time.Millisecond
	memoryStatsInterval      = 5 * time.Second
	ethereumBlockInterval    = 15 * time.Second
	emitUptimeInterval       = 10 * time.Second

	databaseOpsChanSize           = 64 * 1024
	databasePropagationEventLimit = 5000

	maxItemMedataBytes = 5 * 1024
)

// set by build script via ldflags
var release = "unset"

// Toggle high-volume log traffic.
var (
	logMessages          = false
	logEphemeralMessages = false
	logMetrics           = false
)

// Enable error'd and ignore'd requests to be simulated with env variable.
// Given in integer percents, 0 <= r <= 100.
var simulateErrorRate = 0
var simulateIgnoreRate = 0

var (
	networkVersions            = []uint{2}
	currentRelayVersion uint16 = 2
)

var initLoggingOnce sync.Once

func initLogging() {
	logMessages = mustGetEnvBool("LOG_MESSAGES")
	logMetrics = mustGetEnvBool("LOG_METRICS")

	simulateErrorRateStr := os.Getenv("SIMULATE_ERROR_RATE")
	if simulateErrorRateStr != "" {
		var err error
		simulateErrorRate, err = strconv.Atoi(simulateErrorRateStr)
		check(err)
		assert(simulateErrorRate >= 0 && simulateErrorRate <= 100)
	}

	simulateIgnoreRateStr := os.Getenv("SIMULATE_IGNORE_RATE")
	if simulateIgnoreRateStr != "" {
		var err error
		simulateIgnoreRate, err = strconv.Atoi(simulateIgnoreRateStr)
		check(err)
		assert(simulateIgnoreRate >= 0 && simulateIgnoreRate <= 100)
	}
}

func (err *Error) Error() string {
	return "(" + ErrorCodes_name[int32(err.Code)] + "): " + err.Message
}

func coalesce(errs ...*Error) *Error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

var tooManyConcurrentRequestsError = &Error{
	Code:    ErrorCodes_TOO_MANY_CONCURRENT_REQUESTS,
	Message: "Too many concurrent requests sent to server",
}

var alreadyAuthenticatedError = &Error{
	Code:    ErrorCodes_ALREADY_AUTHENTICATED,
	Message: "Already authenticated in a previous message",
}

var notAuthenticatedError = &Error{
	Code:    ErrorCodes_NOT_AUTHENTICATED,
	Message: "Must authenticate before sending any other messages",
}

var alreadyConnectedError = &Error{
	Code:    ErrorCodes_ALREADY_CONNECTED,
	Message: "Already connected from this device in another session",
}

var unlinkedKeyCardError = &Error{
	Code:    ErrorCodes_UNLINKED_KEYCARD,
	Message: "Key Card was removed from the Store",
}

var notFoundError = &Error{
	Code:    ErrorCodes_NOT_FOUND,
	Message: "Item not found",
}

var simulateError = &Error{
	Code:    ErrorCodes_SIMULATED,
	Message: "Error condition simulated for this message",
}

var minimumVersionError = &Error{
	Code:    ErrorCodes_MINUMUM_VERSION_NOT_REACHED,
	Message: "Minumum version not reached for this request",
}

// Message types are protobuf messages with a requestId field.
type Message interface {
	proto.Message
	getRequestID() requestID // Generated
}

// RequestMessage return a response
type RequestMessage interface {
	response(*Error) Message
}

// ResponseMessage are messages that might contain an error
type ResponseMessage interface {
	Message
	getError() *Error // Generated
}

// InMessage are messages that are received from the client and handled by the server
type InMessage interface {
	Message
	handle(*Session)
}

// InRequestMessage are incoming requests that can be validated
type InRequestMessage interface {
	InMessage
	RequestMessage
	validate(uint) *Error
}

// Op are operations that are sent to the database
type Op interface {
	getSessionID() requestID // Generated
	setErr(*Error)           // Generated
}

// SessionOp are operations that are sent to the database and are specific to a session
type SessionOp interface {
	Op
	handle(*Session)
}

// RelayOp are operations that are sent to the database
type RelayOp interface {
	Op
	process(*Relay)
}

// StartOp starts a session
type StartOp struct {
	sessionID      requestID
	sessionVersion uint
	sessionOps     chan SessionOp
	err            *Error
}

// StopOp stops a session
type StopOp struct {
	sessionID requestID
	err       *Error
}

// HeartbeatOp triggers a PingRequest to the connected client
type HeartbeatOp struct {
	sessionID requestID
	err       *Error
}

// AuthenticateOp starts authentication of a session
type AuthenticateOp struct {
	sessionID requestID
	im        *AuthenticateRequest
	err       *Error
	challenge []byte
}

// ChallengeSolvedOp finishes authentication of a session
type ChallengeSolvedOp struct {
	sessionID requestID
	im        *ChallengeSolvedRequest
	err       *Error
}

// SyncStatusOp sends a SyncStatusRequest to the client
type SyncStatusOp struct {
	sessionID requestID
	err       *Error

	unpushedEvents uint64
}

// EventWriteOp processes a write of an event to the database
type EventWriteOp struct {
	sessionID       requestID
	im              *EventWriteRequest
	decodedStoreEvt *StoreEvent
	newStoreHash    []byte
	eventSeq        uint64
	err             *Error
}

// EventPushOp sends an EventPushRequest to the client
type EventPushOp struct {
	sessionID   requestID
	eventStates []*EventState
	err         *Error
}

// CommitItemsToOrderOp finalizes an open order.
// As a result, the relay will wait for the incoming transaction before creating a ChangeStock event.
type CommitItemsToOrderOp struct {
	sessionID        requestID
	im               *CommitItemsToOrderRequest
	orderFinalizedID eventID
	err              *Error
}

// GetBlobUploadURLOp processes a GetBlobUploadURLRequest from the client
type GetBlobUploadURLOp struct {
	sessionID requestID
	im        *GetBlobUploadURLRequest
	uploadURL *url.URL
	err       *Error
}

// Internal Ops

// KeyCardEnrolledInternalOp is triggered by a successful keycard enrollment.
// It results in a KeyCardEnrolled Event on the stores log
type KeyCardEnrolledInternalOp struct {
	storeID           eventID
	keyCardIsGuest    bool
	keyCardDatabaseID requestID
	keyCardPublicKey  []byte
	userWallet        common.Address
}

// PaymentFoundInternalOp is created by payment watchers
type PaymentFoundInternalOp struct {
	orderID eventID
	txHash  common.Hash

	// transaction, orderID, etc.

	done chan struct{}
}

// App/Client Sessions

// Session represents a connection to a client
type Session struct {
	id                requestID
	version           uint
	conn              net.Conn
	messages          chan InMessage
	activeInRequests  *MapRequestIDs[time.Time]
	activeOutRequests *SetRequestIDs
	activePushes      *MapRequestIDs[SessionOp]
	ops               chan SessionOp
	databaseOps       chan RelayOp
	metric            *Metric
	stopping          bool
}

func newSession(version uint, conn net.Conn, databaseOps chan RelayOp, metric *Metric) *Session {
	// TODO: Think more carefully about channel sizes.
	return &Session{
		id:                newRequestID(),
		version:           version,
		conn:              conn,
		messages:          make(chan InMessage, limitMaxInRequests*2),
		activeInRequests:  NewMapRequestIDs[time.Time](),
		activeOutRequests: NewSetRequestIDs(),
		activePushes:      NewMapRequestIDs[SessionOp](),
		ops:               make(chan SessionOp, (limitMaxInRequests+limitMaxOutRequests)*2),
		databaseOps:       databaseOps,
		metric:            metric,
		stopping:          false,
	}
}

// Starts a dedicated session reader goroutine. We need this to get messages
// on a channel to enable multi-way select in the main session go-routine.
// Note that the expected way to end this goroutine is Close'ing the conn
// so that a subsequent read errors.
func (sess *Session) readerRun() {
	logS(sess.id, "session.reader.start")
	// defer sentryRecover()

	for {
		im, err := sess.readerReadMessage()
		if err != nil {
			op := &StopOp{sessionID: sess.id}
			sess.sendDatabaseOp(op)
			return
		}

		select {
		case sess.messages <- im:
		default:
			panic(fmt.Errorf("sessionId=%s session.reader.sendMessage.blocked %+v", sess.id, im))
		}
	}
}

func (sess *Session) readerReadMessage() (InMessage, error) {
	bytes, err := wsutil.ReadClientBinary(sess.conn)
	if err != nil {
		logS(sess.id, "session.reader.readMessage.readError %+v", err)
		return nil, err
	}

	typeNum := bytes[0]
	messageBytes := bytes[1:]

	typeType, typeTypeOk := typesNumToType[typeNum]
	if !typeTypeOk {
		logS(sess.id, "session.reader.readMessage.unrecognizedTypeNum typeNum=%d", typeNum)
		return nil, errors.New("unrecognized typeNum")
	}

	messageValue := reflect.New(typeType)
	imUntyped := messageValue.Interface()
	im, imOk := imUntyped.(InMessage)
	if !imOk {
		logS(sess.id, "session.reader.readMessage.notInMessage typeNum=%d typeType=%v", typeNum, typeType)
		return nil, errors.New("not an in message")
	}

	err = proto.Unmarshal(messageBytes, im)
	if err != nil {
		logS(sess.id, "session.reader.readMessage.messageUnmarshalError %+v", err)
		return nil, err
	}

	if logMessages {
		logS(sess.id, "session.reader.readMessage requestId=%s type=%s length=%d", im.getRequestID(), typeType.Name(), len(bytes))
	}
	sess.metric.counterAdd("sessions_messages_read", 1)
	sess.metric.counterAdd("sessions_messages_read_bytes", float64(len(bytes)))
	sess.metric.counterAdd(fmt.Sprintf("sessions_messages_read_type_%s", typeType.Name()), 1)

	return im, nil
}

func (sess *Session) writeMessage(om Message) {
	requestID := om.getRequestID()
	requestID.assert()

	rm, isResponse := om.(ResponseMessage)
	if isResponse {
		// Note that this inbound requestId has been responded to.
		started, has := sess.activeInRequests.GetHas(requestID)
		assert(has)
		sess.activeInRequests.Delete(requestID)

		// Emit overall time the request took to process, from reading the request
		// to writing the response.
		sess.metric.emit("sessions_messages_write_elapsed", uint64(took(started)))

		// If we're sending an error, log it for our own visibility.
		responseErr := rm.getError()
		if responseErr != nil {
			logS(sess.id, "session.writeMessage.errorResponse requestId=%s code=%s message=\"%s\"", requestID, responseErr.Code, responseErr.Message)
			sess.metric.counterAdd("sessions_messages_write_error", 1)
		}
	} else {
		// Note that this requestId is outbound.
		assert(!sess.activeOutRequests.Has(requestID))
		sess.activeOutRequests.Add(requestID)
	}

	typePointerType := reflect.TypeOf(om)
	typeNum, ok := typesTypePointerToNum[typePointerType]
	typeType := typesNumToType[typeNum]
	assert(ok)
	typeBytes := []byte{typeNum}

	messageBytes, err := proto.Marshal(om)
	check(err)

	bytes := bytes.Join([][]byte{typeBytes, messageBytes}, []byte{})
	err = wsutil.WriteServerBinary(sess.conn, bytes)
	if err != nil {
		logS(sess.id, "session.writeMessage.writeError %+v", err)
		op := &StopOp{sessionID: sess.id}
		sess.sendDatabaseOp(op)
		return
	}

	if logMessages {
		logS(sess.id, "session.writeMessage requestId=%s type=%s length=%d", requestID, typeType.Name(), len(bytes))
	}
	sess.metric.counterAdd("sessions_messages_write", 1)
	sess.metric.counterAdd("sessions_messages_write_bytes", float64(len(bytes)))
	sess.metric.counterAdd(fmt.Sprintf("sessions_messages_write_type_%s", typeType.Name()), 1)
}

func (sess *Session) handleMessage(im InMessage) {
	// This accounting and verification happen here, instead of readMessage (which would be symmetric
	// with comparable code in write Message) because we need everything to happen in the same
	// goroutine, and readMessage is on a separate goroutine.

	// Ensure the client provides a valid requestID.
	// If the client does not we can't coherently respond to them.
	requestID := im.getRequestID()
	err := validateRequestID(requestID, "request_id")
	if err != nil {
		logS(sess.id, "session.handleMessage.invalidRequestIdError requestId=%s requestType=%T", requestID, im)
		op := &StopOp{sessionID: sess.id}
		sess.sendDatabaseOp(op)
		return
	}

	irm, irmOk := im.(InRequestMessage)
	if irmOk {
		// Requests must not duplicate client-originating request IDs.
		// If the client makes this error we can't coherently respond to them.
		if sess.activeInRequests.Has(requestID) {
			logS(sess.id, "session.handleMessage.duplicateRequestIdError requestId=%s requestType=%T", requestID, irm)
			op := &StopOp{sessionID: sess.id}
			sess.sendDatabaseOp(op)
			return
		}

		// Note that this requestId is inbound.
		sess.activeInRequests.Set(requestID, now())

		// Requests must not exceed concurrency limits.
		if sess.activeInRequests.Size() > limitMaxInRequests {
			logS(sess.id, "session.handleMessage.tooManyConcurrentRequestsError requestId=%s requestType=%T", requestID, irm)
			om := irm.response(tooManyConcurrentRequestsError)
			sess.writeMessage(om)
			return
		}

		// Validate request.
		err := irm.validate(sess.version)
		if err != nil {
			logS(sess.id, "session.handleMessage.validationError requestId=%s requestType=%T", requestID, irm)
			om := irm.response(err)
			sess.writeMessage(om)
			return
		}

		// Potentially insert simulate errors and ignores.
		randError := rand.Intn(100)
		if randError < simulateErrorRate {
			logS(sess.id, "session.handleMessage.simulateError requestId=%s requestType=%T", requestID, irm)
			om := irm.response(simulateError)
			sess.writeMessage(om)
			return
		}
		randIgnore := rand.Intn(100)
		if randIgnore < simulateIgnoreRate {
			logS(sess.id, "session.handleMessage.simulateIgnore requestId=%s requestType=%T", requestID, irm)
			return
		}

	} else {
		// Responses must correspond to server-originating request IDs.
		// If the client makes this error we can't coherently respond to them.
		if !sess.activeOutRequests.Has(requestID) {
			logS(sess.id, "session.handleMessage.unknownRequestIdError requestId=%s requestType=%T", requestID, im)
			op := &StopOp{sessionID: sess.id}
			sess.sendDatabaseOp(op)
			return
		}

		// Note that this outbound requestId has been responded to.
		sess.activeOutRequests.Delete(requestID)
	}

	// Handle message-specific logic.
	im.handle(sess)
}

// Send the op to the database. Log if it blocks so that we can see
// this happening in the logs. But since only the session is blocked,
// don't consider this fatal to the server.
func (sess *Session) sendDatabaseOp(op RelayOp) {
	select {
	case sess.databaseOps <- op:
	default:
		logS(sess.id, "session.sendDatabaseOp.blocked opType=%T", op)
		sess.databaseOps <- op
	}
}

func (op *StopOp) handle(sess *Session) {
	logS(sess.id, "session.stopOp")
	sess.stopping = true
}

func (sess *Session) heartbeat() {
	logS(sess.id, "session.heartbeat")
	om := &PingRequest{RequestId: newRequestID()}
	sess.writeMessage(om)
}

func (im *PingResponse) handle(sess *Session) {
	assertNilError(im.Error)
	op := &HeartbeatOp{sessionID: sess.id}
	sess.sendDatabaseOp(op)
}

func (im *AuthenticateRequest) validate(version uint) *Error {
	if version < 2 {
		return minimumVersionError
	}
	return validateBytes(im.PublicKey, "public_key", publicKeyBytes)
}

func (im *AuthenticateRequest) handle(sess *Session) {
	op := &AuthenticateOp{sessionID: sess.id, im: im}
	sess.sendDatabaseOp(op)
}

func (op *AuthenticateOp) handle(sess *Session) {
	om := op.im.response(op.err).(*AuthenticateResponse)
	if op.err == nil {
		om.Challenge = op.challenge
	}
	sess.writeMessage(om)
}

func (im *ChallengeSolvedRequest) validate(version uint) *Error {
	if version < 2 {
		return minimumVersionError
	}
	return validateBytes(im.Signature, "signature", signatureBytes)
}

func (im *ChallengeSolvedRequest) handle(sess *Session) {
	op := &ChallengeSolvedOp{sessionID: sess.id, im: im}
	sess.sendDatabaseOp(op)
}

func (op *ChallengeSolvedOp) handle(sess *Session) {
	om := op.im.response(op.err)
	sess.writeMessage(om)
}

func (op *SyncStatusOp) handle(sess *Session) {
	om := &SyncStatusRequest{
		RequestId: newRequestID(),

		UnpushedEvents: op.unpushedEvents,
	}
	sess.writeMessage(om)
}

func (im *SyncStatusResponse) handle(sess *Session) {
	assertNilError(im.Error)
	op := &HeartbeatOp{sessionID: sess.id}
	sess.sendDatabaseOp(op)
}

func (op *EventPushOp) handle(sess *Session) {
	assertLTE(len(op.eventStates), limitMaxOutBatchSize)
	events := make([]*anypb.Any, len(op.eventStates))
	var err error
	for i, eventState := range op.eventStates {
		eventState.eventID.assert()
		events[i] = eventState.encodedEvent
		assert(eventState.encodedEvent != nil)
		if err != nil {
			panic(fmt.Errorf("failed to create anypb for event: %w", err))
		}
	}

	om := &EventPushRequest{RequestId: newRequestID(), Events: events}
	sess.activePushes.Set(om.RequestId, op)
	sess.writeMessage(om)
}

func (im *EventPushResponse) handle(sess *Session) {
	assertNilError(im.Error)
	op := sess.activePushes.Get(im.RequestId).(*EventPushOp)
	sess.activePushes.Delete(im.RequestId)
	sess.sendDatabaseOp(op)
}

func validateStoreManifest(_ uint, event *StoreManifest) *Error {
	return coalesce(
		validateEventID(event.EventId, "event_id"),
		validateBytes(event.StoreTokenId, "store_token_id", 32),
		validateURL(event.Domain, "domain"),
		validateBytes(event.PublishedTagId, "published_tag_id", 32),
	)
}

func validateUpdateStoreManifest(_ uint, event *UpdateStoreManifest) *Error {
	errs := []*Error{validateEventID(event.EventId, "event_id")}
	hasOpt := false
	if d := event.Domain; d != nil {
		errs = append(errs, validateURL(*d, "domain"))
		hasOpt = true
	}
	if pt := event.PublishedTagId; len(pt) > 0 {
		errs = append(errs, validateEventID(pt, "published_tag_id"))
		hasOpt = true
	}
	if add := event.AddErc20Addr; len(add) > 0 {
		errs = append(errs, validateEthAddressBytes(add, "add_erc20_token_addr"))
		hasOpt = true
	}
	if remove := event.RemoveErc20Addr; len(remove) > 0 {
		errs = append(errs, validateEthAddressBytes(remove, "remove_erc20_token_addr"))
		hasOpt = true
	}
	if !hasOpt {
		errs = append(errs, &Error{Code: ErrorCodes_INVALID, Message: "has no options set"})
	}
	return coalesce(errs...)
}

func validateCreateItem(_ uint, event *CreateItem) *Error {
	errs := []*Error{
		validateEventID(event.EventId, "event_id"),
		validateDecimalPrice(event.Price, "price"),
	}
	if !json.Valid(event.Metadata) {
		errs = append(errs, &Error{Code: ErrorCodes_INVALID, Message: "Invalid metadata"})
	}
	if len(event.Metadata) > maxItemMedataBytes {
		errs = append(errs, &Error{Code: ErrorCodes_INVALID, Message: "Too much metadata"})
	}
	return coalesce(errs...)
}

func validateUpdateItem(_ uint, event *UpdateItem) *Error {
	errs := []*Error{
		validateEventID(event.EventId, "event_id"),
		validateEventID(event.ItemId, "item_id"),
	}
	hasOpt := false
	if pr := event.Price; pr != nil {
		errs = append(errs, validateDecimalPrice(*pr, "price"))
		hasOpt = true
	}
	if meta := event.Metadata; len(meta) > 0 {
		if !json.Valid(meta) {
			errs = append(errs, &Error{Code: ErrorCodes_INVALID, Message: "Invalid metadata"})
		}
		if len(meta) > maxItemMedataBytes {
			errs = append(errs, &Error{Code: ErrorCodes_INVALID, Message: "Too much metadata"})
		}
		hasOpt = true
	}
	if !hasOpt {
		errs = append(errs, &Error{Code: ErrorCodes_INVALID, Message: "has no options set"})
	}
	return coalesce(errs...)
}

func validateCreateTag(_ uint, event *CreateTag) *Error {
	return coalesce(
		validateEventID(event.EventId, "event_id"),
		validateString(event.Name, "name", 64),
	)
}

func validateUpdateTag(_ uint, event *UpdateTag) *Error {
	errs := []*Error{
		validateEventID(event.EventId, "event_id"),
		validateEventID(event.TagId, "tag_id"),
	}
	hasOpt := false
	if add := event.AddItemId; len(add) > 0 {
		errs = append(errs, validateEventID(add, "add_item_id"))
		hasOpt = true
	}
	if rm := event.RemoveItemId; len(rm) > 0 {
		errs = append(errs, validateEventID(rm, "remove_item_id"))
		hasOpt = true
	}
	if rename := event.Rename; rename != nil {
		errs = append(errs, validateString(*rename, "rename", 32))
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

func validateChangeStock(_ uint, event *ChangeStock) *Error {
	if len(event.OrderId) != 0 {
		return &Error{Code: ErrorCodes_INVALID, Message: "OrderId must be empty"}
	}
	if len(event.ItemIds) != len(event.Diffs) {
		return &Error{Code: ErrorCodes_INVALID, Message: "ItemId and Diff must have the same length"}
	}
	for i, item := range event.ItemIds {
		if err := validateEventID(item, fmt.Sprintf("item_id[%d]", i)); err != nil {
			return err
		}
	}
	return nil
}

func validateCreateOrder(_ uint, event *CreateOrder) *Error {
	return coalesce(
		validateEventID(event.EventId, "event_id"),
	)
}

func validateUpdateOrder(_ uint, event *UpdateOrder) *Error {
	errs := []*Error{
		validateEventID(event.EventId, "event_id"),
		validateEventID(event.OrderId, "order_id"),
	}
	switch tv := event.Action.(type) {
	case *UpdateOrder_ChangeItems_:
		errs = append(errs, validateChangeItems(2, tv.ChangeItems))
	case *UpdateOrder_ItemsFinalized_:
		errs = append(errs, &Error{Code: ErrorCodes_INVALID, Message: "OrderFinalized is not allowed in EventWriteRequest"})
	case *UpdateOrder_OrderCanceled_:
		errs = append(errs, validateOrderCanceled(2, tv.OrderCanceled))
	default:
		panic(fmt.Sprintf("Unhandled action type: %T", tv))
	}
	return coalesce(errs...)
}

func validateChangeItems(_ uint, event *UpdateOrder_ChangeItems) *Error {
	return coalesce(
		validateEventID(event.ItemId, "item_id"),
	)
}

func validateOrderCanceled(_ uint, event *UpdateOrder_OrderCanceled) *Error {
	if event.Timestamp == 0 {
		return &Error{Code: ErrorCodes_INVALID, Message: "timestamp can't be 0"}
	}
	return nil
}

func (im *EventWriteRequest) validate(version uint) *Error {
	if version < 2 {
		return minimumVersionError
	}
	var decodedEvt StoreEvent
	if pberr := im.Event.UnmarshalTo(&decodedEvt); pberr != nil {
		log("eventWriteRequest.validate: anypb unmarshal failed: %s", pberr.Error())
		return &Error{Code: ErrorCodes_INVALID, Message: "invalid protobuf encoding"}
	}
	if err := validateBytes(decodedEvt.Signature, "signature", signatureBytes); err != nil {
		return err
	}
	var err *Error
	switch union := decodedEvt.Union.(type) {
	case *StoreEvent_StoreManifest:
		err = validateStoreManifest(version, union.StoreManifest)
	case *StoreEvent_UpdateStoreManifest:
		err = validateUpdateStoreManifest(version, union.UpdateStoreManifest)
	case *StoreEvent_CreateItem:
		err = validateCreateItem(version, union.CreateItem)
	case *StoreEvent_UpdateItem:
		err = validateUpdateItem(version, union.UpdateItem)
	case *StoreEvent_CreateTag:
		err = validateCreateTag(version, union.CreateTag)
	case *StoreEvent_UpdateTag:
		err = validateUpdateTag(version, union.UpdateTag)
	case *StoreEvent_ChangeStock:
		err = validateChangeStock(version, union.ChangeStock)
	case *StoreEvent_CreateOrder:
		err = validateCreateOrder(version, union.CreateOrder)
	case *StoreEvent_UpdateOrder:
		err = validateUpdateOrder(version, union.UpdateOrder)
	case *StoreEvent_NewKeyCard:
		err = &Error{Code: ErrorCodes_INVALID, Message: "NewKeyCard is not allowed in EventWriteRequest"}
	default:
		log("eventWriteRequest.validate: unrecognized event type: %T", decodedEvt.Union)
		return &Error{Code: ErrorCodes_INVALID, Message: "Unrecognized event type"}
	}
	if err != nil {
		return err
	}
	return nil
}

func (im *EventWriteRequest) handle(sess *Session) {
	var decodedEvt StoreEvent
	if pberr := im.Event.UnmarshalTo(&decodedEvt); pberr != nil {
		// TODO: somehow fix double decode
		check(pberr)
	}
	op := &EventWriteOp{sessionID: sess.id, im: im, decodedStoreEvt: &decodedEvt}
	sess.sendDatabaseOp(op)
}

func (op *EventWriteOp) handle(sess *Session) {
	om := op.im.response(op.err).(*EventWriteResponse)
	if op.err == nil {
		om.NewStoreHash = op.newStoreHash
		om.EventSequenceNo = op.eventSeq
	}
	sess.writeMessage(om)
}

func (im *CommitItemsToOrderRequest) validate(version uint) *Error {
	if version < 2 {
		return minimumVersionError
	}
	errs := []*Error{
		validateEventID(im.OrderId, "order_id"),
	}
	if erc20 := im.GetErc20Addr(); erc20 != nil {
		errs = append(errs, validateEthAddressBytes(erc20, "erc20_addr"))
	}
	return coalesce(errs...)
}

func (im *CommitItemsToOrderRequest) handle(sess *Session) {
	op := &CommitItemsToOrderOp{sessionID: sess.id, im: im}
	sess.sendDatabaseOp(op)
}

func (op *CommitItemsToOrderOp) handle(sess *Session) {
	om := op.im.response(op.err).(*CommitItemsToOrderResponse)
	if op.err == nil {
		om.OrderFinalizedId = op.orderFinalizedID
	}
	sess.writeMessage(om)
}

func (im *GetBlobUploadURLRequest) validate(version uint) *Error {
	if version < 2 {
		return minimumVersionError
	}
	return nil // req id is checked seperatly
}

func (im *GetBlobUploadURLRequest) handle(sess *Session) {
	op := &GetBlobUploadURLOp{sessionID: sess.id, im: im}
	sess.sendDatabaseOp(op)
}

func (op *GetBlobUploadURLOp) handle(sess *Session) {
	om := op.im.response(op.err).(*GetBlobUploadURLResponse)
	if op.err == nil {
		om.Url = op.uploadURL.String()
	}
	sess.writeMessage(om)
}

func (sess *Session) run() {
	sess.metric.counterAdd("sessions_start", 1)
	logS(sess.id, "session.run.start version=%d", sess.version)
	go sess.readerRun()

	pingTimer := NewReusableTimer(sessionPingInterval)
	for {
		if sess.stopping {
			sess.metric.counterAdd("sessions_stop", 1)
			logS(sess.id, "session.run.stop")
			_ = sess.conn.Close()
			return
		}

		select {
		case <-pingTimer.C:
			sess.heartbeat()
			pingTimer.Rewind()

		case im := <-sess.messages:
			sess.handleMessage(im)
			pingTimer.Rewind()

		case op := <-sess.ops:
			op.handle(sess)
		}
	}
}

// IPFS integration
const ipfsMaxConnectTries = 3

// getIpfsClient recursivly calls itself until it was able to connect or until ipfsMaxConnectTries is reached.
func getIpfsClient(ctx context.Context, errCount int, lastErr error) (*ipfsRpc.HttpApi, error) {
	if errCount >= ipfsMaxConnectTries {
		return nil, fmt.Errorf("getIpfsClient: tried %d times.. last error: %w", errCount, lastErr)
	}
	if errCount > 0 {
		log("getIpfsClient.retrying lastErr=%s", lastErr)
		// TODO: exp backoff
		time.Sleep(1 * time.Second)
	}
	ipfsAPIAddr, err := multiaddr.NewMultiaddr(mustGetEnvString("IPFS_API_PATH"))
	if err != nil {
		// TODO: check type of error
		return getIpfsClient(ctx, errCount+1, fmt.Errorf("getIpfsClient: multiaddr.NewMultiaddr failed with %w", err))
	}
	ipfsClient, err := ipfsRpc.NewApi(ipfsAPIAddr)
	if err != nil {
		// TODO: check type of error
		return getIpfsClient(ctx, errCount+1, fmt.Errorf("getIpfsClient: ipfsRpc.NewApi failed with %w", err))
	}
	// check connectivity
	if isDevEnv {
		_, err := ipfsClient.Unixfs().Add(ctx, ipfsFiles.NewBytesFile([]byte("test")))
		if err != nil {
			return getIpfsClient(ctx, errCount+1, fmt.Errorf("getIpfsClient: (dev env) add 'test' failed %w", err))
		}
	} else {
		peers, err := ipfsClient.Swarm().Peers(ctx)
		if err != nil {
			// TODO: check type of error
			return getIpfsClient(ctx, errCount+1, fmt.Errorf("getIpfsClient: ipfsClient.Swarm.Peers failed with %w", err))
		}
		if len(peers) == 0 {
			// TODO: dial another peer
			// return getIpfsClient(ctx, errCount+1, fmt.Errorf("ipfs node has no peers"))
			log("getIpfsClient.warning: no peers")
		}
	}
	return ipfsClient, nil
}

// Database

// EventState represents the state of an event in the database.
type EventState struct {
	eventID eventID

	created struct {
		at                     time.Time
		byDeviceID, byStoreID  requestID
		byNetworkSchemaVersion uint64
	}

	storeSeq uint64

	kcSeq uint64
	acked bool

	encodedEvent *anypb.Any
}

// SessionState represents the state of a client in the database.
type SessionState struct {
	version               uint
	authChallenge         []byte
	sessionOps            chan SessionOp
	keyCardID             requestID
	keyCardPublicKey      []byte
	keyCardOfAGuest       bool
	storeID               eventID
	buffer                []*EventState
	initialStatus         bool
	lastStatusedKCSeq     uint64
	lastBufferedKCSeq     uint64
	lastPushedKCSeq       uint64
	nextPushIndex         int
	lastAckedKCSeq        uint64
	lastAckedKCSeqFlushed uint64
	lastSeenAt            time.Time
	lastSeenAtFlushed     time.Time
}

// CachedMetadata represents data cached which is common to all events
type CachedMetadata struct {
	createdByStoreID        eventID
	createdByKeyCardID      requestID
	createdByNetworkVersion uint16
	createdAt               uint64 // TODO: maybe change to time.Time
	// TODO: updatedAt uint64
	serverSeq uint64
	storeSeq  uint64
}

func newMetadata(keyCardID requestID, storeID eventID, version uint16) CachedMetadata {
	var metadata CachedMetadata
	metadata.createdByKeyCardID = keyCardID
	metadata.createdByStoreID = storeID
	metadata.createdByNetworkVersion = version
	return metadata
}

// CachedStoreManifest is latest reduction of a StoreManifest.
// It combines the intial StoreManifest and all UpdateStoreManifests
type CachedStoreManifest struct {
	CachedMetadata

	storeTokenID   []byte
	domain         string
	publishedTagID eventID
	acceptedErc20s map[common.Address]struct{}

	validKeyCardPublicKeys requestIDSlice
	validKeyCardIDs        *MapRequestIDs[keyCardIdWithGuest]

	init sync.Once
}

type keyCardIdWithGuest struct {
	id      requestID
	isGuest bool
}

func (current *CachedStoreManifest) getValidKeyCardIDs(pool *pgxpool.Pool) []keyCardIdWithGuest {
	// turn pubkeys into keyCardIDs

	valid := make([]keyCardIdWithGuest, len(current.validKeyCardPublicKeys))
	i := 0

	for _, publicKey := range current.validKeyCardPublicKeys {
		kcId, has := current.validKeyCardIDs.GetHas(publicKey)
		if !has {
			// TODO: potentially batch these
			const cardIdQry = `select id, isGuest from keyCards
where storeId = $1 and unlinkedAt is null and cardPublicKey = $2`
			row := pool.QueryRow(context.TODO(), cardIdQry, current.createdByStoreID, publicKey)

			var loaded keyCardIdWithGuest
			err := row.Scan(&loaded.id, &loaded.isGuest)
			if err == pgx.ErrNoRows {
				continue
			} else {
				check(err)
			}

			current.validKeyCardIDs.Set(publicKey, loaded)
			kcId = loaded
		}

		valid[i] = kcId
		i++
	}

	return valid
}

func (current *CachedStoreManifest) update(union *StoreEvent, meta CachedMetadata) {
	current.init.Do(func() {
		current.acceptedErc20s = make(map[common.Address]struct{})
		current.validKeyCardIDs = NewMapRequestIDs[keyCardIdWithGuest]()
	})
	switch union.Union.(type) {
	case *StoreEvent_StoreManifest:
		sm := union.GetStoreManifest()
		current.CachedMetadata = meta
		current.storeTokenID = sm.StoreTokenId
		current.domain = sm.Domain
		current.publishedTagID = sm.PublishedTagId
	case *StoreEvent_UpdateStoreManifest:
		um := union.GetUpdateStoreManifest()
		if d := um.Domain; d != nil {
			current.domain = *d
		}
		if pt := um.PublishedTagId; len(pt) > 0 {
			current.publishedTagID = pt
		}
		if addr := um.AddErc20Addr; len(addr) > 0 {
			current.acceptedErc20s[common.Address(addr)] = struct{}{}
		}
		if addr := um.RemoveErc20Addr; len(addr) > 0 {
			delete(current.acceptedErc20s, common.Address(addr))
		}
	case *StoreEvent_NewKeyCard:
		nkc := union.GetNewKeyCard()
		current.CachedMetadata = meta
		current.validKeyCardPublicKeys = append(current.validKeyCardPublicKeys, nkc.CardPublicKey)
	}
}

// CachedItem is the latest reduction of an Item.
// It combines the initial CreateItem and all UpdateItems
type CachedItem struct {
	CachedMetadata
	inited bool

	itemID   eventID
	price    *apd.Decimal
	metadata []byte
}

func (current *CachedItem) update(union *StoreEvent, meta CachedMetadata) {
	var err error
	switch union.Union.(type) {
	case *StoreEvent_CreateItem:
		assert(!current.inited)
		ci := union.GetCreateItem()
		current.CachedMetadata = meta
		current.itemID = ci.EventId
		current.price, _, err = apd.NewFromString(ci.Price)
		check(err)
		current.metadata = ci.Metadata
		current.inited = true
	case *StoreEvent_UpdateItem:
		ui := union.GetUpdateItem()
		if p := ui.Price; p != nil {
			current.price, _, err = apd.NewFromString(*p)
			check(err)
		}
		if meta := ui.Metadata; len(meta) > 0 {
			current.metadata = ui.GetMetadata()
		}
	default:
		panic(fmt.Sprintf("unhandled event type: %T", union.Union))
	}
}

// CachedTag is the latest reduction of a Tag.
// It combines the initial CreateTag and all AddToTag, RemoveFromTag, RenameTag, and DeleteTag
type CachedTag struct {
	CachedMetadata
	inited bool

	tagID   eventID
	name    string
	deleted bool
	items   *SetEventIDs
}

func (current *CachedTag) update(evt *StoreEvent, meta CachedMetadata) {
	if current.items == nil && !current.inited {
		current.items = NewSetEventIDs()
	}
	switch evt.Union.(type) {
	case *StoreEvent_CreateTag:
		assert(!current.inited)
		current.CachedMetadata = meta
		ct := evt.GetCreateTag()
		current.name = ct.Name
		current.tagID = ct.EventId
		current.inited = true

	case *StoreEvent_UpdateTag:
		ut := evt.GetUpdateTag()
		if id := ut.AddItemId; len(id) > 0 {
			current.items.Add(id)
		}
		if id := ut.RemoveItemId; len(id) > 0 {
			current.items.Delete(id)
		}
		if r := ut.Rename; r != nil {
			current.name = *r
		}
		if d := ut.Delete; d != nil && *d == true {
			current.deleted = true
		}
	default:
		panic(fmt.Sprintf("unhandled event type: %T", evt.Union))
	}
}

// CachedOrder is the latest reduction of a Order.
// It combines the initial CreateOrder and all ChangeOrder events
type CachedOrder struct {
	CachedMetadata
	inited    bool
	finalized bool
	abandoned bool
	payed     bool

	paymentId []byte

	txHash common.Hash

	orderID eventID
	items   *MapEventIDs[int32]
}

func (current *CachedOrder) update(evt *StoreEvent, meta CachedMetadata) {
	if current.items == nil && !current.inited {
		current.items = NewMapEventIDs[int32]()
	}
	switch evt.Union.(type) {
	case *StoreEvent_CreateOrder:
		assert(!current.inited)
		ct := evt.GetCreateOrder()
		current.CachedMetadata = meta
		current.orderID = ct.EventId
		current.inited = true
	case *StoreEvent_UpdateOrder:
		uo := evt.GetUpdateOrder()
		switch tv := uo.Action.(type) {
		case *UpdateOrder_ChangeItems_:
			change := tv.ChangeItems
			count := current.items.Get(change.ItemId)
			count += change.Quantity
			current.items.Set(change.ItemId, count)
		case *UpdateOrder_ItemsFinalized_:
			fin := tv.ItemsFinalized
			current.paymentId = fin.PaymentId
			current.finalized = true
		case *UpdateOrder_OrderCanceled_:
			current.abandoned = true

		default:
			panic(fmt.Sprintf("unhandled event type: %T", evt.Union))
		}
	case *StoreEvent_ChangeStock:
		current.payed = true
		cs := evt.GetChangeStock()
		current.txHash = common.Hash(cs.TxHash)
	default:
		panic(fmt.Sprintf("unhandled event type: %T", evt.Union))

	}
}

// CachedStock is the latest reduction of a Store's stock.
// It combines all ChangeStock events
type CachedStock struct {
	CachedMetadata

	inventory *MapEventIDs[int32]
}

func (current *CachedStock) update(evt *StoreEvent, _ CachedMetadata) {
	cs := evt.GetChangeStock()
	if cs == nil {
		return
	}
	if current.inventory == nil {
		current.inventory = NewMapEventIDs[int32]()
	}
	for i := 0; i < len(cs.ItemIds); i++ {
		itemID := cs.ItemIds[i]
		change := cs.Diffs[i]
		stock := current.inventory.Get(itemID)
		stock += change
		current.inventory.Set(itemID, stock)
	}
}

// CachedEvent is the interface for all cached events
type CachedEvent interface {
	comparable
	update(*StoreEvent, CachedMetadata)
}

type KeyCardEvent struct {
	keyCardId     requestID
	eventStoreSeq uint64
	keyCardSeq    uint64
}

// SeqPairKeyCard helps with writing events to the database
type SeqPairKeyCard struct {
	lastUsedKCSeq    uint64
	lastWrittenKCSeq uint64
}

// StoreState helps with writing events to the database
type StoreState struct {
	lastUsedStoreSeq    uint64
	lastWrittenStoreSeq uint64

	keyCards []requestID
}

// IO represents the input/output of the server.
type IO struct {
	metric    *Metric
	connPool  *pgxpool.Pool
	ethClient *ethClient
	prices    priceConverter
	// TODO: add ipfs client?
}

// Relay is the main server struct and represents the database layer
type Relay struct {
	writesEnabled bool // ensures to only create new entries if set to true

	IO
	sessionIDsToSessionStates *MapRequestIDs[*SessionState]
	opsInternal               chan RelayOp
	ops                       chan RelayOp

	blobUploadTokens   map[string]struct{}
	blobUploadTokensMu *sync.Mutex

	// persistence
	syncTx                  pgx.Tx
	queuedEventInserts      []*EventInsert
	keyCardIDsToKeyCardSeqs *MapRequestIDs[*SeqPairKeyCard]
	storeIdsToStoreState    *MapEventIDs[*StoreState]
	lastUsedServerSeq       uint64
	lastWrittenServerSeq    uint64

	// caching layer
	storeManifestsByStoreID *ReductionLoader[*CachedStoreManifest]
	itemsByItemID           *ReductionLoader[*CachedItem]
	tagsByTagID             *ReductionLoader[*CachedTag]
	ordersByOrderID         *ReductionLoader[*CachedOrder]
	stockByStoreID          *ReductionLoader[*CachedStock]
	allLoaders              []Loader
}

func newRelay(metric *Metric) *Relay {
	r := &Relay{}

	r.ethClient = newEthClient()
	if cgAPIKey := os.Getenv("COINGECKO_API_KEY"); cgAPIKey != "" {
		r.prices = newCoinGecko(cgAPIKey, "usd", "ethereum")
	} else {
		r.prices = testingConverter{}
	}

	r.sessionIDsToSessionStates = NewMapRequestIDs[*SessionState]()
	r.opsInternal = make(chan RelayOp)

	r.ops = make(chan RelayOp, databaseOpsChanSize)
	r.storeIdsToStoreState = NewMapEventIDs[*StoreState]()
	r.keyCardIDsToKeyCardSeqs = NewMapRequestIDs[*SeqPairKeyCard]()

	storeFieldFn := func(evt *StoreEvent, meta CachedMetadata) eventID {
		return meta.createdByStoreID
	}
	r.storeManifestsByStoreID = newReductionLoader[*CachedStoreManifest](r, storeFieldFn, []eventType{eventTypeStoreManifest, eventTypeUpdateStoreManifest, eventTypeNewKeyCard}, "createdByStoreId")
	itemsFieldFn := func(evt *StoreEvent, meta CachedMetadata) eventID {
		switch evt.Union.(type) {
		case *StoreEvent_CreateItem:
			return evt.GetCreateItem().EventId
		case *StoreEvent_UpdateItem:
			return evt.GetUpdateItem().ItemId
		case *StoreEvent_NewKeyCard:
			return evt.GetNewKeyCard().EventId
		}
		return nil
	}
	r.itemsByItemID = newReductionLoader[*CachedItem](r, itemsFieldFn, []eventType{eventTypeCreateItem, eventTypeUpdateItem}, "referenceId")
	tagsFieldFn := func(evt *StoreEvent, meta CachedMetadata) eventID {
		switch evt.Union.(type) {
		case *StoreEvent_CreateTag:
			return evt.GetCreateTag().EventId
		case *StoreEvent_UpdateTag:
			return evt.GetUpdateTag().TagId
		}
		return nil
	}
	r.tagsByTagID = newReductionLoader[*CachedTag](r, tagsFieldFn, []eventType{
		eventTypeCreateTag,
		eventTypeUpdateTag,
	}, "referenceId")

	ordersFieldFn := func(evt *StoreEvent, meta CachedMetadata) eventID {
		switch evt.Union.(type) {
		case *StoreEvent_CreateOrder:
			return evt.GetCreateOrder().EventId
		case *StoreEvent_UpdateOrder:
			return evt.GetUpdateOrder().OrderId
		case *StoreEvent_ChangeStock:
			cs := evt.GetChangeStock()
			if len(cs.OrderId) != 0 {
				return cs.OrderId
			}
		}
		return nil
	}
	r.ordersByOrderID = newReductionLoader[*CachedOrder](r, ordersFieldFn, []eventType{
		eventTypeCreateOrder,
		eventTypeUpdateOrder,
		eventTypeChangeStock,
	}, "referenceId")

	r.stockByStoreID = newReductionLoader[*CachedStock](r, storeFieldFn, []eventType{eventTypeChangeStock}, "createdByStoreId")

	r.blobUploadTokens = make(map[string]struct{})
	r.blobUploadTokensMu = &sync.Mutex{}

	r.metric = metric
	return r
}

func (r *Relay) connect() {
	log("relay.pg.connect")
	r.connPool = newPool()

	r.loadServerSeq()
}

// Send the op to the database (itself). Here a block is fatal because the
// database loop won't be able to progress.
func (db *Relay) sendDatabaseOp(op RelayOp) {
	select {
	case db.ops <- op:
	default:
		panic(fmt.Sprintf("relay.sendDatabaseOp.blocked: %+v", op))
	}
}

// TODO: generics solution to reduce [][]any copies
// Returns two slices: rows inserted, and rows not inserted due to conflicts.
func (r *Relay) bulkInsert(table string, columns []string, rows [][]interface{}) ([][]interface{}, [][]interface{}) {
	assertNonemptyString(table)
	assert(len(columns) > 0)
	assert(len(rows) > 0)
	start := now()
	ctx := context.Background()
	qb := strings.Builder{}
	qb.WriteString("insert into ")
	qb.WriteString(table)
	qb.WriteString(" (")
	for c := 0; c < len(columns); c++ {
		qb.WriteString(columns[c])
		if c < len(columns)-1 {
			qb.WriteString(",")
		}
	}
	qb.WriteString(") values (")
	for v := 1; v <= len(columns); v++ {
		qb.WriteString(fmt.Sprintf("$%d", v))
		if v < len(columns) {
			qb.WriteString(",")
		}
	}
	qb.WriteString(") on conflict do nothing")
	q := qb.String()
	insertedRows := make([][]interface{}, 0)
	conflictingRows := make([][]interface{}, 0)
	var tx pgx.Tx
	var err error
	if r.syncTx != nil {
		tx = r.syncTx
	} else {
		tx, err = r.connPool.Begin(ctx)
		defer func() {
			_ = tx.Rollback(ctx)
		}()
		check(err)
	}

	batch := &pgx.Batch{}
	for r := 0; r < len(rows); r++ {
		batch.Queue(q, rows[r]...)
	}
	br := tx.SendBatch(ctx, batch)
	for r := 0; r < len(rows); r++ {
		ct, err := br.Exec()
		if err != nil {
			fmt.Println("row:", rows[r], len(rows[r]))
			fmt.Println("cols:", columns, len(columns))
			check(err)
		}
		rowsAffected := ct.RowsAffected()
		if rowsAffected == 1 {
			insertedRows = append(insertedRows, rows[r])
		} else if rowsAffected == 0 {
			conflictingRows = append(conflictingRows, rows[r])
		} else {
			panic(fmt.Errorf("unexpected rowsAffected=%d", rowsAffected))
		}
	}
	check(br.Close())
	if r.syncTx == nil {
		check(tx.Commit(ctx))
	}
	log("relay.bulkInsert table=%s columns=%d rows=%d insertedRows=%d conflictingRows=%d elapsed=%d", table, len(columns), len(rows), len(insertedRows), len(conflictingRows), took(start))
	return insertedRows, conflictingRows
}

func (r *Relay) assertCursors(sessionID requestID, seqPair *SeqPairKeyCard, sessionState *SessionState) {
	err := r.checkCursors(sessionID, seqPair, sessionState)
	check(err)
}

func (r *Relay) checkCursors(_ requestID, seqPair *SeqPairKeyCard, sessionState *SessionState) error {
	if seqPair.lastUsedKCSeq < seqPair.lastWrittenKCSeq {
		return fmt.Errorf("cursor lastUsedStoreSeq(%d) < lastWrittenStoreSeq(%d)", seqPair.lastUsedKCSeq, seqPair.lastWrittenKCSeq)
	}
	if seqPair.lastWrittenKCSeq < sessionState.lastStatusedKCSeq {
		return fmt.Errorf("cursor: lastWrittenKCSeq(%d) < lastStatusedKCSeq(%d)", seqPair.lastWrittenKCSeq, sessionState.lastStatusedKCSeq)
	}
	if sessionState.lastStatusedKCSeq < sessionState.lastBufferedKCSeq {
		return fmt.Errorf("cursor: lastStatusedKCSeq(%d) < lastBufferedKCSeq(%d)", sessionState.lastStatusedKCSeq, sessionState.lastBufferedKCSeq)
	}
	if sessionState.lastBufferedKCSeq < sessionState.lastPushedKCSeq {
		return fmt.Errorf("cursor: lastBufferedKCSeq(%d) < lastPushedKCSeq(%d)", sessionState.lastBufferedKCSeq, sessionState.lastPushedKCSeq)
	}
	if sessionState.lastPushedKCSeq < sessionState.lastAckedKCSeq {
		return fmt.Errorf("cursor: lastPushedKCSeq(%d) < lastAckedKCSeq(%d)", sessionState.lastPushedKCSeq, sessionState.lastAckedKCSeq)
	}
	return nil
}

func (r *Relay) sendSessionOp(sessionState *SessionState, op SessionOp) {
	select {
	case sessionState.sessionOps <- op:
	default:
		panic(fmt.Errorf("relay.sendSessionOp.blocked keyCardId=%s %+v", sessionState.keyCardID, op))
	}
}

func (r *Relay) lastSeenAtTouch(sessionState *SessionState) time.Time {
	n := now()
	sessionState.lastSeenAt = n
	return n
}

func (r *Relay) hydrateKeyCards(kcIds *SetRequestIDs) {
	start := now()
	ctx := context.Background()
	novelKeyCardIds := NewSetRequestIDs()
	kcIds.All(func(keyCardID requestID) {
		if !r.keyCardIDsToKeyCardSeqs.Has(keyCardID) {
			novelKeyCardIds.Add(keyCardID)
		}
	})
	if sz := novelKeyCardIds.Size(); sz > 0 {
		novelKeyCardIds.All(func(keyCardID requestID) {
			seqPair := &SeqPairKeyCard{}
			r.keyCardIDsToKeyCardSeqs.Set(keyCardID, seqPair)
		})
		for _, novelUserIdsSubslice := range subslice(novelKeyCardIds.Slice(), 256) {
			// Index: userEntries(userId, userSeq)
			query := `with wanted (keyCardId) as (select unnest($1::bytea[]))
			select
				wanted.keyCardId,
				(select keyCardSeq from keyCardEvents where keyCardId = wanted.keyCardId order by keyCardSeq desc limit 1)
			from wanted`
			rows, err := r.connPool.Query(ctx, query, novelUserIdsSubslice)
			check(err)
			defer rows.Close()
			for rows.Next() {
				var keyCardID requestID
				var lastWrittenKCSeq *uint64
				err := rows.Scan(&keyCardID, &lastWrittenKCSeq)
				check(err)
				seqPair := r.keyCardIDsToKeyCardSeqs.MustGet(keyCardID)
				// handle NULL values as userSeq=0, which is initiated by default anyway
				if lastWrittenKCSeq != nil {
					seqPair.lastWrittenKCSeq = *lastWrittenKCSeq
					seqPair.lastUsedKCSeq = *lastWrittenKCSeq
				}

			}
			check(rows.Err())
		}
	}
	took := took(start)
	if novelKeyCardIds.Size() > 0 || took > 1 {
		log("db.hydrateUsers keyCards=%d novelKeyCards=%d took=%d", kcIds.Size(), novelKeyCardIds.Size(), took)
	}
}

func (r *Relay) hydrateStores(storeIds *SetEventIDs) {
	start := now()
	ctx := context.Background()
	novelStoreIds := NewSetEventIDs()
	storeIds.All(func(storeId eventID) {
		if !r.storeIdsToStoreState.Has(storeId) {
			novelStoreIds.Add(storeId)
		}
	})
	if sz := novelStoreIds.Size(); sz > 0 {
		novelStoreIds.All(func(storeId eventID) {
			seqPair := &StoreState{}
			r.storeIdsToStoreState.Set(storeId, seqPair)
		})
		for _, novelStoreIdsSubslice := range subslice(novelStoreIds.Slice(), 256) {
			// Index: events(createdByStoreId, storeSeq)
			query := `select createdByStoreId, max(storeSeq) from events where createdByStoreId = any($1) group by createdByStoreId`
			rows, err := r.connPool.Query(ctx, query, novelStoreIdsSubslice)
			check(err)
			defer rows.Close()
			for rows.Next() {
				var storeID eventID
				var lastWrittenStoreSeq *uint64
				err := rows.Scan(&storeID, &lastWrittenStoreSeq)
				check(err)
				seqPair := r.storeIdsToStoreState.MustGet(storeID)
				if lastWrittenStoreSeq != nil {
					seqPair.lastWrittenStoreSeq = *lastWrittenStoreSeq
					seqPair.lastUsedStoreSeq = *lastWrittenStoreSeq
				}
			}
			check(rows.Err())
		}
	}
	elapsed := took(start)
	if novelStoreIds.Size() > 0 || elapsed > 1 {
		log("relay.hydrateStores stores=%d novelStores=%d elapsed=%d", storeIds.Size(), novelStoreIds.Size(), elapsed)
		r.metric.counterAdd("hydrate_users", float64(novelStoreIds.Size()))
	}
}

func (r *Relay) loadServerSeq() {
	log("relay.loadServerSeq.start")
	start := now()
	// Index: none
	err := r.connPool.QueryRow(context.Background(), `select serverSeq from events order by serverSeq desc limit 1`).Scan(&r.lastWrittenServerSeq)
	if err != nil {
		if err == pgx.ErrNoRows {
			r.lastWrittenServerSeq = 0
		} else {
			panic(err)
		}
	}
	r.lastUsedServerSeq = r.lastWrittenServerSeq
	log("relay.loadServerSeq.finish serverSeq=%d elapsed=%d", r.lastUsedServerSeq, took(start))
}

// Read events from the database according to some
// `whereFragment` criteria, assumed to have a single `$1` arg for a
// slice of indexedIds.
// Does not change any in-memory caches; to be done by caller.
func (r *Relay) readEvents(whereFragment string, indexedIds []eventID) []EventInsert {
	// Index: events(field in whereFragment)
	// The indicies eventsOnEventTypeAnd* should correspond to the various Loaders defined in newDatabase.
	query := fmt.Sprintf(`select serverSeq, storeSeq, eventType, createdByKeyCardId, createdByStoreId, createdAt, createdByNetworkSchemaVersion, encoded from events where %s order by serverSeq asc`, whereFragment)
	var rows pgx.Rows
	var err error
	if r.syncTx != nil {
		rows, err = r.syncTx.Query(context.Background(), query, indexedIds)
	} else {
		rows, err = r.connPool.Query(context.Background(), query, indexedIds)
	}
	check(err)
	defer rows.Close()
	events := make([]EventInsert, 0)
	for rows.Next() {
		var (
			eventType eventType
			createdAt time.Time
			encoded   []byte
		)
		var m CachedMetadata
		err := rows.Scan(&m.serverSeq, &m.storeSeq, &eventType, &m.createdByKeyCardID, &m.createdByStoreID, &createdAt, &m.createdByNetworkVersion, &encoded)
		check(err)
		m.createdAt = uint64(createdAt.Unix())
		var e StoreEvent
		err = proto.Unmarshal(encoded, &e)
		check(err)
		events = append(events, EventInsert{CachedMetadata: m, evt: &e, evtType: eventType})
	}
	check(rows.Err())
	return events
}

// EventInsert is a struct that represents an event to be inserted into the database
type EventInsert struct {
	CachedMetadata
	evtType eventType
	evt     *StoreEvent
	pbany   *anypb.Any
}

func newEventInsert(evt *StoreEvent, meta CachedMetadata, abstract *anypb.Any) *EventInsert {
	meta.createdAt = uint64(now().Unix())
	return &EventInsert{
		CachedMetadata: meta,
		evt:            evt,
		pbany:          abstract,
	}
}

func (r *Relay) writeEvent(evt *StoreEvent, cm CachedMetadata, abstract *anypb.Any) {
	assert(r.writesEnabled)

	nextServerSeq := r.lastUsedServerSeq + 1
	cm.serverSeq = nextServerSeq
	r.lastUsedServerSeq = nextServerSeq

	storeSeqPair := r.storeIdsToStoreState.MustGet(cm.createdByStoreID)
	cm.storeSeq = storeSeqPair.lastUsedStoreSeq + 1
	storeSeqPair.lastUsedStoreSeq = cm.storeSeq

	insert := newEventInsert(evt, cm, abstract)
	r.queuedEventInserts = append(r.queuedEventInserts, insert)
	r.applyEvent(insert)
}

func (r *Relay) beginSyncTransaction() {
	assert(r.queuedEventInserts == nil)
	assert(r.syncTx == nil)
	r.queuedEventInserts = make([]*EventInsert, 0)
	ctx := context.Background()
	tx, err := r.connPool.Begin(ctx)
	check(err)
	r.syncTx = tx
}

func (r *Relay) commitSyncTransaction() {
	assert(r.queuedEventInserts != nil)
	assert(r.syncTx != nil)
	ctx := context.Background()
	r.flushEvents()
	check(r.syncTx.Commit(ctx))
	r.queuedEventInserts = nil
	r.syncTx = nil
}

var dbEventInsertColumns = []string{"eventType", "eventId", "createdByKeyCardId", "createdByStoreId", "storeSeq", "createdAt", "createdByNetworkSchemaVersion", "serverSeq", "encoded", "referenceID"}

func formInsert(ins *EventInsert) []interface{} {
	var (
		evtType eventType
		evtID   eventID
		refID   *eventID // used to stich together related events
	)
	switch ins.evt.Union.(type) {
	case *StoreEvent_StoreManifest:
		evtType = eventTypeStoreManifest
		evtID = ins.evt.GetStoreManifest().EventId
	case *StoreEvent_UpdateStoreManifest:
		evtType = eventTypeUpdateStoreManifest
		evtID = ins.evt.GetUpdateStoreManifest().EventId
	case *StoreEvent_CreateItem:
		evtType = eventTypeCreateItem
		evtID = ins.evt.GetCreateItem().EventId
		refID = &evtID
	case *StoreEvent_UpdateItem:
		evtType = eventTypeUpdateItem
		ui := ins.evt.GetUpdateItem()
		evtID = ui.EventId
		refID = (*eventID)(&ui.ItemId)
	case *StoreEvent_CreateTag:
		evtType = eventTypeCreateTag
		evtID = ins.evt.GetCreateTag().EventId
		refID = &evtID
	case *StoreEvent_UpdateTag:
		evtType = eventTypeUpdateTag
		ut := ins.evt.GetUpdateTag()
		evtID = ut.EventId
		refID = (*eventID)(&ut.TagId)
	case *StoreEvent_ChangeStock:
		evtType = eventTypeChangeStock
		cs := ins.evt.GetChangeStock()
		evtID = cs.EventId
		if len(cs.OrderId) > 0 {
			refID = (*eventID)(&cs.OrderId)
		}
	case *StoreEvent_CreateOrder:
		evtType = eventTypeCreateOrder
		cc := ins.evt.GetCreateOrder()
		evtID = cc.EventId
		refID = &evtID
	case *StoreEvent_UpdateOrder:
		evtType = eventTypeUpdateOrder
		uo := ins.evt.GetUpdateOrder()
		evtID = uo.EventId
		refID = (*eventID)(&uo.OrderId)
	case *StoreEvent_NewKeyCard:
		evtType = eventTypeNewKeyCard
		evtID = ins.evt.GetNewKeyCard().EventId
	default:
		panic(fmt.Errorf("formInsert.unrecognizeType eventType=%T", ins.evt.Union))
	}
	return []interface{}{
		evtType,                     // eventType
		evtID,                       // eventId
		ins.createdByKeyCardID,      // createdByKeyCardId
		ins.createdByStoreID,        // createdByStoreId
		ins.storeSeq,                // storeSeq
		now(),                       // createdAt
		ins.createdByNetworkVersion, // createdByNetworkSchemaVersion
		ins.serverSeq,               // serverSeq
		ins.pbany.Value,             // encoded
		refID,                       // referenceID
	}
}

func (r *Relay) flushEvents() {
	if len(r.queuedEventInserts) == 0 {
		return
	}
	assert(r.writesEnabled)
	log("relay.flushEvents.start entries=%d", len(r.queuedEventInserts))
	start := now()

	eventTuples := make([][]any, len(r.queuedEventInserts))
	for i, ei := range r.queuedEventInserts {
		eventTuples[i] = formInsert(ei)
	}
	assert(r.lastWrittenServerSeq < r.lastUsedServerSeq)
	insertedEventRows, conflictedEventRows := r.bulkInsert("events", dbEventInsertColumns, eventTuples)
	for _, row := range insertedEventRows {
		rowServerSeq := row[7].(uint64)
		assert(r.lastWrittenServerSeq < rowServerSeq)
		assert(rowServerSeq <= r.lastUsedServerSeq)
		r.lastWrittenServerSeq = rowServerSeq
		rowStoreID := row[3].(eventID)
		rowStoreSeq := row[4].(uint64)
		storeSeqPair := r.storeIdsToStoreState.MustGet(rowStoreID)
		assert(storeSeqPair.lastWrittenStoreSeq < rowStoreSeq)
		assert(rowStoreSeq <= storeSeqPair.lastUsedStoreSeq)
		storeSeqPair.lastWrittenStoreSeq = rowStoreSeq
	}
	assert(r.lastWrittenServerSeq <= r.lastUsedServerSeq)

	// We only want to propagate the original event write and don't want to redo it if the
	// event is written again idempotently (i.e. ends up in the discarded conflicted rows
	// value above.)
	// Don't do anything if there were no inserts because this would lead to an empty
	// bulk insert.
	if len(insertedEventRows) > 0 {
		eventPropagationTuples := make([][]any, len(insertedEventRows))
		for i, row := range insertedEventRows {
			eventPropagationTuples[i] = []any{row[1].(eventID)}
		}
		r.bulkInsert("eventPropagations", []string{"eventId"}, eventPropagationTuples)
		for _, row := range conflictedEventRows {
			log("db.flushEntries.discardConflictedEvent eventId=%x", row[1].(eventID))
		}
	}

	r.queuedEventInserts = nil
	log("relay.flushEvents.finish insertedEntries=%d conflictedEntries=%d elapsed=%d", len(insertedEventRows), len(conflictedEventRows), took(start))
}

// returns true if the event is owned by the passed store and keyCard
func (r *Relay) doesSessionOwnEvent(session *SessionState, eventID eventID) bool {
	ctx := context.Background()

	// crawl all keyCards of this user
	const checkOrderOwnershipQuery = `select count(*) from events
where createdByKeyCardId in (select id from keycards where userWalletAddr = (select userWalletAddr from keyCards where id = $1))
and createdByStoreId = $2
and eventId = $3`
	var found int
	err := r.connPool.QueryRow(ctx, checkOrderOwnershipQuery, session.keyCardID, session.storeID, eventID).Scan(&found)
	check(err)
	return found == 1
}

// Loader is an interface for all loaders.
// Loaders represent the read-through cache layer.
type Loader interface {
	applyEvent(*EventInsert)
}

type fieldFn func(*StoreEvent, CachedMetadata) eventID

// ReductionLoader is a struct that represents a loader for a specific event type
type ReductionLoader[T CachedEvent] struct {
	db            *Relay
	fieldFn       fieldFn
	loaded        *MapEventIDs[T]
	whereFragment string
}

func newReductionLoader[T CachedEvent](r *Relay, fn fieldFn, pgTypes []eventType, pgField string) *ReductionLoader[T] {
	sl := &ReductionLoader[T]{}
	sl.db = r
	sl.fieldFn = fn
	sl.loaded = NewMapEventIDs[T]()
	var quotedTypes = make([]string, len(pgTypes))
	for i, pgType := range pgTypes {
		quotedTypes[i] = fmt.Sprintf("'%s'", string(pgType))
	}
	sl.whereFragment = fmt.Sprintf(`eventType IN (%s) and %s = any($1)`, strings.Join(quotedTypes, ","), pgField)
	r.allLoaders = append(r.allLoaders, sl)
	return sl
}

func (sl *ReductionLoader[T]) applyEvent(e *EventInsert) {
	fieldID := sl.fieldFn(e.evt, e.CachedMetadata)
	if fieldID == nil {
		return
	}
	v, has := sl.loaded.GetHas(fieldID)
	if has {
		v.update(e.evt, e.CachedMetadata)
	}
}

func (sl *ReductionLoader[T]) get(indexedID eventID) (T, bool) {
	var zero T
	_, known := sl.loaded.GetHas(indexedID)
	if !known {
		entries := sl.db.readEvents(sl.whereFragment, []eventID{indexedID})
		if len(entries) == 0 {
			return zero, false
		}
		var empty T
		typeOf := reflect.TypeOf(empty)
		var zeroValT = reflect.New(typeOf.Elem())
		var zeroVal = zeroValT.Interface().(T)
		sl.loaded.Set(indexedID, zeroVal)
		for _, e := range entries {
			sl.applyEvent(&e)
		}
		for _, qei := range sl.db.queuedEventInserts {
			sl.applyEvent(qei)
		}
	}
	all, has := sl.loaded.GetHas(indexedID)
	return all, has
}

func (r *Relay) applyEvent(e *EventInsert) {
	for _, loader := range r.allLoaders {
		loader.applyEvent(e)
	}
}

func (op *StartOp) process(r *Relay) {
	assert(!r.sessionIDsToSessionStates.Has(op.sessionID))
	assert(op.sessionVersion != 0)
	assert(op.sessionOps != nil)
	logS(op.sessionID, "relay.startOp.start")
	sessionState := &SessionState{
		version:    op.sessionVersion,
		sessionOps: op.sessionOps,
		buffer:     make([]*EventState, 0),
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
	} else if sessionState.keyCardID != nil {
		logS(op.sessionID, "relay.authenticateOp.alreadyAuthenticated")
		op.err = alreadyAuthenticatedError
		r.sendSessionOp(sessionState, op)
		return
	}

	logS(op.sessionID, "relay.authenticateOp.start")
	authenticateOpStart := now()

	var keyCardID requestID
	var storeID requestID
	logS(op.sessionID, "relay.authenticateOp.idsQuery")
	ctx := context.Background()
	// Index: keyCards(publicKey)
	query := `select id, storeId from keyCards
	where cardPublicKey = $1 and unlinkedAt is null`
	err := r.connPool.QueryRow(ctx, query, op.im.PublicKey).Scan(&keyCardID, &storeID)
	if err == pgx.ErrNoRows {
		logS(op.sessionID, "relay.authenticateOp.idsQuery.noSuchKeyCard")
		op.err = notFoundError
		r.sendSessionOp(sessionState, op)
		return
	}
	check(err)
	logS(op.sessionID, "relay.authenticateOp.ids keyCardId=%s storeId=%s", keyCardID, storeID)

	// Ensure the device isn't already connected via another session.
	// If we find such another session, initiate a stop on it because it is probably
	// a dangling session that only the server side thinks is still alive.
	// Reject this authentication attempt from the second device, but with the stop
	// the client should be able to successfully retry shortly.
	iter := r.sessionIDsToSessionStates.Iter()

	for {
		otherSessionID, otherSessionState, ok := iter.Next()
		if !ok {
			break
		}
		if otherSessionState.keyCardID != nil && keyCardID.Equal(otherSessionState.keyCardID) {
			logS(op.sessionID, "relay.authenticateOp.alreadyConnected otherSessionId=%s", otherSessionID)
			stopOp := &StopOp{sessionID: otherSessionID}
			r.sendSessionOp(otherSessionState, stopOp)
			op.err = alreadyConnectedError
			r.sendSessionOp(sessionState, op)
			return
		}
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
	} else if sessionState.keyCardID == nil {
		logS(op.sessionID, "relay.challengeSolvedOp.invalidSessionState")
		op.err = &Error{Code: ErrorCodes_INVALID, Message: "authentication not started"}
		r.sendSessionOp(sessionState, op)
		return
	} else if sessionState.storeID != nil {
		logS(op.sessionID, "relay.challengeSolvedOp.alreadyAuthenticated")
		op.err = alreadyAuthenticatedError
		r.sendSessionOp(sessionState, op)
		return
	}

	var keyCardPublicKey []byte
	var storeID eventID

	logS(op.sessionID, "relay.challengeSolvedOp.query")
	ctx := context.Background()
	// Index: keyCards(publicKey)
	query := `select cardPublicKey, storeId from keyCards
	where id = $1 and unlinkedAt is null`
	err := r.connPool.QueryRow(ctx, query, sessionState.keyCardID).Scan(&keyCardPublicKey, &storeID)
	if err == pgx.ErrNoRows {
		logS(op.sessionID, "relay.challengeSolvedOp.query.noSuchKeyCard")
		op.err = notFoundError
		r.sendSessionOp(sessionState, op)
		return
	}
	check(err)
	logS(op.sessionID, "relay.challengeSolvedOp.ids keyCardId=%s storeId=%s", sessionState.keyCardID, storeID)

	err = r.ethClient.verifyChallengeResponse(keyCardPublicKey, sessionState.authChallenge, op.im.Signature)
	if err != nil {
		logS(op.sessionID, "relay.challengeSolvedOp.verifyFailed err=%s", err)
		op.err = notFoundError
		r.sendSessionOp(sessionState, op)
		return
	}

	// Create or update the device DB record.
	var dbUnlinkedAt *time.Time
	var dbLastAckedKCSeq uint64
	var dbLastVersion int
	var isGuestKeyCard bool
	instant := now()
	sessionState.lastSeenAt = instant
	sessionState.lastSeenAtFlushed = instant

	// Index: keyCards(id)
	query = `select unlinkedAt, lastAckedKCSeq, lastVersion, isGuest from keyCards where id = $1`
	err = r.connPool.QueryRow(ctx, query, sessionState.keyCardID).Scan(&dbUnlinkedAt, &dbLastAckedKCSeq, &dbLastVersion, &isGuestKeyCard)
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
	sessionState.lastStatusedKCSeq = dbLastAckedKCSeq
	sessionState.lastBufferedKCSeq = dbLastAckedKCSeq
	sessionState.lastPushedKCSeq = dbLastAckedKCSeq
	sessionState.lastAckedKCSeq = dbLastAckedKCSeq
	sessionState.lastAckedKCSeqFlushed = dbLastAckedKCSeq
	query = `update keyCards set lastVersion = $1, lastSeenAt = $2 where id = $3`
	_, err = r.connPool.Exec(ctx, query, sessionState.version, sessionState.lastSeenAt, sessionState.keyCardID)
	check(err)

	sessionState.storeID = storeID
	sessionState.initialStatus = false
	sessionState.nextPushIndex = 0
	sessionState.keyCardPublicKey = keyCardPublicKey

	// Establish store seq.
	r.hydrateStores(NewSetEventIDs(sessionState.storeID))
	r.hydrateKeyCards(NewSetRequestIDs(sessionState.keyCardID))
	seqPair := r.keyCardIDsToKeyCardSeqs.MustGet(sessionState.keyCardID)

	// Verify we have valid seq cursor relationships. We will check this whenever we move a cursor.
	err = r.checkCursors(op.sessionID, seqPair, sessionState)
	logS(op.sessionID, "relay.challengeSolvedOp.checkCursors lastWrittenKCSeq=%d lastUsedKCSeq=%d lastStatusedKCSeq=%d lastBufferedKCSeq=%d lastPushedKCSeq=%d lastAckedKCSeq=%d error=%t",
		seqPair.lastWrittenKCSeq, seqPair.lastUsedKCSeq, sessionState.lastStatusedKCSeq, sessionState.lastBufferedKCSeq, sessionState.lastPushedKCSeq, sessionState.lastAckedKCSeq, err != nil)
	if err != nil {
		logS(op.sessionID, "relay.challengeSolvedOp.brokenCursor err=%s", err.Error())
		op.err = notFoundError
		r.sendSessionOp(sessionState, op)
		return
	}

	// At this point we know authentication was successful and seqs validated, so indicate by removing authChallenge.
	sessionState.authChallenge = nil

	r.sendSessionOp(sessionState, op)
	logS(op.sessionID, "relay.authenticateOp.finish elapsed=%d", took(challengeSolvedOpStart))
}

// compute current store hash
//
// until we need to verify proofs this is a pretty simple merkle tree with three intermediary nodes
// 1. the manifest
// 2. all published items (TODO: other tags?)
// 3. the stock counts
func (r *Relay) storeRootHash(storeID eventID) []byte {
	start := now()
	//log("relay.storeRootHash storeId=%s", storeID)

	storeManifest, has := r.storeManifestsByStoreID.get(storeID)
	assertWithMessage(has, "no manifest for storeId")

	// 1. the manifest
	manifestHash := sha3.NewLegacyKeccak256()
	manifestHash.Write(storeManifest.storeTokenID)
	_, _ = fmt.Fprint(manifestHash, storeManifest.domain)
	manifestHash.Write(storeManifest.publishedTagID)
	//log("relay.storeRootHash manifest=%x", manifestHash.Sum(nil))

	// 2. all items in the published set
	publishedItemsHash := sha3.NewLegacyKeccak256()
	publishedTag, has := r.tagsByTagID.get(storeManifest.publishedTagID)
	if has {
		// iterating over sets is randomized in Go, sort them for consistency
		publishedItemIds := publishedTag.items.Slice()
		sort.Sort(publishedItemIds)

		for _, itemID := range publishedItemIds {
			item, has := r.itemsByItemID.get(itemID)
			assertWithMessage(has, fmt.Sprintf("failed to load published itemId=%s", itemID))
			publishedItemsHash.Write(item.itemID)
		}
		//log("relay.storeRootHash published=%x", publishedItemsHash.Sum(nil))
	}

	// TODO: other tags

	// 3. the stock
	stockHash := sha3.NewLegacyKeccak256()
	stock, has := r.stockByStoreID.get(storeID)
	//assertWithMessage(has, "stock unavailable")
	if has {
		// TODO: we should probably always have a stock that's just empty
		//log("relay.storeRootHash.hasStock storeId=%s", storeID)
		// see above
		stockIds := stock.inventory.Keys()
		sort.Sort(stockIds)

		for _, id := range stockIds {
			count := stock.inventory.MustGet(id)
			stockHash.Write(id)
			_, _ = fmt.Fprintf(stockHash, "%d", count)
		}
	}
	//log("relay.storeRootHash stock=%x", stockHash.Sum(nil))

	// final root hash of the three nodes
	rootHash := sha3.NewLegacyKeccak256()
	rootHash.Write(manifestHash.Sum(nil))
	rootHash.Write(publishedItemsHash.Sum(nil))
	rootHash.Write(stockHash.Sum(nil))

	digest := rootHash.Sum(nil)
	took := took(start)
	log("relay.storeRootHash.hash store=%s digest=%x took=%d", storeID, digest, took)
	r.metric.counterAdd("storeRootHash_took", float64(took))
	return digest
}

func (op *EventWriteOp) process(r *Relay) {
	sessionID := op.sessionID
	requestID := op.im.RequestId
	sessionState := r.sessionIDsToSessionStates.Get(sessionID)
	if sessionState == nil {
		logSR("relay.eventWriteOp.drain", sessionID, requestID)
		return
	} else if sessionState.keyCardID == nil {
		logSR("relay.eventWriteOp.notAuthenticated", sessionID, requestID)
		op.err = notAuthenticatedError
		r.sendSessionOp(sessionState, op)
		return
	}
	logSR("relay.eventWriteOp.process", sessionID, requestID)
	r.lastSeenAtTouch(sessionState)

	// check signature
	if err := r.ethClient.eventVerify(op.decodedStoreEvt, sessionState.keyCardPublicKey); err != nil {
		logSR("relay.eventWriteOp.verifyEventFailed err=%s", sessionID, requestID, err.Error())
		op.err = &Error{Code: ErrorCodes_INVALID, Message: "invalid signature"}
		r.sendSessionOp(sessionState, op)
		return
	}

	meta := newMetadata(sessionState.keyCardID, sessionState.storeID, uint16(sessionState.version))
	if err := r.checkStoreEventWriteConsistency(op.decodedStoreEvt, meta, sessionState); err != nil {
		logSR("relay.eventWriteOp.checkEventFailed code=%s msg=%s", sessionID, requestID, err.Code, err.Message)
		op.err = err
		r.sendSessionOp(sessionState, op)
		return
	}

	// update store
	r.beginSyncTransaction()
	r.writeEvent(op.decodedStoreEvt, meta, op.im.Event)
	r.commitSyncTransaction()

	// compute resulting hash
	storeSeq := r.storeIdsToStoreState.MustGet(sessionState.storeID)
	if storeSeq.lastUsedStoreSeq >= 3 {
		hash := r.storeRootHash(sessionState.storeID)
		op.newStoreHash = hash
	}
	op.eventSeq = storeSeq.lastWrittenStoreSeq

	r.sendSessionOp(sessionState, op)
}

func (r *Relay) checkStoreEventWriteConsistency(union *StoreEvent, m CachedMetadata, sess *SessionState) *Error {
	manifest, storeExists := r.storeManifestsByStoreID.get(m.createdByStoreID)
	storeManifestExists := storeExists && len(manifest.storeTokenID) > 0

	switch tv := union.Union.(type) {

	case *StoreEvent_StoreManifest:
		if sess.keyCardOfAGuest {
			return notFoundError
		}
		if storeManifestExists {
			return &Error{Code: ErrorCodes_INVALID, Message: "store already exists"}
		}

	case *StoreEvent_UpdateStoreManifest:
		if !storeManifestExists {
			return notFoundError
		}
		if sess.keyCardOfAGuest {
			return notFoundError
		}
		// this feels like a pre-op validation step but we dont have access to the relay there
		if addr := tv.UpdateStoreManifest.AddErc20Addr; len(addr) > 0 {
			callOpts := &bind.CallOpts{
				Pending: false,
				From:    r.ethClient.wallet,
				Context: context.Background(),
			}

			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			gethClient, err := r.ethClient.getClient(ctx)
			if err != nil {
				log("relay.validateWrite.failedToGetClient err=%s", err)
				return &Error{Code: ErrorCodes_INVALID, Message: "internal server error"}
			}
			defer gethClient.Close()

			tokenCaller, err := NewERC20Caller(common.Address(addr), gethClient)
			if err != nil {
				log("relay.validateWrite.newERC20Caller err=%s", err)
				return &Error{Code: ErrorCodes_INVALID, Message: "failed to create token caller"}
			}
			decimalCount, err := tokenCaller.Decimals(callOpts)
			if err != nil {
				return &Error{Code: ErrorCodes_INVALID, Message: fmt.Sprintf("failed to get token decimals: %s", err)}
			}
			if decimalCount < 1 || decimalCount > 18 {
				return &Error{Code: ErrorCodes_INVALID, Message: "invalid token decimals"}
			}
			symbol, err := tokenCaller.Symbol(callOpts)
			if err != nil {
				return &Error{Code: ErrorCodes_INVALID, Message: fmt.Sprintf("failed to get token symbol: %s", err)}
			}
			if symbol == "" {
				return &Error{Code: ErrorCodes_INVALID, Message: "invalid token symbol"}
			}
			tokenName, err := tokenCaller.Name(callOpts)
			if err != nil {
				return &Error{Code: ErrorCodes_INVALID, Message: fmt.Sprintf("failed to get token name: %s", err)}
			}
			if tokenName == "" {
				return &Error{Code: ErrorCodes_INVALID, Message: "invalid token name"}
			}
		}
	case *StoreEvent_CreateItem:
		if !storeManifestExists || sess.keyCardOfAGuest {
			return notFoundError
		}
		evt := union.GetCreateItem()
		_, itemExists := r.itemsByItemID.get(evt.EventId)
		if itemExists {
			return &Error{Code: ErrorCodes_INVALID, Message: "item already exists"}
		}

	case *StoreEvent_UpdateItem:
		if !storeManifestExists || sess.keyCardOfAGuest {
			return notFoundError
		}
		evt := union.GetUpdateItem()
		item, itemExists := r.itemsByItemID.get(evt.ItemId)
		if !itemExists {
			return notFoundError
		}
		if !item.createdByStoreID.Equal(sess.storeID) { // not allow to alter data from other store
			return notFoundError
		}

	case *StoreEvent_CreateTag:
		if !storeManifestExists || sess.keyCardOfAGuest {
			return notFoundError
		}
		evt := union.GetCreateTag()
		_, tagExists := r.tagsByTagID.get(evt.EventId)
		if tagExists {
			return &Error{Code: ErrorCodes_INVALID, Message: "tag already exists"}
		}

	case *StoreEvent_UpdateTag:
		if !storeManifestExists || sess.keyCardOfAGuest {
			return notFoundError
		}
		evt := union.GetUpdateTag()
		tag, tagExists := r.tagsByTagID.get(evt.TagId)
		if !tagExists {
			return notFoundError
		}
		if !tag.createdByStoreID.Equal(sess.storeID) { // not allow to alter data from other stores
			return notFoundError
		}
		if id := evt.AddItemId; len(id) > 0 {
			item, itemExists := r.itemsByItemID.get(id)
			if !itemExists {
				return notFoundError
			}
			if !item.createdByStoreID.Equal(sess.storeID) { // not allow to alter data from other stores
				return notFoundError
			}
		}
		if id := evt.RemoveItemId; len(id) > 0 {
			item, itemExists := r.itemsByItemID.get(id)
			if !itemExists {
				return notFoundError
			}
			if !item.createdByStoreID.Equal(sess.storeID) { // not allow to alter data from other stores
				return notFoundError
			}
		}
		if d := evt.Delete; d != nil && *d == false {
			return &Error{Code: ErrorCodes_INVALID, Message: "Can't undelete a tag"}
		}

	case *StoreEvent_ChangeStock:
		if !storeManifestExists || sess.keyCardOfAGuest {
			return notFoundError
		}
		evt := union.GetChangeStock()
		for i := 0; i < len(evt.ItemIds); i++ {
			itemID := evt.ItemIds[i]
			change := evt.Diffs[i]
			item, itemExists := r.itemsByItemID.get(itemID)
			if !itemExists {
				return notFoundError
			}
			if !item.createdByStoreID.Equal(sess.storeID) { // not allow to alter data from other stores
				return notFoundError
			}
			storeStock, storeStockExists := r.stockByStoreID.get(m.createdByStoreID)
			if storeStockExists {
				items, has := storeStock.inventory.GetHas(itemID)
				if has && items+change < 0 {
					return &Error{Code: ErrorCodes_OUT_OF_STOCK, Message: "not enough stock"}
				}
			}
		}

	case *StoreEvent_CreateOrder:
		if !storeManifestExists {
			return notFoundError
		}
		evt := union.GetCreateOrder()
		_, orderExists := r.ordersByOrderID.get(evt.EventId)
		if orderExists {
			return &Error{Code: ErrorCodes_INVALID, Message: "order already exists"}
		}

	case *StoreEvent_UpdateOrder:
		if !storeManifestExists {
			return notFoundError
		}
		evt := union.GetUpdateOrder()
		order, orderExists := r.ordersByOrderID.get(evt.OrderId)
		if !orderExists {
			return notFoundError
		}
		if !order.createdByStoreID.Equal(sess.storeID) { // not allow to alter data from other stores
			return notFoundError
		}
		if sess.keyCardOfAGuest && !r.doesSessionOwnEvent(sess, evt.OrderId) {
			return notFoundError
		}
		switch tv := evt.Action.(type) {
		case *UpdateOrder_ChangeItems_:
			if order.finalized {
				return &Error{Code: ErrorCodes_INVALID, Message: "order already finalized"}
			}
			change := tv.ChangeItems
			item, itemExists := r.itemsByItemID.get(change.ItemId)
			if !itemExists {
				return notFoundError
			}
			if !item.createdByStoreID.Equal(sess.storeID) { // not allow to alter data from other stores
				return notFoundError
			}
			stock, has := r.stockByStoreID.get(m.createdByStoreID)
			if !has {
				return &Error{Code: ErrorCodes_INVALID, Message: "not enough stock"}
			}
			inStock, has := stock.inventory.GetHas(change.ItemId)
			if !has || inStock < change.Quantity {
				return &Error{Code: ErrorCodes_INVALID, Message: "not enough stock"}
			}
			inOrder := order.items.Get(change.ItemId)
			if change.Quantity < 0 && inOrder+change.Quantity < 0 {
				return &Error{Code: ErrorCodes_INVALID, Message: "not enough items in order"}
			}
		case *UpdateOrder_OrderCanceled_:
			if !order.finalized {
				return &Error{Code: ErrorCodes_INVALID, Message: "order is not finalized"}
			}
		}

	default:
		panic(fmt.Errorf("eventWritesOp.validateWrite.unrecognizeType eventType=%T", union.Union))
	}
	return nil
}

func (op *EventPushOp) process(r *Relay) {
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

const DefaultPaymentTTL = 60 * 60 * 24

func (op *CommitItemsToOrderOp) process(r *Relay) {
	ctx := context.Background()
	sessionID := op.sessionID
	requestID := op.im.RequestId
	sessionState := r.sessionIDsToSessionStates.Get(sessionID)
	if sessionState == nil {
		logS(sessionID, "relay.commitOrderOp.drain")
		return
	} else if sessionState.keyCardID == nil {
		logSR("relay.commitOrderOp.notAuthenticated", sessionID, requestID)
		op.err = notAuthenticatedError
		r.sendSessionOp(sessionState, op)
		return
	}
	start := now()
	logSR("relay.commitOrderOp.process", sessionID, requestID)
	r.lastSeenAtTouch(sessionState)

	// sum up order content
	decimalCtx := apd.BaseContext.WithPrecision(20)
	fiatSubtotal := new(apd.Decimal)
	order, has := r.ordersByOrderID.get(op.im.OrderId)
	if !has {
		op.err = notFoundError
		r.sendSessionOp(sessionState, op)
		return
	}
	// check ownership of the cart if it is a guest
	if sessionState.keyCardOfAGuest {
		if !r.doesSessionOwnEvent(sessionState, op.im.OrderId) {
			op.err = notFoundError
			r.sendSessionOp(sessionState, op)
			return
		}
	}
	if order.finalized {
		op.err = &Error{Code: ErrorCodes_INVALID, Message: "order is already finalized"}
		r.sendSessionOp(sessionState, op)
		return
	}
	if order.items.Size() == 0 {
		op.err = &Error{Code: ErrorCodes_INVALID, Message: "order is empty"}
		r.sendSessionOp(sessionState, op)
		return
	}

	stock, has := r.stockByStoreID.get(sessionState.storeID)
	if !has {
		op.err = &Error{Code: ErrorCodes_INVALID, Message: "not enough stock"}
		r.sendSessionOp(sessionState, op)
		return
	}

	store, has := r.storeManifestsByStoreID.get(sessionState.storeID)
	if !has {
		op.err = &Error{Code: ErrorCodes_INVALID, Message: "store not found"}
		r.sendSessionOp(sessionState, op)
		return
	}

	// get all other orders that haven't been paid yet
	otherOrderRows, err := r.connPool.Query(ctx, `select orderId from payments where
	createdByStoreId = $1 and
	orderId != $2 and
	orderPayedAt is null`, sessionState.storeID, op.im.OrderId)
	check(err)
	defer otherOrderRows.Close()

	otherOrderIds := NewMapEventIDs[*CachedOrder]()
	for otherOrderRows.Next() {
		var otherOrderID eventID
		check(otherOrderRows.Scan(&otherOrderID))
		otherOrder, has := r.ordersByOrderID.get(otherOrderID)
		assert(has)
		otherOrderIds.Set(otherOrderID, otherOrder)
	}
	check(otherOrderRows.Err())

	// for convenience, sum up all items in the  other orders
	otherOrderItemQuantities := NewMapEventIDs[int32]()
	otherOrderIds.AllWithBreak(func(_ eventID, order *CachedOrder) bool {
		if order.abandoned {
			return false
		}
		order.items.AllWithBreak(func(itemId eventID, quantity int32) bool {
			current := otherOrderItemQuantities.Get(itemId)
			current += quantity
			otherOrderItemQuantities.Set(itemId, current)
			return false
		})
		return false
	})

	// iterate over this order
	order.items.AllWithBreak(func(itemId eventID, quantity int32) bool {
		item, has := r.itemsByItemID.get(itemId)
		if !has {
			op.err = notFoundError
			return true
		}

		if !item.createdByStoreID.Equal(sessionState.storeID) { // not allow to alter data from other stores
			op.err = notFoundError
			return true
		}

		stockItems, has := stock.inventory.GetHas(itemId)
		if !has {
			op.err = &Error{Code: ErrorCodes_OUT_OF_STOCK, Message: "not enough stock"}
			return true
		}

		usedInOtherOrders := otherOrderItemQuantities.Get(itemId)
		if stockItems-usedInOtherOrders < quantity {
			op.err = &Error{Code: ErrorCodes_OUT_OF_STOCK, Message: "not enough stock"}
			return true
		}

		decQuantityt := apd.New(int64(quantity), 0)

		// total += quantity * price
		quantTimesPrice := new(apd.Decimal)
		_, err = decimalCtx.Mul(quantTimesPrice, decQuantityt, item.price)
		check(err)
		_, err = decimalCtx.Add(fiatSubtotal, fiatSubtotal, quantTimesPrice)
		check(err)
		return false
	})
	if op.err != nil {
		r.sendSessionOp(sessionState, op)
		return
	}

	// calcualte taxes
	// TODO: parameterize tax rate
	salesTaxRate, _, err := apd.NewFromString("0.05")
	check(err)

	salesTax := new(apd.Decimal)
	_, err = decimalCtx.Mul(salesTax, fiatSubtotal, salesTaxRate)
	check(err)

	fiatTotal := new(apd.Decimal)
	_, err = decimalCtx.Add(fiatTotal, fiatSubtotal, salesTax)
	check(err)

	// create payment address for order content
	var (
		bigTotal = new(big.Int)

		receiptHash [32]byte

		usignErc20     = len(op.im.Erc20Addr) == 20
		erc20TokenAddr common.Address
	)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	gethClient, err := r.ethClient.getClient(ctx)
	if err != nil {
		logSR("relay.commitOrderOp.failedToGetGethClient err=%s", sessionID, requestID, err.Error())
		op.err = &Error{Code: ErrorCodes_INVALID, Message: "internal server error"}
		r.sendSessionOp(sessionState, op)
		return
	}
	defer gethClient.Close()

	callOpts := &bind.CallOpts{
		Pending: false,
		From:    r.ethClient.wallet,
		Context: context.Background(),
	}

	inBaseTokens := new(apd.Decimal)
	if usignErc20 {
		erc20TokenAddr = common.Address(op.im.Erc20Addr)
		var has bool
		_, has = store.acceptedErc20s[erc20TokenAddr]
		if !has {
			logSR("relay.commitOrderOp.noSuchAcceptedErc20s addr=%s", sessionID, requestID, erc20TokenAddr.Hex())
			op.err = &Error{Code: ErrorCodes_INVALID, Message: "erc20 not accepted"}
			r.sendSessionOp(sessionState, op)
			return
		}
		inErc20 := r.prices.FromFiatToERC20(fiatTotal, erc20TokenAddr)

		// get decimals count of this contract
		// TODO: since this is a contract constant we could cache it when adding the token
		tokenCaller, err := NewERC20Caller(erc20TokenAddr, gethClient)
		if err != nil {
			logSR("relay.commitOrderOp.failedToCreateERC20Caller err=%s", sessionID, requestID, err.Error())
			op.err = &Error{Code: ErrorCodes_INVALID, Message: "failed to create erc20 caller"}
			r.sendSessionOp(sessionState, op)
			return
		}
		decimalCount, err := tokenCaller.Decimals(callOpts)
		if err != nil {
			logSR("relay.commitOrderOp.erc20DecimalsFailed err=%s", sessionID, requestID, err.Error())
			op.err = &Error{Code: ErrorCodes_INVALID, Message: "failed to establish contract decimals"}
			r.sendSessionOp(sessionState, op)
			return
		}

		_, err = decimalCtx.Mul(inBaseTokens, inErc20, apd.New(1, int32(decimalCount)))
		check(err)
	} else {
		// convert decimal in USD to ethereum
		inEth := r.prices.FromFiatToCoin(fiatTotal)
		_, err = decimalCtx.Mul(inBaseTokens, inEth, apd.New(1, 18))
		check(err)
	}

	bigTotal.SetString(inBaseTokens.Text('f'), 10)

	// TODO: actual proof. for now we just use the hash of the internal orderId as a nonce
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(order.orderID)
	copy(receiptHash[:], hasher.Sum(nil))

	bigStoreTokenID := new(big.Int).SetBytes(store.storeTokenID)

	// owner
	storeReg, err := NewRegStoreCaller(r.ethClient.contractAddresses.StoreRegistry, gethClient)
	if err != nil {
		logSR("relay.commitOrderOp.erc20DecimalsFailed err=%s", sessionID, requestID, err.Error())
		op.err = &Error{Code: ErrorCodes_INVALID, Message: "failed to create store registry caller"}
		r.sendSessionOp(sessionState, op)
		return
	}

	ownerAddr, err := storeReg.OwnerOf(callOpts, bigStoreTokenID)
	if err != nil {
		logSR("relay.commitOrderOp.erc20DecimalsFailed err=%s", sessionID, requestID, err.Error())
		op.err = &Error{Code: ErrorCodes_INVALID, Message: "failed to get store owner"}
		r.sendSessionOp(sessionState, op)
		return
	}

	// ttl
	blockNo, err := gethClient.BlockNumber(ctx)
	if err != nil {
		op.err = &Error{Code: ErrorCodes_INVALID, Message: "failed to get block number"}
		r.sendSessionOp(sessionState, op)
		return
	}

	block, err := gethClient.BlockByNumber(ctx, new(big.Int).SetInt64(int64(blockNo)))
	if err != nil {
		op.err = &Error{Code: ErrorCodes_INVALID, Message: "failed to get block number"}
		r.sendSessionOp(sessionState, op)
		return
	}

	// if there is an escrow address use it for payee
	payeeAddress := ownerAddr
	isEndpoint := false
	/* TODO: configure payout endpoint
	isEndpoint := ea != nil
		if isEndpoint {
			isEndpoint = true
		    payeeAddress = common.Address(ea)
		}
	*/

	var pr = PaymentRequest{}
	pr.ChainId = new(big.Int).SetInt64(int64(r.ethClient.chainID))
	pr.Ttl = new(big.Int).SetUint64(block.Time() + DefaultPaymentTTL)
	pr.Order = receiptHash
	pr.Currency = erc20TokenAddr
	pr.Amount = bigTotal
	pr.PayeeAddress = payeeAddress
	pr.IsPaymentEndpoint = isEndpoint
	pr.ShopId = bigStoreTokenID
	// TODO: calculate signature
	pr.ShopSignature = bytes.Repeat([]byte{0}, 64)

	// get paymentId and create fallback address
	paymentsContract, err := NewPaymentsByAddressCaller(r.ethClient.contractAddresses.Payments, gethClient)
	if err != nil {
		logSR("relay.commitCartOp.newPaymentsByAddressFailed err=%s", sessionID, requestID, err.Error())
		op.err = &Error{Code: ErrorCodes_INVALID, Message: "contract interaction error"}
		r.sendSessionOp(sessionState, op)
		return
	}

	paymentId, err := paymentsContract.GetPaymentId(callOpts, pr)
	if err != nil {
		logSR("relay.commitCartOp.getPaymentIdFailed err=%s", sessionID, requestID, err.Error())
		op.err = &Error{Code: ErrorCodes_INVALID, Message: "failed to paymentId"}
		r.sendSessionOp(sessionState, op)
		return
	}

	purchaseAddr, err := paymentsContract.GetPaymentAddress(callOpts, pr, ownerAddr)
	if err != nil {
		op.err = &Error{Code: ErrorCodes_INVALID, Message: "failed to create payment address"}
		r.sendSessionOp(sessionState, op)
		return
	}

	log("relay.commitCartOp.paymentRequest id=%s addr=%x total=%s currentBlock=%d", paymentId.Text(16), purchaseAddr, bigTotal.String(), blockNo)

	// mark order as finalized by creating the event and updating payments table
	var (
		fin UpdateOrder_ItemsFinalized
		w   PaymentWaiter
	)
	fin.PaymentId = paymentId.Bytes()

	fin.SubTotal = roundPrice(fiatSubtotal).Text('f')
	fin.SalesTax = roundPrice(salesTax).Text('f')
	fin.Total = roundPrice(fiatTotal).Text('f')

	fin.Ttl = pr.Ttl.String()
	fin.OrderHash = receiptHash[:]
	fin.CurrencyAddr = erc20TokenAddr[:]
	fin.TotalInCrypto = bigTotal.String()
	fin.PayeeAddr = payeeAddress[:]
	fin.IsPaymentEndpoint = isEndpoint
	fin.ShopSignature = pr.ShopSignature

	update := &UpdateOrder{
		EventId: newEventID(),
		OrderId: order.orderID,
		Action:  &UpdateOrder_ItemsFinalized_{&fin},
	}

	op.orderFinalizedID = update.EventId

	w.waiterID = newRequestID()
	w.orderID = op.im.OrderId
	w.orderFinalizedAt = now()
	w.purchaseAddr = purchaseAddr
	w.lastBlockNo.SetInt64(int64(blockNo))
	w.coinsTotal.Set(bigTotal)
	w.coinsPayed.SetInt64(0)
	w.paymentId = SQLStringBigInt{*paymentId}

	if usignErc20 {
		w.erc20TokenAddr = &erc20TokenAddr
	}

	cfMetadata := newMetadata(relayKeyCardID, sessionState.storeID, currentRelayVersion)
	cfEvent := &StoreEvent{Union: &StoreEvent_UpdateOrder{update}}

	err = r.ethClient.eventSign(cfEvent)
	if err != nil {
		logSR("relay.commitOrderOp.eventSignFailed err=%s", sessionID, requestID, err)
		op.err = &Error{Code: ErrorCodes_INVALID, Message: "interal server error"}
		r.sendSessionOp(sessionState, op)
		return
	}

	cfAny, err := anypb.New(cfEvent)
	if err != nil {
		logSR("relay.commitOrderOp.anypb err=%s", sessionID, requestID, err)
		op.err = &Error{Code: ErrorCodes_INVALID, Message: "interal server error"}
		r.sendSessionOp(sessionState, op)
		return
	}

	r.beginSyncTransaction()
	r.writeEvent(cfEvent, cfMetadata, cfAny)

	seqPair := r.storeIdsToStoreState.MustGet(sessionState.storeID)
	const insertPaymentWaiterQuery = `insert into payments (waiterId, storeSeqNo, createdByStoreId, orderId, orderFinalizedAt, purchaseAddr, lastBlockNo, coinsPayed, coinsTotal, erc20TokenAddr, paymentId)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`
	_, err = r.syncTx.Exec(ctx, insertPaymentWaiterQuery,
		w.waiterID, seqPair.lastUsedStoreSeq, order.createdByStoreID, w.orderID, w.orderFinalizedAt, w.purchaseAddr.Bytes(), w.lastBlockNo, w.coinsPayed, w.coinsTotal, w.erc20TokenAddr, w.paymentId.Bytes())
	check(err)

	r.commitSyncTransaction()

	op.orderFinalizedID = update.EventId

	logSR("relay.commitOrderOp.finish took=%d", sessionID, requestID, took(start))
	r.sendSessionOp(sessionState, op)
}

var (
	blobUplodBaseURL         *url.URL
	initblobUplodBaseURLOnce sync.Once
)

func initblobUplodBaseURL() {
	var err error
	blobUplodBaseURL, err = url.Parse(mustGetEnvString("BLOB_UPLOAD_ENDPOINT"))
	check(err)
}

func (op *GetBlobUploadURLOp) process(r *Relay) {
	initblobUplodBaseURLOnce.Do(initblobUplodBaseURL)
	sessionID := op.sessionID
	requestID := op.im.RequestId
	sessionState := r.sessionIDsToSessionStates.Get(sessionID)
	if sessionState == nil {
		logS(sessionID, "relay.getBlobUploadURLOp.drain")
		return
	} else if sessionState.keyCardID == nil {
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

	var uploadURL url.URL
	uploadURL = *blobUplodBaseURL
	uploadURL.Path = fmt.Sprintf("/v%d/upload_blob", currentRelayVersion)
	uploadURL.RawQuery = "token=" + token
	op.uploadURL = &uploadURL

	r.sendSessionOp(sessionState, op)
	logSR("relay.getBlobUploadURLOp.finish token=%s took=%d", sessionID, requestID, token, took(start))

}

// Internal ops

func (op *KeyCardEnrolledInternalOp) getSessionID() requestID { panic("not implemented") }
func (op *KeyCardEnrolledInternalOp) setErr(_ *Error)         { panic("not implemented") }

func (op *KeyCardEnrolledInternalOp) process(r *Relay) {
	log("db.KeyCardEnrolledOp.start storeId=%s", op.storeID)
	start := now()

	r.hydrateStores(NewSetEventIDs(op.storeID))

	ctx := context.Background()
	r.beginSyncTransaction()

	// get other keycards for public key
	const previousKeyCardsQuery = `select id from keyCards where userWalletAddr = $1 and id != $2 and storeId = $3`
	prevRows, err := r.syncTx.Query(ctx, previousKeyCardsQuery, op.userWallet, op.keyCardDatabaseID, op.storeID)
	check(err)
	defer prevRows.Close()

	sameUserKeyCards := NewSetRequestIDs()
	for prevRows.Next() {
		var kcId requestID
		err = prevRows.Scan(&kcId)
		check(err)

		sameUserKeyCards.Add(kcId)
	}
	check(prevRows.Err())

	// replay previous store history
	const existingStoreEventsQuery = `select eventType, storeSeq, createdByKeyCardId
from events
where createdByStoreId = $1
order by storeSeq`
	evtRows, err := r.connPool.Query(ctx, existingStoreEventsQuery, op.storeID)
	check(err)
	// TODO: check for missing closes
	defer evtRows.Close()

	var kcEvents []KeyCardEvent
	kcSeqs := r.keyCardIDsToKeyCardSeqs.GetOrCreate(op.keyCardDatabaseID, func(_ requestID) *SeqPairKeyCard { return &SeqPairKeyCard{} })
	for evtRows.Next() {
		var (
			kcEvt              KeyCardEvent
			eventType          eventType
			createdByKeyCardID requestID
		)
		err = evtRows.Scan(&eventType, &kcEvt.eventStoreSeq, &createdByKeyCardID)
		check(err)

		switch eventType {
		// staff + that customer
		case eventTypeNewKeyCard:
			fallthrough
		case eventTypeChangeStock:
			fallthrough
		case eventTypeCreateOrder:
			fallthrough
		case eventTypeUpdateOrder:
			isFromRelay := bytes.Equal(createdByKeyCardID, relayKeyCardID)

			// if its a guest, they get an event if its from one of their previous keycards,
			// or if it's a keycard from a clerk
			if op.keyCardIsGuest && !(sameUserKeyCards.Has(createdByKeyCardID) || (eventType == eventTypeNewKeyCard && isFromRelay)) {

				log("createKeyCardLog type=%s isFromClerk=%v", eventType, isFromRelay)
				continue // skip events for other users
			}

			// all other event types are public
		}

		kcEvt.keyCardId = op.keyCardDatabaseID
		kcEvt.keyCardSeq = kcSeqs.lastWrittenKCSeq + 1
		kcSeqs.lastUsedKCSeq = kcEvt.keyCardSeq
		kcSeqs.lastWrittenKCSeq = kcEvt.keyCardSeq

		kcEvents = append(kcEvents, kcEvt)
	}
	check(evtRows.Err())

	if evtCount := len(kcEvents); evtCount > 0 {
		keyCardEventRows := make([][]any, evtCount)
		for i, ue := range kcEvents {
			keyCardEventRows[i] = []interface{}{ue.keyCardId, ue.keyCardSeq, ue.eventStoreSeq}
		}
		insertedRows, _ := r.bulkInsert("keyCardEvents", []string{"keyCardId", "keyCardSeq", "eventStoreSeq"}, keyCardEventRows)
		assertWithMessage(len(insertedRows) == len(kcEvents), "new keycard log isnt empty")
	}

	// emit new keycard event
	evt := &StoreEvent{
		Union: &StoreEvent_NewKeyCard{NewKeyCard: &NewKeyCard{
			EventId:        newEventID(),
			CardPublicKey:  op.keyCardPublicKey,
			UserWalletAddr: op.userWallet[:],
		}},
	}

	err = r.ethClient.eventSign(evt)
	check(err)

	anyEvt, err := anypb.New(evt)
	check(err)

	meta := newMetadata(relayKeyCardID, op.storeID, currentRelayVersion)
	r.writeEvent(evt, meta, anyEvt)

	r.commitSyncTransaction()
	log("db.KeyCardEnrolledOp.finish storeId=%s took=%d", op.storeID, took(start))
}

func (op *PaymentFoundInternalOp) getSessionID() requestID { panic("not implemented") }
func (op *PaymentFoundInternalOp) setErr(_ *Error)         { panic("not implemented") }

func (op *PaymentFoundInternalOp) process(r *Relay) {
	order, has := r.ordersByOrderID.get(op.orderID)
	assertWithMessage(has, fmt.Sprintf("order not found for orderId=%s", op.orderID))

	log("db.paymentFoundInternalOp.start orderID=%s", op.orderID)
	start := now()

	r.beginSyncTransaction()

	const markOrderAsPayedQuery = `UPDATE payments SET orderPayedAt = NOW(), orderPayedTx = $1 WHERE orderId = $2;`
	_, err := r.syncTx.Exec(context.Background(), markOrderAsPayedQuery, op.txHash.Bytes(), op.orderID)
	check(err)

	meta := CachedMetadata{
		createdByKeyCardID:      relayKeyCardID,
		createdByStoreID:        order.createdByStoreID,
		createdByNetworkVersion: currentRelayVersion,
	}
	r.hydrateStores(NewSetEventIDs(order.createdByStoreID))
	// emit changeStock event
	cs := &ChangeStock{
		EventId: newEventID(),
		OrderId: op.orderID,
		TxHash:  op.txHash.Bytes(),
	}

	// fill diff
	i := 0
	cs.ItemIds = make([][]byte, order.items.Size())
	cs.Diffs = make([]int32, order.items.Size())
	order.items.All(func(itemId eventID, quantity int32) {
		cs.ItemIds[i] = itemId
		cs.Diffs[i] = -quantity
		i++
	})

	evt := &StoreEvent{Union: &StoreEvent_ChangeStock{ChangeStock: cs}}

	err = r.ethClient.eventSign(evt)
	check(err) // fatal code error

	evtAny, err := anypb.New(evt)
	check(err) // fatal code error

	r.writeEvent(evt, meta, evtAny)
	r.commitSyncTransaction()
	log("db.paymentFoundInternalOp.finish orderID=%s took=%d", op.orderID, took(start))
	close(op.done)
}

// Database processing

func (r *Relay) debounceSessions() {
	// Process each session.
	// Only log if there is substantial activity because this is polling constantly and usually a no-op.
	start := now()
	ctx := context.Background()

	r.sessionIDsToSessionStates.All(func(sessionId requestID, sessionState *SessionState) {
		// Kick the session if we haven't received any recent messages from it, including ping responses.
		if time.Since(sessionState.lastSeenAt) > sessionKickTimeout {
			r.metric.emit("sessions.kick", 1)
			logS(sessionId, "relay.debounceSessions.kick")
			op := &StopOp{sessionID: sessionId}
			r.sendSessionOp(sessionState, op)
			return
		}

		// Don't try to do anything else if the session isn't even authenticated yet.
		if sessionState.storeID == nil {
			return
		}

		// If the session is authenticated, we can get user info.
		seqPair := r.keyCardIDsToKeyCardSeqs.MustGet(sessionState.keyCardID)
		r.assertCursors(sessionId, seqPair, sessionState)

		// Calculate the new user seq up to which the device has acked all pushes.
		// Slice the buffer to drop such entries as they have completed their lifecycle.
		// Do this all first to trim down the buffer before reading more, if possible.
		var (
			advancedFrom uint64
			advancedTo   uint64
			i            = 0
		)
		for ; i < len(sessionState.buffer); i++ {
			entryState := sessionState.buffer[i]
			if !entryState.acked {
				break
			}
			assert(entryState.kcSeq > sessionState.lastAckedKCSeq)
			if i == 0 {
				advancedFrom = sessionState.lastAckedKCSeq
			}
			sessionState.lastAckedKCSeq = entryState.kcSeq
			advancedTo = entryState.kcSeq
		}
		if i != 0 {
			sessionState.buffer = sessionState.buffer[i:]
			sessionState.nextPushIndex -= i
			logS(sessionId, "relay.debounceSessions.advanceStoreSeq reason=entries from=%d to=%d", advancedFrom, advancedTo)
		}
		r.assertCursors(sessionId, seqPair, sessionState)

		// Check if a sync status is needed, and if so query and send it.
		// Use the boolean to ensure we always send an initial sync status for the session,
		// including if the user has no writes yet.
		// If everything for the device has been pushed, advance the buffered and pushed cursors too.
		if !sessionState.initialStatus || sessionState.lastStatusedKCSeq < seqPair.lastWrittenKCSeq {
			syncStatusStart := now()
			op := &SyncStatusOp{sessionID: sessionId}
			// Index: keyCardEvents(keyCardId, keyCardSeq) -> events(createdByStoreId, storeSeq)
			// TODO: fix count (see test.sql)
			query := `select count(*) from keyCardEvents kce, events e
where e.createdByStoreId = $1
  and kce.eventStoreSeq = e.storeSeq
  and kce.keyCardSeq > $2
  and kce.keyCardId != $3`
			err := r.connPool.QueryRow(ctx, query, sessionState.storeID, sessionState.lastPushedKCSeq, sessionState.keyCardID).
				Scan(&op.unpushedEvents)
			if err != pgx.ErrNoRows {
				check(err)
			}
			r.sendSessionOp(sessionState, op)
			sessionState.initialStatus = true
			sessionState.lastStatusedKCSeq = seqPair.lastWrittenKCSeq
			if op.unpushedEvents == 0 {
				sessionState.lastBufferedKCSeq = sessionState.lastStatusedKCSeq
				sessionState.lastPushedKCSeq = sessionState.lastStatusedKCSeq
			}
			// TODO: maybe we should consider making this log line dynamic and just print the types where it's >0 ?
			logS(sessionId, "relay.debounceSessions.syncStatus initialStatus=%t unpushedEvents=%d elapsed=%d", sessionState.initialStatus, op.unpushedEvents, took(syncStatusStart))
		}
		r.assertCursors(sessionId, seqPair, sessionState)

		// Check if more buffering is needed, and if so fill buffer.
		writesNotBuffered := sessionState.lastBufferedKCSeq < seqPair.lastWrittenKCSeq
		var readsAllowed int
		if len(sessionState.buffer) >= sessionBufferSizeRefill {
			readsAllowed = 0
		} else {
			readsAllowed = sessionBufferSizeMax - len(sessionState.buffer)
		}
		if writesNotBuffered && readsAllowed > 0 {
			readStart := now()
			reads := 0
			// Index: events(storeId, storeSeq)
			query := `select kce.keycardseq, e.storeSeq, e.eventId, e.createdByKeyCardId, e.createdByStoreId, e.createdAt, e.encoded
from events e, keyCardEvents kce
where kce.keyCardSeq > $2
    and kce.eventStoreSeq = e.storeSeq
    and kce.keyCardId = $3
	and e.createdByKeyCardId != $3
    and e.createdByStoreId = $1
order by kce.keyCardSeq asc limit $4`
			rows, err := r.connPool.Query(ctx, query, sessionState.storeID, sessionState.lastPushedKCSeq, sessionState.keyCardID, readsAllowed)
			check(err)
			defer rows.Close()
			for rows.Next() {
				var (
					eventState = &EventState{}
					encoded    []byte
				)
				err := rows.Scan(&eventState.kcSeq, &eventState.storeSeq, &eventState.eventID, &eventState.created.byDeviceID, &eventState.created.byStoreID, &eventState.created.at, &encoded)
				check(err)
				reads++
				// log("relay.debounceSessions.debug event=%x", eventState.eventID)

				eventState.acked = false
				sessionState.buffer = append(sessionState.buffer, eventState)
				assert(eventState.kcSeq > sessionState.lastBufferedKCSeq)
				sessionState.lastBufferedKCSeq = eventState.kcSeq

				// TODO: would prever to not craft this manually
				eventState.encodedEvent = &anypb.Any{
					TypeUrl: "type.googleapis.com/market.mass.StoreEvent",
					Value:   encoded,
				}
			}
			check(rows.Err())

			// If the read rows didn't use the full limit, that means we must be at the end
			// of this user's writes.
			if reads < readsAllowed {
				sessionState.lastBufferedKCSeq = seqPair.lastWrittenKCSeq
			}

			logS(sessionId, "relay.debounceSessions.read storeId=%s reads=%d readsAllowed=%d bufferLen=%d lastWrittenKCSeq=%d, lastBufferedKCSeq=%d elapsed=%d", sessionState.storeID, reads, readsAllowed, len(sessionState.buffer), seqPair.lastWrittenKCSeq, sessionState.lastBufferedKCSeq, took(readStart))
			r.metric.counterAdd("relay_events_read", float64(reads))
		}
		r.assertCursors(sessionId, seqPair, sessionState)

		// Push any events as needed.
		const maxPushes = limitMaxOutRequests * limitMaxOutBatchSize
		pushes := 0
		var eventPushOp *EventPushOp
		pushOps := make([]SessionOp, 0)
		for ; sessionState.nextPushIndex < len(sessionState.buffer) && sessionState.nextPushIndex < maxPushes; sessionState.nextPushIndex++ {
			entryState := sessionState.buffer[sessionState.nextPushIndex]
			if eventPushOp != nil && len(eventPushOp.eventStates) == limitMaxOutBatchSize {
				eventPushOp = nil
			}
			if eventPushOp == nil {
				eventPushOp = &EventPushOp{
					sessionID:   sessionId,
					eventStates: make([]*EventState, 0),
				}
				pushOps = append(pushOps, eventPushOp)
			}
			eventPushOp.eventStates = append(eventPushOp.eventStates, entryState)
			sessionState.lastPushedKCSeq = entryState.kcSeq
			pushes++
		}
		for _, pushOp := range pushOps {
			r.sendSessionOp(sessionState, pushOp)
		}
		if pushes > 0 {
			logS(sessionId, "relay.debounce.push pushes=%d ops=%d", pushes, len(pushOps))
		}
		r.assertCursors(sessionId, seqPair, sessionState)

		// If there are no buffered events at this point, it's safe to advance the acked pointer.
		if len(sessionState.buffer) == 0 && sessionState.lastAckedKCSeq < sessionState.lastPushedKCSeq {
			logS(sessionId, "relay.debounceSessions.advanceKCSeq reason=emptyBuffer from=%d to=%d", sessionState.lastAckedKCSeq, sessionState.lastPushedKCSeq)
			sessionState.lastAckedKCSeq = sessionState.lastPushedKCSeq
		}
		r.assertCursors(sessionId, seqPair, sessionState)

		// Flush session state if sufficiently advanced.
		lastAckedKCSeqNeedsFlush := sessionState.lastAckedKCSeq-sessionState.lastAckedKCSeqFlushed > sessionLastAckedKCSeqFlushLimit
		lastSeenAtNeedsFlush := sessionState.lastSeenAt.Sub(sessionState.lastSeenAtFlushed) > sessionLastSeenAtFlushLimit
		if lastAckedKCSeqNeedsFlush || lastSeenAtNeedsFlush {
			flushStart := now()
			// Index: keyCards(id)
			query := `update keyCards set lastAckedKCSeq = $1, lastSeenAt = $2 where id = $3`
			_, err := r.connPool.Exec(ctx, query, sessionState.lastAckedKCSeq, sessionState.lastSeenAt, sessionState.keyCardID)
			check(err)
			sessionState.lastAckedKCSeqFlushed = sessionState.lastAckedKCSeq
			sessionState.lastSeenAtFlushed = sessionState.lastSeenAt
			logS(sessionId, "relay.debounceSessions.flush lastAckedKCSeqNeedsFlush=%t lastSeenAtNeedsFlush=%t lastAckedKCSeq=%d elapsed=%d", lastAckedKCSeqNeedsFlush, lastSeenAtNeedsFlush, sessionState.lastAckedKCSeq, took(flushStart))
		}
		// logS(sessionId, "relay.debounce.cursors lastWrittenKCSeq=%d lastStatusedstoreSeq=%d lastBufferedstoreSeq=%d lastPushedstoreSeq=%d lastAckedKCSeq=%d", userState.lastWrittenKCSeq, sessionState.lastStatusedstoreSeq, sessionState.lastBufferedstoreSeq, sessionState.lastPushedstoreSeq, sessionState.lastAckedKCSeq)
	})

	// Since we're polling this loop constantly, only log if takes a non-trivial amount of time.
	debounceSessionsElapsed := took(start)
	if debounceSessionsElapsed > 0 {
		r.metric.emit("relay.debounceSessions.elapsed", uint64(debounceSessionsElapsed))
		log("relay.debounceSessions.finish sessions=%d elapsed=%d", r.sessionIDsToSessionStates.Size(), debounceSessionsElapsed)
	}
}

func (r *Relay) debounceEventPropagations() {
	start := now()
	ctx := context.Background()

	// Pick IDs from DB that are to be propagated, short circuit if there are non for this debounce.
	eventIds := make([]eventID, 0)
	// Index: none, events(eventId)
	query := `select e.eventId from eventPropagations ep, events e where ep.eventId = e.eventId order by e.serverSeq asc limit $1`
	rows, err := r.connPool.Query(ctx, query, databasePropagationEventLimit)
	check(err)
	defer rows.Close()
	for rows.Next() {
		var eventId eventID
		err = rows.Scan(&eventId)
		check(err)
		eventIds = append(eventIds, eventId)
	}
	check(rows.Err())
	if len(eventIds) == 0 {
		return
	}
	log("relay.debounceEventPropagations.list events=%d took=%d", len(eventIds), took(start))

	// Read in event data for listed event IDs.
	readStart := now()
	events := r.readEvents(`eventId = any($1)`, eventIds)
	log("relay.debounceEventPropagations.read took=%d", took(readStart))

	// Compute new keyCardEvent tuples propagating for all listed events.
	deriveStart := now()
	keyCardEvents := make([]*KeyCardEvent, 0)

	for _, e := range events {
		storeState, exists := r.storeManifestsByStoreID.get(e.createdByStoreID)
		assert(exists)
		fanOutKeyCards := storeState.getValidKeyCardIDs(r.connPool)

		switch e.evtType {

		// staff + that customer
		// -===================-
		case eventTypeChangeStock:
			fallthrough
		case eventTypeCreateOrder:
			fallthrough
		case eventTypeUpdateOrder:
			for _, kc := range fanOutKeyCards {
				if !kc.isGuest || e.createdByKeyCardID.Equal(kc.id) {
					keyCardEvents = append(keyCardEvents, &KeyCardEvent{
						keyCardId:     kc.id,
						eventStoreSeq: e.storeSeq,
					})
				}
			}

			// public
			// -====-
			// TODO: decide if keyCards should be private
			//   -> means guests cant verify signatures
		case eventTypeNewKeyCard:
			// first user
			if len(fanOutKeyCards) == 0 {
				keyCardEvents = append(keyCardEvents, &KeyCardEvent{
					keyCardId:     e.createdByKeyCardID,
					eventStoreSeq: e.storeSeq,
				})
			}
			fallthrough
		case eventTypeStoreManifest:
			fallthrough
		case eventTypeUpdateStoreManifest:
			fallthrough
		case eventTypeCreateItem:
			fallthrough
		case eventTypeUpdateItem:
			fallthrough
		case eventTypeCreateTag:
			fallthrough
		case eventTypeUpdateTag:
			for _, kc := range fanOutKeyCards {
				keyCardEvents = append(keyCardEvents, &KeyCardEvent{
					keyCardId:     kc.id,
					eventStoreSeq: e.storeSeq,
				})
			}
		default:
			panic(fmt.Sprintf("unhandeled event type: %s", e.evtType))
		}
	}
	for _, kce := range keyCardEvents {
		kce.keyCardId.assert()
		assert(kce.eventStoreSeq != 0)
		assert(kce.keyCardSeq == 0)
	}
	log("relay.debounceEventPropagations.derive keyCardEvents=%d took=%d", len(keyCardEvents), took(deriveStart))

	// Hydrate users in preparation for enriching derived keyCardEvents with userSeqs.
	// Then enrich derived keyCardEvents with userSeqs, in order they were emitted.
	enrichStart := now()
	keyCardIds := NewSetRequestIDs()
	for _, ue := range keyCardEvents {
		keyCardIds.Add(ue.keyCardId)
	}
	r.hydrateKeyCards(keyCardIds)
	for _, ue := range keyCardEvents {
		seqPair := r.keyCardIDsToKeyCardSeqs.MustGet(ue.keyCardId)
		ue.keyCardSeq = seqPair.lastUsedKCSeq + 1
		seqPair.lastUsedKCSeq = ue.keyCardSeq
	}
	log("relay.debounceEventPropagations.enrich took=%d", took(enrichStart))

	// Insert derived and enriched keyCardEvents.
	insertStart := now()
	keyCardEventRows := make([][]any, len(keyCardEvents))
	for i, ue := range keyCardEvents {
		keyCardEventRows[i] = []interface{}{ue.keyCardId, ue.keyCardSeq, ue.eventStoreSeq}
	}
	insertedRows, _ := r.bulkInsert("keyCardEvents", []string{"keyCardId", "keyCardSeq", "eventStoreSeq"}, keyCardEventRows)
	for _, row := range insertedRows {
		kcID := row[0].(requestID)
		kcSeq := row[1].(uint64)
		seqPair := r.keyCardIDsToKeyCardSeqs.MustGet(kcID)
		assert(seqPair.lastWrittenKCSeq < kcSeq)
		assert(kcSeq <= seqPair.lastUsedKCSeq)
		seqPair.lastWrittenKCSeq = kcSeq
	}
	log("relay.debounceEventPropagations.insert inserted=%d took=%d", len(insertedRows), took(insertStart))

	// Delete from eventPropagations now that we've completed these propagations.
	deleteStart := now()
	query = `delete from eventPropagations ep where eventId = any($1)`
	_, err = r.connPool.Exec(ctx, query, eventIds)
	check(err)
	log("relay.debounceEventPropagations.delete took=%d", took(deleteStart))

	log("relay.debounceEventPropagations.finish took=%d", took(start))
}

// PaymentWaiter is a struct that holds the state of a order that is waiting for payment.
type PaymentWaiter struct {
	waiterID         requestID
	orderID          eventID
	orderFinalizedAt time.Time
	purchaseAddr     common.Address
	lastBlockNo      SQLStringBigInt
	coinsPayed       SQLStringBigInt
	coinsTotal       SQLStringBigInt
	paymentId        SQLStringBigInt

	// (optional) contract of the erc20 that we are looking for
	erc20TokenAddr *common.Address

	// set if order was payed
	orderPayedAt *time.Time
	orderPayedTx *common.Hash
}

var (
	bigZero = big.NewInt(0)
	bigOne  = big.NewInt(1)
)

func (r *Relay) watchEthereumPayments() error {
	log("relay.watchEthereumPayments.start")

	var (
		start = now()

		// this is the block iterator
		lowestLastBlock = new(big.Int)

		waiters = make(map[common.Address]PaymentWaiter)
	)

	ctx, cancel := context.WithDeadline(context.Background(), start.Add(watcherTimeout))
	defer cancel()

	openPaymentsQry := `SELECT waiterId, orderId, orderFinalizedAt, purchaseAddr, lastBlockNo, coinsPayed, coinsTotal
	FROM payments
	WHERE orderPayedAt IS NULL
		AND erc20TokenAddr IS NULL -- see watchErc20Payments()
		AND orderFinalizedAt >= NOW() - INTERVAL '1 day' ORDER BY lastBlockNo asc;`
	rows, err := r.connPool.Query(ctx, openPaymentsQry)
	check(err)
	defer rows.Close()
	for rows.Next() {
		var waiter PaymentWaiter
		err := rows.Scan(&waiter.waiterID, &waiter.orderID, &waiter.orderFinalizedAt, &waiter.purchaseAddr, &waiter.lastBlockNo, &waiter.coinsPayed, &waiter.coinsTotal)
		check(err)

		assert(waiter.lastBlockNo.Cmp(bigZero) != 0)

		// init first
		if lowestLastBlock.Cmp(bigZero) == 0 {
			lowestLastBlock = &waiter.lastBlockNo.Int
		}
		// is this waiter smaller?
		if lowestLastBlock.Cmp(&waiter.lastBlockNo.Int) == -1 {
			lowestLastBlock = &waiter.lastBlockNo.Int
		}

		waiters[waiter.purchaseAddr] = waiter
	}
	check(rows.Err())

	if len(waiters) == 0 {
		log("relay.watchEthereumPayments.noOpenPayments took=%d", took(start))
		return nil
	}

	log("relay.watchEthereumPayments.dbRead took=%d waiters=%d lowestLastBlock=%s", took(start), len(waiters), lowestLastBlock)

	// make geth client
	gethClient, err := r.ethClient.getClient(ctx)
	if err != nil {
		return err
	}
	defer gethClient.Close()

	// Get the latest block number
	currentBlockNoInt, err := gethClient.BlockNumber(ctx)
	check(err)
	currentBlockNo := big.NewInt(int64(currentBlockNoInt))

	for {
		if currentBlockNo.Cmp(lowestLastBlock) == -1 {
			// nothing to do
			log("relay.watchEthereumPayments.noNewBlocks current=%d", currentBlockNoInt)
			break
		}
		// check each block for transactions
		block, err := gethClient.BlockByNumber(ctx, lowestLastBlock)
		if err != nil {

			return fmt.Errorf("relay.watchEthereumPayments.failedToGetBlock block=%s err=%s", lowestLastBlock, err)
		}

		for _, tx := range block.Transactions() {
			to := tx.To()
			if to == nil {
				continue // contract creation
			}
			waiter, has := waiters[*to]
			if has {
				log("relay.watchEthereumPayments.checkTx waiter.lastBlockNo=%s checkingBlock=%s tx=%s to=%s", waiter.lastBlockNo.String(), block.Number().String(), tx.Hash().String(), tx.To().String())
				orderID := waiter.orderID
				// order, has := r.ordersByOrderID.get(orderID)
				assertWithMessage(has, fmt.Sprintf("order not found for orderId=%s", orderID))

				// found a transaction to the purchase address
				// check if it's the right amount
				inTx := tx.Value()
				waiter.coinsPayed.Add(&waiter.coinsPayed.Int, inTx)
				if waiter.coinsPayed.Cmp(&waiter.coinsTotal.Int) != -1 {
					// it is larger or equal

					op := PaymentFoundInternalOp{
						orderID: orderID,
						txHash:  tx.Hash(),
						done:    make(chan struct{}),
					}
					r.opsInternal <- &op
					<-op.done // wait for write

					delete(waiters, waiter.purchaseAddr)
					log("relay.watchEthereumPayments.completed orderId=%s", orderID)
				} else {
					// it is still smaller
					log("relay.watchEthereumPayments.partial orderId=%s inTx=%s subTotal=%s", orderID, inTx.String(), waiter.coinsPayed.String())
					// update subtotal
					const updateSubtotalQuery = `UPDATE payments SET coinsPayed = $1 WHERE orderId = $2;`
					_, err := r.connPool.Exec(ctx, updateSubtotalQuery, waiter.coinsPayed, orderID)
					check(err) // cant recover sql errors
				}
			}
		}
		for _, waiter := range waiters {
			// only advance those waiters which last blocks are lower then the block we just checked
			if waiter.lastBlockNo.Cmp(currentBlockNo) == -1 {
				continue
			}
			// lastBlockNo += 1
			waiter.lastBlockNo.Add(&waiter.lastBlockNo.Int, bigOne)
			const updateLastBlockNoQuery = `UPDATE payments SET lastBlockNo = lastBlockNo + 1 WHERE orderId = $1;`
			orderID := waiter.orderID
			_, err = r.connPool.Exec(ctx, updateLastBlockNoQuery, orderID)
			check(err)
			log("relay.watchEthereumPayments.advance orderId=%x newLastBlock=%s", orderID, waiter.lastBlockNo.String())
		}
		// increment iterator
		lowestLastBlock.Add(lowestLastBlock, bigOne)
	}

	stillWaiting := len(waiters)
	log("relay.watchEthereumPayments.finish took=%d openWaiters=%d", took(start), stillWaiting)
	r.metric.emit("relay_payments_eth_open", uint64(stillWaiting))
	return nil
}

var (
	eventSignatureTransferErc20 = crypto.Keccak256Hash([]byte("Transfer(address,address,uint256)"))
	eventSignaturePaymentMade   = crypto.Keccak256Hash([]byte("PaymentMade(uint256)"))
)

func (r *Relay) watchErc20Payments() error {
	log("relay.watchErc20Payments.start")

	var (
		start = now()

		// this is the block iterator
		lowestLastBlock = new(big.Int)

		waiters         = make(map[common.Hash]PaymentWaiter)
		erc20AddressSet = make(map[common.Address]struct{})
	)

	ctx, cancel := context.WithDeadline(context.Background(), start.Add(watcherTimeout))
	defer cancel()

	gethClient, err := r.ethClient.getClient(ctx)
	if err != nil {
		return err
	}
	defer gethClient.Close()

	openPaymentsQry := `SELECT waiterId, orderId, orderFinalizedAt, purchaseAddr, lastBlockNo, coinsPayed, coinsTotal, erc20TokenAddr
		FROM payments
		WHERE orderPayedAt IS NULL
			AND erc20TokenAddr IS NOT NULL -- see watchErc20Payments()
			AND orderFinalizedAt >= NOW() - INTERVAL '1 day' ORDER BY lastBlockNo asc;`
	rows, err := r.connPool.Query(ctx, openPaymentsQry)
	check(err)
	defer rows.Close()
	for rows.Next() {
		var waiter PaymentWaiter
		err := rows.Scan(&waiter.waiterID, &waiter.orderID, &waiter.orderFinalizedAt, &waiter.purchaseAddr, &waiter.lastBlockNo, &waiter.coinsPayed, &waiter.coinsTotal, &waiter.erc20TokenAddr)
		check(err)
		assert(waiter.lastBlockNo.Cmp(bigZero) != 0)

		// init first
		if lowestLastBlock.Cmp(bigZero) == 0 {
			lowestLastBlock = &waiter.lastBlockNo.Int
		}
		// is this waiter smaller?
		if lowestLastBlock.Cmp(&waiter.lastBlockNo.Int) == -1 {
			lowestLastBlock = &waiter.lastBlockNo.Int
		}

		erc20AddressSet[*waiter.erc20TokenAddr] = struct{}{}

		// right-align the purchase address to 32 bytes so we can use it as a topic
		var purchaseAddrAsHash common.Hash
		copy(purchaseAddrAsHash[12:], waiter.purchaseAddr.Bytes())
		waiters[purchaseAddrAsHash] = waiter
	}
	check(rows.Err())

	if len(waiters) == 0 {
		log("relay.watchErc20Payments.noOpenPayments took=%d", took(start))
		return nil
	}

	// Get the latest block number.
	currentBlockNoInt, err := gethClient.BlockNumber(ctx)
	if err != nil {
		return fmt.Errorf("relay.watchErc20Payments.blockNumber err=%s", err)
	}

	log("relay.watchErc20Payments.starting currentBlock=%d", currentBlockNoInt)
	currentBlockNo := big.NewInt(int64(currentBlockNoInt))

	// turn set into a list
	erc20Addresses := make([]common.Address, len(erc20AddressSet))
	i := 0
	for addr := range erc20AddressSet {
		copy(erc20Addresses[i][:], addr[:])
		i++
	}

	qry := ethereum.FilterQuery{
		Addresses: erc20Addresses,
		FromBlock: lowestLastBlock,
		ToBlock:   currentBlockNo,
		Topics: [][]common.Hash{
			{eventSignatureTransferErc20},
			// TODO: it would seem that {transferSignatureErc20, {}, purchaseAddrAsHash} would be the right filter, but it doesn't work
			// See the following article but i'm not willing to do all that just right now
			// https://dave-appleton.medium.com/overcoming-ethclients-filter-restrictions-81e232a8eccd
		},
	}
	logs, err := gethClient.FilterLogs(ctx, qry)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil // possibly no new block, dont try again immediatly
		}
		return err
	}

	// iterate over all matching logs of events from that erc20 contract with the transfer signature
	var lastBlockNo uint64
	for _, vLog := range logs {
		// log("relay.watchErc20Payments.checking block=%d", vLog.BlockNumber)
		// log("relay.watchErc20Payments.checking topics=%#v", vLog.Topics[1:])
		fromHash := vLog.Topics[1]
		toHash := vLog.Topics[2]

		waiter, has := waiters[toHash]
		if has && waiter.erc20TokenAddr.Cmp(vLog.Address) == 0 {
			// We found a transfer to our address!
			orderID := waiter.orderID

			_, has := r.ordersByOrderID.get(orderID)
			assertWithMessage(has, fmt.Sprintf("order not found for orderId=%s", orderID))

			evts, err := r.ethClient.erc20ContractABI.Unpack("Transfer", vLog.Data)
			if err != nil {
				log("relay.watchErc20Payments.transferErc20.failedToUnpackTransfer err=%s", err)
				continue
			}

			inTx, ok := evts[0].(*big.Int)
			assertWithMessage(ok, fmt.Sprintf("unexpected unpack result for field 0 - type=%T", evts[0]))
			log("relay.watchErc20Payments.foundTransfer orderId=%s from=%s to=%s amount=%s", orderID, fromHash.Hex(), toHash.Hex(), inTx.String())

			waiter.coinsPayed.Add(&waiter.coinsPayed.Int, inTx)
			if waiter.coinsPayed.Cmp(&waiter.coinsTotal.Int) != -1 {
				// it is larger or equal

				op := PaymentFoundInternalOp{
					orderID: orderID,
					txHash:  vLog.TxHash,
					done:    make(chan struct{}),
				}
				r.opsInternal <- &op
				<-op.done

				delete(waiters, toHash)
				log("relay.watchErc20Payments.completed orderId=%s", orderID)

			} else {
				// it is still smaller
				log("relay.watchErc20Payments.partial orderId=%s inTx=%s subTotal=%s", orderID, inTx.String(), waiter.coinsPayed.String())
				// update subtotal
				const updateSubtotalQuery = `UPDATE payments SET coinsPayed = $1 WHERE orderId = $2;`
				_, err = r.connPool.Exec(ctx, updateSubtotalQuery, waiter.coinsPayed, orderID)
				check(err)
			}
		}
		if vLog.BlockNumber > lastBlockNo {
			lastBlockNo = vLog.BlockNumber
		}

	}
	if lastBlockNo > 0 {
		lastBlockBig := new(big.Int).SetUint64(lastBlockNo)
		for _, waiter := range waiters {
			// only advance those waiters which last blocks are lower then the block we just checked
			if waiter.lastBlockNo.Cmp(lastBlockBig) == -1 {
				continue
			}
			// move up block number
			const updateLastBlockNoQuery = `UPDATE payments SET lastBlockNo = $2 WHERE orderId = $1;`
			_, err = r.connPool.Exec(ctx, updateLastBlockNoQuery, waiter.orderID, currentBlockNo.String())
			check(err)
			log("relay.watchErc20Payments.advance orderId=%x newLastBlock=%s", waiter.orderID, waiter.lastBlockNo.String())
		}
	}
	stillWaiting := len(waiters)
	log("relay.watchErc20Payments.finish took=%d openWaiters=%d", took(start), stillWaiting)
	r.metric.emit("relay_payments_erc20_open", uint64(stillWaiting))
	return nil
}

func (r *Relay) watchPaymentMade() error {
	log("relay.watchPaymentMade.start")

	var (
		start = now()

		// this is the block iterator
		lowestLastBlock = new(big.Int)

		waiters = make(map[common.Hash]PaymentWaiter)
	)

	ctx, cancel := context.WithDeadline(context.Background(), start.Add(watcherTimeout))
	defer cancel()

	gethClient, err := r.ethClient.getClient(ctx)
	if err != nil {
		return err
	}
	defer gethClient.Close()

	openPaymentsQry := `SELECT waiterId, orderId, orderFinalizedAt, paymentId, lastBlockNo
		FROM payments
		WHERE orderPayedAt IS NULL AND orderFinalizedAt >= NOW() - INTERVAL '1 day' ORDER BY lastBlockNo asc;`
	rows, err := r.connPool.Query(ctx, openPaymentsQry)
	check(err)
	defer rows.Close()
	for rows.Next() {
		var waiter PaymentWaiter
		err := rows.Scan(&waiter.waiterID, &waiter.orderID, &waiter.orderFinalizedAt, &waiter.paymentId, &waiter.lastBlockNo)
		check(err)
		assert(waiter.lastBlockNo.Cmp(bigZero) != 0)

		// init first
		if lowestLastBlock.Cmp(bigZero) == 0 {
			lowestLastBlock = &waiter.lastBlockNo.Int
		}
		// is this waiter smaller?
		if lowestLastBlock.Cmp(&waiter.lastBlockNo.Int) == -1 {
			lowestLastBlock = &waiter.lastBlockNo.Int
		}
		pid := common.Hash(waiter.paymentId.Bytes())
		//log("relay.watchPaymentMade.want pid=%s", pid.Hex())
		waiters[pid] = waiter
	}
	check(rows.Err())

	if len(waiters) == 0 {
		log("relay.watchPaymentMade.noOpenPayments took=%d", took(start))
		return nil
	}

	// Get the latest block number.
	currentBlockNoInt, err := gethClient.BlockNumber(ctx)
	if err != nil {
		return fmt.Errorf("relay.watchPaymentMade.blockNumber err=%s", err)
	}

	log("relay.watchPaymentMade.starting currentBlock=%d", currentBlockNoInt)
	currentBlockNo := big.NewInt(int64(currentBlockNoInt))

	qry := ethereum.FilterQuery{
		Addresses: []common.Address{r.ethClient.contractAddresses.Payments},
		FromBlock: lowestLastBlock,
		ToBlock:   currentBlockNo,
		Topics: [][]common.Hash{
			{eventSignaturePaymentMade},
		},
	}
	logs, err := gethClient.FilterLogs(ctx, qry)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			log("relay.watchPaymentMade.noNewBlocks took=%d", took(start))
			return nil // possibly no new block, dont try again immediatly
		}
		return err
	}

	// iterate over all matching logs of events from that erc20 contract with the transfer signature
	var lastBlockNo uint64
	for _, vLog := range logs {
		//log("relay.watchPaymentMade.checking block=%d", vLog.BlockNumber)

		var paymentIdHash = common.Hash(vLog.Topics[1])
		//log("relay.watchPaymentMade.seen pid=%s", paymentIdHash.Hex())

		if waiter, has := waiters[paymentIdHash]; has {
			orderID := waiter.orderID
			//log("relay.watchPaymentMade.found cartId=%s txHash=%x", orderID, vLog.TxHash)

			_, has := r.ordersByOrderID.get(orderID)
			assertWithMessage(has, fmt.Sprintf("order not found for orderId=%s", orderID))

			op := PaymentFoundInternalOp{
				orderID: orderID,
				txHash:  vLog.TxHash,
				done:    make(chan struct{}),
			}
			r.opsInternal <- &op
			<-op.done // block until op was processed by server loop

			delete(waiters, paymentIdHash)
			log("relay.watchPaymentMade.completed cartId=%s txHash=%x", orderID, vLog.TxHash)
		}
		if vLog.BlockNumber > lastBlockNo {
			lastBlockNo = vLog.BlockNumber
		}
	}
	if lastBlockNo > 0 {
		lastBlockBig := new(big.Int).SetUint64(lastBlockNo)
		for _, waiter := range waiters {
			// only advance those waiters which last blocks are lower then the block we just checked
			if waiter.lastBlockNo.Cmp(lastBlockBig) == -1 {
				continue
			}
			// move up block number
			const updateLastBlockNoQuery = `UPDATE payments SET lastBlockNo = $2 WHERE cartId = $1;`
			_, err = r.connPool.Exec(ctx, updateLastBlockNoQuery, waiter.orderID, currentBlockNo.String())
			check(err)
			log("relay.watchPaymentMade.advance cartId=%x newLastBlock=%s", waiter.orderID, waiter.lastBlockNo.String())
		}
	}
	stillWaiting := len(waiters)
	log("relay.watchPaymentMade.finish elapsed=%d openWaiters=%d", took(start), stillWaiting)
	r.metric.emit("relay_payments_open", uint64(stillWaiting))
	return nil
}

func (r *Relay) memoryStats() {
	start := now()
	log("relay.memoryStats.start")

	// Shared between old and sharing worlds.
	sessionCount := r.sessionIDsToSessionStates.Size()
	sessionVersionCounts := make(map[uint]uint64)
	r.sessionIDsToSessionStates.All(func(sessionId requestID, sessionState *SessionState) {
		sessionVersionCount := sessionVersionCounts[sessionState.version]
		sessionVersionCounts[sessionState.version] = sessionVersionCount + 1
	})
	r.metric.emit("sessions.active", uint64(sessionCount))
	for version, versionCount := range sessionVersionCounts {
		r.metric.emit(fmt.Sprintf("sessions.active.version.%d", version), versionCount)
	}
	r.metric.emit("relay.cached.stores", uint64(r.storeIdsToStoreState.Size()))

	r.metric.emit("relay.ops.queued", uint64(len(r.ops)))

	r.metric.emit("relay.cached.items", uint64(r.itemsByItemID.loaded.Size()))
	r.metric.emit("relay.cached.orders", uint64(r.ordersByOrderID.loaded.Size()))

	// Go runtime memory information
	var runtimeMemory runtime.MemStats
	runtime.ReadMemStats(&runtimeMemory)
	r.metric.emit("go.runtime.heapalloc", runtimeMemory.HeapAlloc)
	r.metric.emit("go.runtime.inuse", runtimeMemory.HeapInuse)
	r.metric.emit("go.runtime.gcpauses", runtimeMemory.PauseTotalNs)

	memoryStatsTook := took(start)
	r.metric.emit("relay.memoryStats.took", uint64(memoryStatsTook))
	log("relay.memoryStats.finish took=%d", memoryStatsTook)
}

func newPool() *pgxpool.Pool {
	syncPool, err := pgxpool.Connect(context.Background(), mustGetEnvString("DATABASE_URL"))
	check(err)
	return syncPool
}

//go:generate stringer -output gen_tickType_string.go -trimprefix tt -type tickType  .

type tickType uint

const (
	ttInvalid tickType = iota
	ttWait
	ttOp
	ttOpInternal
	ttDebounceSessions
	ttPaymentWatcher
	ttMemoryStats
	ttTickStats
)

var allTickTypes = [...]tickType{
	ttWait,
	ttOp,
	ttOpInternal,
	ttDebounceSessions,
	ttPaymentWatcher,
	ttMemoryStats,
	ttTickStats,
}

func timeTick(tt tickType) (tickType, time.Time) {
	return tt, now()
}

func (r *Relay) run() {
	assert(r.writesEnabled)
	log("relay.run")
	// defer sentryRecover()

	debounceSessionsTimer := NewReusableTimer(databaseDebounceInterval)
	memoryStatsTimer := NewReusableTimer(memoryStatsInterval)
	tickStatsTimer := NewReusableTimer(tickStatsInterval)

	tickTypeToTooks := make(map[tickType]time.Duration, len(allTickTypes))
	for _, tt := range allTickTypes {
		tickTypeToTooks[tt] = 0
	}

	for {
		var (
			tickType     = ttInvalid
			tickStart    = now()
			tickSelected time.Time
		)

		select {

		case op := <-r.ops:
			tickType, tickSelected = timeTick(ttOp)
			op.getSessionID().assert()
			op.process(r)

		case op := <-r.opsInternal:
			tickType, tickSelected = timeTick(ttOpInternal)
			op.process(r)

		case <-debounceSessionsTimer.C:
			tickType, tickSelected = timeTick(ttDebounceSessions)
			r.debounceEventPropagations()
			r.debounceSessions()
			debounceSessionsTimer.Rewind()

		case <-memoryStatsTimer.C:
			tickType, tickSelected = timeTick(ttMemoryStats)
			r.memoryStats()
			memoryStatsTimer.Rewind()

		case <-tickStatsTimer.C:
			tickType, tickSelected = timeTick(ttTickStats)
			for tt, e := range tickTypeToTooks {
				if e.Milliseconds() > 0 {
					r.metric.emit(fmt.Sprintf("relay.run.tick.%s.took", tt.String()), uint64(e.Milliseconds()))
				}
				tickTypeToTooks[tt] = 0
			}
			tickStatsTimer.Rewind()
		}

		assert(tickType != ttInvalid)
		assert(!tickSelected.IsZero())
		tickWait := tickSelected.Sub(tickStart)
		tickTook := time.Since(tickSelected)
		tickTypeToTooks[ttWait] += tickWait
		e, ok := tickTypeToTooks[tickType]
		assert(ok)
		e += tickTook
		tickTypeToTooks[tickType] = e
		if tickTook > tickBlockThreshold {
			log("relay.run.tick.block type=%s took=%d", tickType, tickTook.Milliseconds())
		}
	}
}

// Metric maps a name to a prometheus metric.
type Metric struct {
	name2gauge      map[string]prometheus.Gauge
	name2counter    map[string]prometheus.Counter
	httpStatusCodes *prometheus.CounterVec
}

func newMetric() *Metric {
	return &Metric{
		name2gauge:   make(map[string]prometheus.Gauge),
		name2counter: make(map[string]prometheus.Counter),
		httpStatusCodes: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "http_response_codes",
		}, []string{"status", "path"}),
	}
}

func (m *Metric) connect() {
	log("metric.connect")

	srv := http.Server{}
	srv.Addr = mustGetEnvString("LISTENER_METRIC")
	srv.Handler = promhttp.Handler()
	err := srv.ListenAndServe()
	check(err)
}

// TODO: deprecate this function and use gauge / counter where appropriate
func (m *Metric) emit(name string, value uint64) {
	name = strings.Replace(name, ".", "_", -1)
	if logMetrics {
		log("metric.emit name=%s value=%d", name, value)
	}
	gauge, has := m.name2gauge[name]
	if !has {
		gauge = promauto.NewGauge(prometheus.GaugeOpts{
			Name: name,
		})
	}

	gauge.Set(float64(value))
	if !has {
		m.name2gauge[name] = gauge
	}
}

func (m *Metric) counterAdd(name string, value float64) {
	counter, has := m.name2counter[name]
	if !has {
		counter = promauto.NewCounter(prometheus.CounterOpts{
			Name: name,
		})
	}

	counter.Add(value)
	if !has {
		m.name2counter[name] = counter
	}
}

// HTTP Handlers

func sessionsHandleFunc(version uint, r *Relay) func(http.ResponseWriter, *http.Request) {
	log("relay.sessionsHandleFunc version=%d", version)
	return func(w http.ResponseWriter, req *http.Request) {
		conn, _, _, err := ws.UpgradeHTTP(req, w)
		if err != nil {
			code := http.StatusInternalServerError
			if rej, ok := err.(*ws.ConnectionRejectedError); ok {
				code = rej.StatusCode()
			}
			r.metric.httpStatusCodes.WithLabelValues(strconv.Itoa(code), req.URL.Path).Inc()
			log("relay.upgradeError %+v", err)
			return
		}
		// bit of a misnomer, to set 201, but let's log it at least
		r.metric.httpStatusCodes.WithLabelValues("201", req.URL.Path).Inc()
		sess := newSession(version, conn, r.ops, r.metric)
		startOp := &StartOp{sessionID: sess.id, sessionVersion: version, sessionOps: sess.ops}
		sess.sendDatabaseOp(startOp)
		sess.run()
	}
}

func (r *Relay) getOrCreateInternalStoreID(storeTokenID big.Int) eventID {
	var (
		storeID eventID
		ctx     = context.Background()
	)
	err := r.connPool.QueryRow(ctx, `select id from stores where tokenId = $1`, storeTokenID.String()).Scan(&storeID)
	if err == nil {
		return storeID
	}
	if err != pgx.ErrNoRows {
		check(err)
	}

	storeID = newEventID()
	_, err = r.connPool.Exec(ctx, `insert into stores (id, tokenId) values ($1, $2)`, storeID, storeTokenID.String())
	check(err)
	return storeID
}

func uploadBlobHandleFunc(_ uint, r *Relay) func(http.ResponseWriter, *http.Request) {
	fn := func(w http.ResponseWriter, req *http.Request) (int, error) {
		err := req.ParseMultipartForm(32 << 20) // 32mb max file size
		if err != nil {
			return http.StatusBadRequest, err
		}
		params := req.URL.Query()

		r.blobUploadTokensMu.Lock()
		token := params.Get("token")
		_, has := r.blobUploadTokens[token]
		if !has {
			r.blobUploadTokensMu.Unlock()
			return http.StatusBadRequest, fmt.Errorf("blobs: no such token %q", token)
		}
		delete(r.blobUploadTokens, token)
		r.blobUploadTokensMu.Unlock()

		file, _, err := req.FormFile("file")
		if err != nil {
			return http.StatusBadRequest, err
		}

		ipfsClient, err := getIpfsClient(req.Context(), 0, nil)
		if err != nil {
			return http.StatusInternalServerError, err
		}

		dc := datacounter.NewReaderCounter(file)
		uploadHandle := ipfsFiles.NewReaderFile(dc)

		uploadedCid, err := ipfsClient.Unixfs().Add(req.Context(), uploadHandle)
		if err != nil {
			return http.StatusInternalServerError, err
		}

		log("relay.blobUpload bytes=%d path=%s", dc.Count(), uploadedCid)
		r.metric.counterAdd("blob_upload", 1)
		r.metric.counterAdd("blob_uploadBytes", float64(dc.Count()))

		if !isDevEnv {
			go func() {
				// TODO: better pin name
				startPin := now()
				pinResp, err := pinataPin(uploadedCid, "relay-blob")
				if err != nil {
					log("relay.blobUpload.pinata err=%s", err)
					return
				}
				log("relay.blobUpload.pinata ipfs_cid=%s pinata_id=%s status=%s", uploadedCid, pinResp.ID, pinResp.Status)
				r.metric.counterAdd("blob_pinata", 1)
				r.metric.counterAdd("blob_pinata_took", float64(took(startPin)))
			}()
		}

		const status = http.StatusCreated
		w.WriteHeader(status)
		err = json.NewEncoder(w).Encode(map[string]any{"ipfs_path": uploadedCid.String(), "url": "https://cloudflare-ipfs.com" + uploadedCid.String()})
		if err != nil {
			log("relay.blobUpload.writeFailed err=%s", err)
			// returning nil since responding with an error is not possible at this point
		}
		return status, nil
	}
	return func(w http.ResponseWriter, req *http.Request) {
		code, err := fn(w, req)
		r.metric.httpStatusCodes.WithLabelValues(strconv.Itoa(code), req.URL.Path).Inc()
		if err != nil {
			jsonEnc := json.NewEncoder(w)
			log("relay.blobUploadHandler err=%s", err)
			w.WriteHeader(code)
			err = jsonEnc.Encode(map[string]any{"handler": "getBlobUpload", "error": err.Error()})
			if err != nil {
				log("relay.blobUpload.writeFailed err=%s", err)
			}
			return
		}
	}
}

// once a user is registered, they need to sign their keycard
func enrollKeyCardHandleFunc(_ uint, r *Relay) func(http.ResponseWriter, *http.Request) {
	type requestData struct {
		KeyCardPublicKey []byte `json:"key_card"`
		Signature        []byte `json:"signature"`
		StoreTokenID     []byte `json:"store_token_id"`
	}

	fn := func(w http.ResponseWriter, req *http.Request) (int, error) {
		var data requestData
		err := json.NewDecoder(req.Body).Decode(&data)
		if err != nil {
			return http.StatusBadRequest, fmt.Errorf("invalid json: %w", err)
		}

		if len(data.StoreTokenID) != 32 {
			return http.StatusBadRequest, errors.New("invalid storeTokenID")
		}

		userWallet, err := r.ethClient.verifyKeyCardEnroll(data.KeyCardPublicKey, data.Signature)
		if err != nil {
			return http.StatusForbidden, fmt.Errorf("invalid signature: %w", err)
		}

		ctx, cancel := context.WithTimeout(req.Context(), 5*time.Second)
		defer cancel()

		storeReg, gethClient, err := r.ethClient.newStoreReg(ctx)
		if err != nil {
			return http.StatusInternalServerError, fmt.Errorf("contract call error: %w", err)
		}
		defer gethClient.Close()

		opts := &bind.CallOpts{
			Pending: false,
			From:    r.ethClient.wallet,
			Context: ctx,
		}

		var bigTokenID big.Int
		bigTokenID.SetBytes(data.StoreTokenID)

		//  check if store exists
		_, err = storeReg.OwnerOf(opts, &bigTokenID)
		if err != nil {
			return http.StatusNotFound, fmt.Errorf("no owner for store: %w", err)
		}

		var isGuest bool = req.URL.Query().Get("guest") == "1"
		if !isGuest {
			// updateRootHash PERM is equivalent to Clerk or higher
			perm, err := storeReg.PERMUpdateRootHash(opts)
			if err != nil {
				return http.StatusBadRequest, fmt.Errorf("failed to get updateRootHash PERM: %w", err)
			}
			has, err := storeReg.HasPermission(opts, &bigTokenID, userWallet, perm)
			if err != nil {
				return http.StatusInternalServerError, fmt.Errorf("contract call error: %w", err)
			}
			log("relay.enrollKeyCard.verifyAccess storeTokenID=%s userWallet=%s has=%v", bigTokenID.String(), userWallet.Hex(), has)
			if !has {
				return http.StatusForbidden, errors.New("access denied")
			}
		}

		dbCtx := context.Background()
		storeID := r.getOrCreateInternalStoreID(bigTokenID)
		newKeyCardID := newRequestID()
		const insertKeyCard = `insert into keyCards (id, storeId, cardPublicKey, userWalletAddr, linkedAt, lastAckedKCSeq, lastSeenAt, lastVersion, isGuest)
		VALUES ($1, $2, $3, $4, now(), 0, now(), $5, $6)`
		_, err = r.connPool.Exec(dbCtx, insertKeyCard, newKeyCardID, storeID, data.KeyCardPublicKey, userWallet, currentRelayVersion, isGuest)
		check(err)

		w.WriteHeader(http.StatusCreated)
		err = json.NewEncoder(w).Encode(map[string]any{"success": true})
		if err != nil {
			log("relay.enrollKeyCard.responseFailure err=%s", err)
			// returning an error would mean sending error code
			// we already sent one so we cant
			_, err = r.connPool.Exec(dbCtx, `delete from keyCards where id = $1`, newKeyCardID)
			check(err)
			return 0, nil
		}

		go func() {
			r.opsInternal <- &KeyCardEnrolledInternalOp{
				storeID:           storeID,
				keyCardIsGuest:    isGuest,
				keyCardDatabaseID: newKeyCardID,
				keyCardPublicKey:  data.KeyCardPublicKey,
				userWallet:        userWallet,
			}
		}()
		return http.StatusCreated, nil
	}
	return func(w http.ResponseWriter, req *http.Request) {
		code, err := fn(w, req)
		r.metric.httpStatusCodes.WithLabelValues(strconv.Itoa(code), req.URL.Path).Inc()
		if err != nil {
			jsonEnc := json.NewEncoder(w)
			log("relay.enrollKeyCard.failed err=%s", err)
			w.WriteHeader(code)
			err = jsonEnc.Encode(map[string]any{"handler": "enrollKeyCard", "error": err.Error()})
			if err != nil {
				log("relay.enrollKeyCard.failedToRespond err=%s", err)
			}
			return
		}
	}
}

func healthHandleFunc(r *Relay) func(http.ResponseWriter, *http.Request) {
	log("relay.healthHandleFunc")
	return func(w http.ResponseWriter, req *http.Request) {
		start := now()
		log("relay.health.start")
		ctx := context.Background()
		var res int
		err := r.connPool.QueryRow(ctx, `select 1`).Scan(&res)
		if err != nil {
			log("relay.health.dbs.fail")
			w.WriteHeader(500)
			r.metric.httpStatusCodes.WithLabelValues("500", req.URL.Path).Inc()
			_, err = fmt.Fprintln(w, "database unavailable")
			if err != nil {
				log("relay.health.okFailed error=%s", err)
			}
			return
		}

		log("relay.health.pass")
		_, err = fmt.Fprintln(w, "health OK")
		if err != nil {
			log("relay.health.okFailed error=%s", err)
			return
		}
		r.metric.httpStatusCodes.WithLabelValues("200", req.URL.Path).Inc()
		log("relay.health.finish took=%d", took(start))
	}
}

// If PORT_PPROF is set to anything but an integer, this will silently fail.
func openPProfEndpoint() {
	var (
		port int
		err  error
	)

	if port, err = strconv.Atoi(os.Getenv("PORT_PPROF")); err != nil {
		return
	}

	pprofMux := http.NewServeMux()
	pprofMux.HandleFunc("/debug/pprof/", pprof.Index)
	pprofMux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	pprofMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	pprofMux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	pprofMux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	go func() {
		listenAddr := fmt.Sprintf("localhost:%d", port)
		log("pprof addr=%s", listenAddr)
		err := http.ListenAndServe(listenAddr, pprofMux)
		check(err)
	}()
}

func emitUptime(metric *Metric) {
	start := now()
	for {
		uptime := uint64(time.Since(start).Milliseconds())
		log("relay.emitUptime uptime=%d", uptime)
		metric.emit("server.uptime", uptime)
		time.Sleep(emitUptimeInterval)
	}
}

func server() {
	initLoggingOnce.Do(initLogging)
	port := mustGetEnvInt("PORT")
	log("relay.start port=%d logMessages=%t logEphemeralMessages=%t simulateErrorRate=%d simulateIgnoreRate=%d", port, logMessages, logEphemeralMessages, simulateErrorRate, simulateIgnoreRate)

	metric := newMetric()

	r := newRelay(metric)
	r.connect()
	r.writesEnabled = true
	go r.run()

	// spawn payment watchers
	var ops = []repeat.Operation{
		repeat.Fn(func() error {
			err := r.watchPaymentMade()
			if err != nil {
				log("relay.watchPayemtnMade.error %+v", err)
				return repeat.HintTemporary(err)
			}
			return nil
		}),
		repeat.Fn(func() error {
			err := r.watchEthereumPayments()
			if err != nil {
				log("relay.watchEthereumPayments.error %+v", err)
				return repeat.HintTemporary(err)
			}
			return nil
		}),
		repeat.Fn(func() error {
			err := r.watchErc20Payments()
			if err != nil {
				log("relay.watchErc20Payments.error %+v", err)
				return repeat.HintTemporary(err)
			}
			return nil
		}),
	}
	for _, op := range ops {
		go func(op repeat.Operation) {
			for {
				err := repeat.Repeat(op,
					repeat.LimitMaxTries(10),
					repeat.StopOnSuccess(),
				)
				if err != nil {
					r.metric.counterAdd("relay_watchError_error", 1)
				}
				time.Sleep(ethereumBlockInterval/2 + time.Duration(rand.Intn(1000))*time.Millisecond)
			}
		}(op)
	}

	// open metrics and pprof after relay & ethclient booted
	openPProfEndpoint()
	go metric.connect()

	go emitUptime(metric)

	mux := http.NewServeMux()

	// Public APIs

	for _, v := range networkVersions {
		mux.HandleFunc(fmt.Sprintf("/v%d/sessions", v), sessionsHandleFunc(v, r))
		mux.HandleFunc(fmt.Sprintf("/v%d/enroll_key_card", v), enrollKeyCardHandleFunc(v, r))

		mux.HandleFunc(fmt.Sprintf("/v%d/upload_blob", v), uploadBlobHandleFunc(v, r))
	}

	// Internal engineering APIs
	mux.HandleFunc("/health", healthHandleFunc(r))

	corsOpts := cors.Options{
		AllowedOrigins: []string{"*"},
	}
	if isDevEnv {
		mux.HandleFunc("/testing/discovery", r.ethClient.discoveryHandleFunc)
		corsOpts.Debug = true
	}

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: cors.New(corsOpts).Handler(mux),
	}
	err := srv.ListenAndServe()
	check(err)
}

// CLI

func usage() {
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  relay server\n")
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	cmd := os.Args[1]
	cmdArgs := os.Args[2:]
	if cmd == "server" && len(cmdArgs) == 0 {
		server()
	} else {
		usage()
	}
}
