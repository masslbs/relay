// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

// Package main implements the relay server for a massMarket store
package main

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/sha512"
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
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
)

// Server configuration.
const sessionPingInterval = 5 * time.Second
const sessionKickTimeout = 6 * sessionPingInterval
const sessionLastSeenAtFlushLimit = 30 * time.Second
const sessionLastAckedstoreSeqFlushLimit = 4096
const sessionBufferSizeRefill = limitMaxOutRequests * limitMaxOutBatchSize
const sessionBufferSizeMax = limitMaxOutRequests * limitMaxOutBatchSize * 2
const databaseDebounceInterval = 100 * time.Millisecond
const newEthereumBlockInterval = 5 * time.Second
const tickStatsInterval = 1 * time.Second
const tickBlockThreshold = 50 * time.Millisecond
const memoryStatsInterval = 5 * time.Second
const databaseOpsChanSize = 64 * 1024

const maxItemMedataBytes = 5 * 1024

// const s3SignatureTimeout = 5 * 60 * 24 * time.Minute
const sentryFlushTimeout = 2 * time.Second
const emitUptimeInterval = 10 * time.Second

// set by build script via ldflags
var release = "unset"

// Toggle high-volume log traffic.
var logMessages = false
var logEphemeralMessages = false
var logMetrics = false

// Enable error'd and ignore'd requests to be simulated with env variable.
// Given in integer percents, 0 <= r <= 100.
var simulateErrorRate = 0
var simulateIgnoreRate = 0

var networkVersions = []uint{1}

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
	return "(" + err.Code + "): " + err.Message
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
	Code:    "tooManyConcurrentRequests",
	Message: "Too many concurrent requests sent to server",
}

var alreadyAuthenticatedError = &Error{
	Code:    "alreadyAuthenticated",
	Message: "Already authenticated in a previous message",
}

var notAuthenticatedError = &Error{
	Code:    "notAuthenticated",
	Message: "Must authenticate before sending any other messages",
}

var alreadyConnectedError = &Error{
	Code:    "alreadyConnected",
	Message: "Already connected from this device in another session",
}

var unlinkedKeyCardError = &Error{
	Code:    "unlinkedKeyCard",
	Message: "Key Card was removed from the Store",
}

var notFoundError = &Error{
	Code:    "notFound",
	Message: "Item not found",
}

var simulateError = &Error{
	Code:    "simulated",
	Message: "Error condition simulated for this message",
}

var (
	invalidErrorCode    = "invalid"
	outOfStockErrorCode = "outOfStock"
)

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
	sessionID    requestID
	im           *EventWriteRequest
	newStoreHash []byte
	eventSeq     uint64
	err          *Error
}

// EventPushOp sends an EventPushRequest to the client
type EventPushOp struct {
	sessionID   requestID
	eventStates []*EventState
	err         *Error
}

// CommitCartOp finalizes an open cart by processing a CommitCartRequest.
// As a result, the relay will wait for the incoming transaction before creating a ChangeStock event.
type CommitCartOp struct {
	sessionID       requestID
	im              *CommitCartRequest
	cartFinalizedID eventID
	err             *Error
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
	storeID          eventID
	keyCardPublicKey []byte
	userWallet       common.Address
}

// App/Client Sessions

// Session represents a connection to a client
type Session struct {
	id                requestID
	version           uint
	conn              net.Conn
	messages          chan InMessage
	activeInRequests  *MapRequestIds[time.Time]
	activeOutRequests *SetRequestIDs
	activePushes      *MapRequestIds[SessionOp]
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
		activeInRequests:  NewMapRequestIds[time.Time](),
		activeOutRequests: NewSetRequestIDs(),
		activePushes:      NewMapRequestIds[SessionOp](),
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

func (im *AuthenticateRequest) validate(_ uint) *Error {
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

func (im *ChallengeSolvedRequest) validate(_ uint) *Error {
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
	events := make([]*Event, len(op.eventStates))
	for i, eventState := range op.eventStates {
		eventState.eventID.assert()
		assert(eventState.eventType != "")
		assertOneOfEvent(eventState)
		e := &Event{}
		e.Signature = eventState.signature
		switch eventState.eventType {
		case eventTypeStoreManifest:
			e.Union = &Event_StoreManifest{eventState.storeManifest}
		case eventTypeUpdateManifest:
			e.Union = &Event_UpdateManifest{eventState.updateManifest}
		case eventTypeCreateItem:
			e.Union = &Event_CreateItem{eventState.createItem}
		case eventTypeUpdateItem:
			e.Union = &Event_UpdateItem{eventState.updateItem}
		case eventTypeCreateTag:
			e.Union = &Event_CreateTag{eventState.createTag}
		case eventTypeAddToTag:
			e.Union = &Event_AddToTag{eventState.addToTag}
		case eventTypeRemoveFromTag:
			e.Union = &Event_RemoveFromTag{eventState.removeFromTag}
		case eventTypeRenameTag:
			e.Union = &Event_RenameTag{eventState.renameTag}
		case eventTypeDeleteTag:
			e.Union = &Event_DeleteTag{eventState.deleteTag}
		case eventTypeCreateCart:
			e.Union = &Event_CreateCart{eventState.createCart}
		case eventTypeChangeCart:
			e.Union = &Event_ChangeCart{eventState.changeCart}
		case eventTypeCartFinalized:
			e.Union = &Event_CartFinalized{eventState.cartFinalized}
		case eventTypeCartAbandoned:
			e.Union = &Event_CartAbandoned{eventState.cartAbandoned}
		case eventTypeChangeStock:
			e.Union = &Event_ChangeStock{eventState.changeStock}
		case eventTypeNewKeyCard:
			e.Union = &Event_NewKeyCard{eventState.newKeyCard}
		default:
			panic(fmt.Errorf("unhandled eventType: %s", eventState.eventType))
		}
		events[i] = e
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

func validateUpdateManifest(_ uint, event *UpdateManifest) *Error {
	errs := []*Error{validateEventID(event.EventId, "event_id")}
	switch event.Field {
	case UpdateManifest_MANIFEST_FIELD_DOMAIN:
		strVal, ok := event.Value.(*UpdateManifest_String_)
		if ok {
			errs = append(errs, validateURL(strVal.String_, "domain_value"))
		} else {
			errs = append(errs, &Error{Code: invalidErrorCode, Message: "Invalid value type for domain"})
		}
	case UpdateManifest_MANIFEST_FIELD_PUBLISHED_TAG:
		idVal, ok := event.Value.(*UpdateManifest_TagId)
		if ok {
			errs = append(errs, validateEventID(idVal.TagId, "published_tag"))
		} else {
			errs = append(errs, &Error{Code: invalidErrorCode, Message: "Invalid value type for published_tag"})
		}
	case UpdateManifest_MANIFEST_FIELD_ADD_ERC20:
		val, ok := event.Value.(*UpdateManifest_Erc20Addr)
		if ok {
			errs = append(errs, validateEthAddressBytes(val.Erc20Addr, "erc20_token_addr"))
		} else {
			errs = append(errs, &Error{Code: invalidErrorCode, Message: fmt.Sprintf("Invalid value type for add_erc20 - got %T", event.Value)})
		}
	case UpdateManifest_MANIFEST_FIELD_REMOVE_ERC20:
		val, ok := event.Value.(*UpdateManifest_Erc20Addr)
		if ok {
			errs = append(errs, validateEthAddressBytes(val.Erc20Addr, "erc20_token_addr"))
		} else {
			errs = append(errs, &Error{Code: invalidErrorCode, Message: "Invalid value type for remove_erc20"})
		}
	default:
		errs = append(errs, &Error{Code: invalidErrorCode, Message: "Invalid update field"})
	}
	return coalesce(errs...)
}

func validateCreateItem(_ uint, event *CreateItem) *Error {
	errs := []*Error{
		validateEventID(event.EventId, "event_id"),
		validateDecimalPrice(event.Price, "price"),
	}
	if !json.Valid(event.Metadata) {
		errs = append(errs, &Error{Code: invalidErrorCode, Message: "Invalid metadata"})
	}
	if len(event.Metadata) > maxItemMedataBytes {
		errs = append(errs, &Error{Code: invalidErrorCode, Message: "Too much metadata"})
	}
	return coalesce(errs...)
}

func validateUpdateItem(_ uint, event *UpdateItem) *Error {
	errs := []*Error{
		validateEventID(event.EventId, "event_id"),
		validateEventID(event.ItemId, "item_id"),
	}
	switch event.Field {
	case UpdateItem_ITEM_FIELD_PRICE:
		priceStr, ok := event.Value.(*UpdateItem_Price)
		if !ok {
			errs = append(errs, &Error{Code: invalidErrorCode, Message: "Invalid value type for price"})
		} else {
			errs = append(errs, validateDecimalPrice(priceStr.Price, "price"))
		}
	case UpdateItem_ITEM_FIELD_METADATA:
		v, ok := event.Value.(*UpdateItem_Metadata)
		if !ok {
			errs = append(errs, &Error{Code: invalidErrorCode, Message: "Invalid value type for price"})
		} else if !json.Valid(v.Metadata) {
			errs = append(errs, &Error{Code: invalidErrorCode, Message: "Invalid metadata"})
		} else if len(v.Metadata) > maxItemMedataBytes {
			errs = append(errs, &Error{Code: invalidErrorCode, Message: "Too much metadata"})
		}
	default:
		errs = append(errs, &Error{Code: invalidErrorCode, Message: "Invalid update field"})
	}
	return coalesce(errs...)
}

func validateCreateTag(_ uint, event *CreateTag) *Error {
	return coalesce(
		validateEventID(event.EventId, "event_id"),
		validateString(event.Name, "name", 64),
	)
}

func validateRenameTag(_ uint, event *RenameTag) *Error {
	return coalesce(
		validateEventID(event.EventId, "event_id"),
		validateEventID(event.TagId, "tag_id"),
		validateString(event.Name, "name", 64),
	)
}

func validateDeleteTag(_ uint, event *DeleteTag) *Error {
	return coalesce(
		validateEventID(event.EventId, "event_id"),
		validateEventID(event.TagId, "tag_id"),
	)
}

func validateAddToTag(_ uint, event *AddToTag) *Error {
	return coalesce(
		validateEventID(event.EventId, "event_id"),
		validateEventID(event.TagId, "tag_id"),
		validateEventID(event.ItemId, "item_id"),
	)
}

func validateRemoveFromTag(_ uint, event *RemoveFromTag) *Error {
	return coalesce(
		validateEventID(event.EventId, "event_id"),
		validateEventID(event.TagId, "tag_id"),
		validateEventID(event.ItemId, "item_id"),
	)
}

func validateChangeStock(_ uint, event *ChangeStock) *Error {
	if len(event.ItemIds) != len(event.Diffs) {
		return &Error{Code: invalidErrorCode, Message: "ItemId and Diff must have the same length"}
	}
	for i, item := range event.ItemIds {
		if err := validateEventID(item, fmt.Sprintf("item_id[%d]", i)); err != nil {
			return err
		}
	}
	return nil
}

func validateCreateCart(_ uint, event *CreateCart) *Error {
	return coalesce(
		validateEventID(event.EventId, "event_id"),
	)
}

func validateChangeCart(_ uint, event *ChangeCart) *Error {
	return coalesce(
		validateEventID(event.EventId, "event_id"),
		validateEventID(event.CartId, "cart_id"),
		validateEventID(event.ItemId, "item_id"),
	)
}

func validateCartAbandoned(_ uint, event *CartAbandoned) *Error {
	return validateEventID(event.CartId, "cart_id")
}

func (im *EventWriteRequest) validate(version uint) *Error {
	if err := validateBytes(im.Event.Signature, "signature", signatureBytes); err != nil {
		return err
	}
	var err *Error
	switch union := im.Event.Union.(type) {
	case *Event_StoreManifest:
		err = validateStoreManifest(version, union.StoreManifest)
	case *Event_UpdateManifest:
		err = validateUpdateManifest(version, union.UpdateManifest)
	case *Event_CreateItem:
		err = validateCreateItem(version, union.CreateItem)
	case *Event_UpdateItem:
		err = validateUpdateItem(version, union.UpdateItem)
	case *Event_CreateTag:
		err = validateCreateTag(version, union.CreateTag)
	case *Event_AddToTag:
		err = validateAddToTag(version, union.AddToTag)
	case *Event_RemoveFromTag:
		err = validateRemoveFromTag(version, union.RemoveFromTag)
	case *Event_RenameTag:
		err = validateRenameTag(version, union.RenameTag)
	case *Event_DeleteTag:
		err = validateDeleteTag(version, union.DeleteTag)
	case *Event_ChangeStock:
		err = validateChangeStock(version, union.ChangeStock)
	case *Event_CreateCart:
		err = validateCreateCart(version, union.CreateCart)
	case *Event_ChangeCart:
		err = validateChangeCart(version, union.ChangeCart)
	case *Event_CartFinalized:
		err = &Error{Code: invalidErrorCode, Message: "CartFinalized is not allowed in EventWriteRequest"}
	case *Event_CartAbandoned:
		err = validateCartAbandoned(version, union.CartAbandoned)
	case *Event_NewKeyCard:
		err = &Error{Code: invalidErrorCode, Message: "NewKeyCard is not allowed in EventWriteRequest"}
	default:
		log("eventWriteRequest.validate: unrecognized event type: %T", im.Event.Union)
		return &Error{Code: invalidErrorCode, Message: "Unrecognized event type"}
	}
	if err != nil {
		return err
	}
	return nil
}

func (im *EventWriteRequest) handle(sess *Session) {
	op := &EventWriteOp{sessionID: sess.id, im: im}
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

func (im *CommitCartRequest) validate(_ uint) *Error {
	return validateEventID(im.CartId, "cart_id")
}

func (im *CommitCartRequest) handle(sess *Session) {
	op := &CommitCartOp{sessionID: sess.id, im: im}
	sess.sendDatabaseOp(op)
}

func (op *CommitCartOp) handle(sess *Session) {
	om := op.im.response(op.err).(*CommitCartResponse)
	if op.err == nil {
		om.CartFinalizedId = op.cartFinalizedID
	}
	sess.writeMessage(om)
}

func (im *GetBlobUploadURLRequest) validate(_ uint) *Error {
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
			sess.conn.Close()
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
	eventID   eventID
	eventType eventType

	created struct {
		at                     time.Time
		byDeviceID, byStoreID  requestID
		byNetworkSchemaVersion uint64
	}

	// TODO: change to serverSeq to individual storeSeq for relay2relay sync
	serverSeq uint64

	storeSeq uint64
	acked    bool

	signature []byte
	// one-of
	storeManifest  *StoreManifest
	updateManifest *UpdateManifest

	createItem *CreateItem
	updateItem *UpdateItem

	createTag     *CreateTag
	addToTag      *AddToTag
	removeFromTag *RemoveFromTag
	renameTag     *RenameTag
	deleteTag     *DeleteTag

	createCart    *CreateCart
	changeCart    *ChangeCart
	cartFinalized *CartFinalized
	cartAbandoned *CartAbandoned

	changeStock *ChangeStock

	newKeyCard *NewKeyCard
}

// SessionState represents the state of a client in the database.
type SessionState struct {
	version                  uint
	authChallenge            []byte
	dbWorld                  chan<- RelayOp
	sessionOps               chan SessionOp
	keyCardID                requestID
	keyCardPublicKey         []byte
	storeID                  eventID
	buffer                   []*EventState
	initialStatus            bool
	lastStatusedStoreSeq     uint64
	lastBufferedStoreSeq     uint64
	lastPushedStoreSeq       uint64
	nextPushIndex            int
	lastAckedStoreSeq        uint64
	lastAckedStoreSeqFlushed uint64
	lastSeenAt               time.Time
	lastSeenAtFlushed        time.Time
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
// It combines the intial StoreManifest and all UpdateManifests
type CachedStoreManifest struct {
	CachedMetadata
	inited bool

	storeTokenID   []byte
	domain         string
	publishedTagID eventID
	acceptedErc20s map[common.Address]struct{}
}

func (current *CachedStoreManifest) update(union *Event, meta CachedMetadata) {
	switch union.Union.(type) {
	case *Event_StoreManifest:
		assert(!current.inited)
		sm := union.GetStoreManifest()
		current.CachedMetadata = meta
		current.storeTokenID = sm.StoreTokenId
		current.domain = sm.Domain
		current.publishedTagID = sm.PublishedTagId
		current.acceptedErc20s = make(map[common.Address]struct{})
		current.inited = true
	case *Event_UpdateManifest:
		um := union.GetUpdateManifest()
		if um.Field == UpdateManifest_MANIFEST_FIELD_DOMAIN {
			current.domain = um.Value.(*UpdateManifest_String_).String_
		} else if um.Field == UpdateManifest_MANIFEST_FIELD_PUBLISHED_TAG {
			current.publishedTagID = um.Value.(*UpdateManifest_TagId).TagId
		} else if um.Field == UpdateManifest_MANIFEST_FIELD_ADD_ERC20 {
			erc20 := um.Value.(*UpdateManifest_Erc20Addr).Erc20Addr
			current.acceptedErc20s[common.Address(erc20)] = struct{}{}
		} else if um.Field == UpdateManifest_MANIFEST_FIELD_REMOVE_ERC20 {
			erc20 := um.Value.(*UpdateManifest_Erc20Addr).Erc20Addr
			delete(current.acceptedErc20s, common.Address(erc20))
		} else {
			panic(fmt.Sprintf("unhandled update field: %d", um.Field))
		}
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

func (current *CachedItem) update(union *Event, meta CachedMetadata) {
	var err error
	switch union.Union.(type) {
	case *Event_CreateItem:
		assert(!current.inited)
		ci := union.GetCreateItem()
		current.CachedMetadata = meta
		current.itemID = ci.EventId
		current.price, _, err = apd.NewFromString(ci.Price)
		check(err)
		current.metadata = ci.Metadata
		current.inited = true
	case *Event_UpdateItem:
		ui := union.GetUpdateItem()
		if ui.Field == UpdateItem_ITEM_FIELD_PRICE {
			current.price, _, err = apd.NewFromString(ui.GetPrice())
			check(err)
		}
		if ui.Field == UpdateItem_ITEM_FIELD_METADATA {
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
	items   *SetEventIds
}

func (current *CachedTag) update(evt *Event, meta CachedMetadata) {
	if current.items == nil && !current.inited {
		current.items = NewSetEventIds()
	}
	switch evt.Union.(type) {
	case *Event_CreateTag:
		assert(!current.inited)
		current.CachedMetadata = meta
		ct := evt.GetCreateTag()
		current.name = ct.Name
		current.tagID = ct.EventId
		current.inited = true
	case *Event_AddToTag:
		at := evt.GetAddToTag()
		current.items.Add(at.ItemId)
	case *Event_RemoveFromTag:
		rft := evt.GetRemoveFromTag()
		current.items.Delete(rft.ItemId)
	case *Event_RenameTag:
		rt := evt.GetRenameTag()
		current.name = rt.Name
	case *Event_DeleteTag:
		current.deleted = true
	default:
		panic(fmt.Sprintf("unhandled event type: %T", evt.Union))
	}
}

// CachedCart is the latest reduction of a Cart.
// It combines the initial CreateCart and all ChangeCart events
type CachedCart struct {
	CachedMetadata
	inited    bool
	finalized bool
	abandoned bool
	payed     bool

	purchaseAddr common.Address

	txHash common.Hash

	cartID eventID
	items  *MapEventIds[int32]
}

func (current *CachedCart) update(evt *Event, meta CachedMetadata) {
	if current.items == nil && !current.inited {
		current.items = NewMapEventIds[int32]()
	}
	switch evt.Union.(type) {
	case *Event_CreateCart:
		assert(!current.inited)
		ct := evt.GetCreateCart()
		current.CachedMetadata = meta
		current.cartID = ct.EventId
		current.inited = true
	case *Event_ChangeCart:
		atc := evt.GetChangeCart()
		count := current.items.Get(atc.ItemId)
		count += atc.Quantity
		current.items.Set(atc.ItemId, count)
	case *Event_CartFinalized:
		cf := evt.GetCartFinalized()
		current.purchaseAddr = common.Address(cf.PurchaseAddr)
		// TODO: other fields?
		current.finalized = true
	case *Event_ChangeStock:
		current.payed = true
		cs := evt.GetChangeStock()
		current.txHash = common.Hash(cs.TxHash)
	case *Event_CartAbandoned:
		current.abandoned = true
	default:
		panic(fmt.Sprintf("unhandled event type: %T", evt.Union))

	}
}

// CachedStock is the latest reduction of a Store's stock.
// It combines all ChangeStock events
type CachedStock struct {
	CachedMetadata

	inventory *MapEventIds[int32]
}

func (current *CachedStock) update(evt *Event, _ CachedMetadata) {
	cs := evt.GetChangeStock()
	if cs == nil {
		return
	}
	if current.inventory == nil {
		current.inventory = NewMapEventIds[int32]()
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
	update(*Event, CachedMetadata)
}

// SeqPair helps with writing events to the database
type SeqPair struct {
	lastUsedStoreSeq    uint64
	lastWrittenStoreSeq uint64
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
	sessionIdsToSessionStates *MapRequestIds[*SessionState]
	opsInternal               chan RelayOp
	ops                       chan RelayOp

	blobUploadTokens   map[string]struct{}
	blobUploadTokensMu *sync.Mutex

	// persistence
	syncTx               pgx.Tx
	queuedEventInserts   []*EventInsert
	storeIdsToStoreSeqs  *MapEventIds[*SeqPair]
	lastUsedServerSeq    uint64
	lastWrittenServerSeq uint64

	// caching layer
	storeManifestsByStoreID *ReductionLoader[*CachedStoreManifest]
	itemsByItemID           *ReductionLoader[*CachedItem]
	tagsByTagID             *ReductionLoader[*CachedTag]
	cartsByCartID           *ReductionLoader[*CachedCart]
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

	r.sessionIdsToSessionStates = NewMapRequestIds[*SessionState]()
	r.opsInternal = make(chan RelayOp)

	r.ops = make(chan RelayOp, databaseOpsChanSize)
	r.storeIdsToStoreSeqs = NewMapEventIds[*SeqPair]()

	storeFieldFn := func(evt *Event, meta CachedMetadata) eventID {
		return meta.createdByStoreID
	}
	r.storeManifestsByStoreID = newReductionLoader[*CachedStoreManifest](r, storeFieldFn, []eventType{eventTypeStoreManifest, eventTypeUpdateManifest}, "createdByStoreId")
	itemsFieldFn := func(evt *Event, meta CachedMetadata) eventID {
		switch evt.Union.(type) {
		case *Event_CreateItem:
			return evt.GetCreateItem().EventId
		case *Event_UpdateItem:
			return evt.GetUpdateItem().ItemId
		}
		return nil
	}
	r.itemsByItemID = newReductionLoader[*CachedItem](r, itemsFieldFn, []eventType{eventTypeCreateItem, eventTypeUpdateItem}, "itemId")
	tagsFieldFn := func(evt *Event, meta CachedMetadata) eventID {
		switch evt.Union.(type) {
		case *Event_CreateTag:
			return evt.GetCreateTag().EventId
		case *Event_AddToTag:
			return evt.GetAddToTag().TagId
		case *Event_RemoveFromTag:
			return evt.GetRemoveFromTag().TagId
		case *Event_RenameTag:
			return evt.GetRenameTag().TagId
		case *Event_DeleteTag:
			return evt.GetDeleteTag().TagId
		}
		return nil
	}
	r.tagsByTagID = newReductionLoader[*CachedTag](r, tagsFieldFn, []eventType{
		eventTypeCreateTag,
		eventTypeAddToTag,
		eventTypeRemoveFromTag,
		eventTypeRenameTag,
		eventTypeDeleteTag,
	}, "tagId")

	cartsFieldFn := func(evt *Event, meta CachedMetadata) eventID {
		switch evt.Union.(type) {
		case *Event_CreateCart:
			return evt.GetCreateCart().EventId
		case *Event_ChangeCart:
			return evt.GetChangeCart().CartId
		case *Event_CartFinalized:
			return evt.GetCartFinalized().CartId
		case *Event_ChangeStock:
			cs := evt.GetChangeStock()
			if len(cs.CartId) != 0 {
				return cs.CartId
			}
		case *Event_CartAbandoned:
			return evt.GetCartAbandoned().CartId
		}
		return nil
	}
	r.cartsByCartID = newReductionLoader[*CachedCart](r, cartsFieldFn, []eventType{
		eventTypeCreateCart,
		eventTypeChangeCart,
		eventTypeCartFinalized,
		eventTypeChangeStock,
		eventTypeCartAbandoned,
	}, "cartId")

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
func (db *SessionState) sendOp(op RelayOp) {
	select {
	case db.dbWorld <- op:
	default:
		panic(fmt.Errorf("sessionState.sendDatabaseOp.blocked: %+v", op))
	}
}

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
		defer tx.Rollback(ctx)
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

func (r *Relay) assertCursors(sessionID requestID, seqPair *SeqPair, sessionState *SessionState) {
	err := r.checkCursors(sessionID, seqPair, sessionState)
	check(err)
}

func (r *Relay) checkCursors(_ requestID, seqPair *SeqPair, sessionState *SessionState) error {
	if seqPair.lastUsedStoreSeq < seqPair.lastWrittenStoreSeq {
		return fmt.Errorf("cursor lastUsedStoreSeq(%d) < lastWrittenStoreSeq(%d)", seqPair.lastUsedStoreSeq, seqPair.lastWrittenStoreSeq)
	}
	if seqPair.lastWrittenStoreSeq < sessionState.lastStatusedStoreSeq {
		return fmt.Errorf("cursor: lastWrittenStoreSeq(%d) < lastStatusedStoreSeq(%d)", seqPair.lastWrittenStoreSeq, sessionState.lastStatusedStoreSeq)
	}
	if sessionState.lastStatusedStoreSeq < sessionState.lastBufferedStoreSeq {
		return fmt.Errorf("cursor: lastStatusedStoreSeq(%d) < lastBufferedStoreSeq(%d)", sessionState.lastStatusedStoreSeq, sessionState.lastBufferedStoreSeq)
	}
	if sessionState.lastBufferedStoreSeq < sessionState.lastPushedStoreSeq {
		return fmt.Errorf("cursor: lastBufferedStoreSeq(%d) < lastPushedStoreSeq(%d)", sessionState.lastBufferedStoreSeq, sessionState.lastPushedStoreSeq)
	}
	if sessionState.lastPushedStoreSeq < sessionState.lastAckedStoreSeq {
		return fmt.Errorf("cursor: lastPushedStoreSeq(%d) < lastAckedStoreSeq(%d)", sessionState.lastPushedStoreSeq, sessionState.lastAckedStoreSeq)
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

func (r *Relay) hydrateStores(storeIds *SetEventIds) {
	start := now()
	ctx := context.Background()
	novelStoreIds := NewSetEventIds()
	storeIds.All(func(storeId eventID) {
		if !r.storeIdsToStoreSeqs.Has(storeId) {
			novelStoreIds.Add(storeId)
		}
	})
	if sz := novelStoreIds.Size(); sz > 0 {
		novelStoreIds.All(func(storeId eventID) {
			seqPair := &SeqPair{}
			r.storeIdsToStoreSeqs.Set(storeId, seqPair)
		})
		for _, novelStoreIdsSubslice := range novelStoreIds.Slice().subslice(256) {
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
				seqPair := r.storeIdsToStoreSeqs.MustGet(storeID)
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
		log("relay.hydrateUsers users=%d novelUsers=%d elapsed=%d", storeIds.Size(), novelStoreIds.Size(), elapsed)
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
	query := fmt.Sprintf(`select serverSeq, storeSeq, eventId, eventType, createdByKeyCardId, createdByStoreId, createdAt, createdByNetworkSchemaVersion, signature,
	storeTokenId, domain, publishedTagId, manifestUpdateField, string, addr, referencedEventId, itemId, price,
	metadata, itemUpdateField, name, tagId, cartId, quantity, itemIds, changes, txHash,
    purchaseAddr, erc20Addr, subTotal, salesTax, total, totalInCrypto
from events where %s order by serverSeq asc`, whereFragment)
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
			serverSeq               uint64
			storeSeq                uint64
			eID                     eventID
			eventType               eventType
			createdByKeyCardID      requestID
			createdByStoreID        eventID
			createdAt               time.Time
			createdByNetworkVersion uint16
			signature               []byte
			storeTokenID            *[]byte
			domain                  *string
			publishedTagID          *[]byte
			manifestUpdateField     *UpdateManifest_ManifestField
			stringVal               *string
			addrVal                 *[]byte
			referencedEventID       *[]byte
			itemID                  *[]byte
			price                   *string
			metadata                *[]byte
			itemUpdateField         *UpdateItem_ItemField
			name                    *string
			tagID                   *[]byte
			cartID                  *[]byte
			quantity                *int32
			itemIds                 *[][]byte
			changes                 *[]int32
			txHash                  *[]byte
			purchaseAddr            *[]byte
			erc20Addr               *[]byte
			subTotal                *string
			salesTax                *string
			total                   *string
			totalInCrypto           *string
		)
		err := rows.Scan(&serverSeq, &storeSeq, &eID, &eventType, &createdByKeyCardID, &createdByStoreID, &createdAt, &createdByNetworkVersion, &signature,
			&storeTokenID, &domain, &publishedTagID, &manifestUpdateField, &stringVal, &addrVal, &referencedEventID, &itemID, &price,
			&metadata, &itemUpdateField, &name, &tagID, &cartID, &quantity, &itemIds, &changes, &txHash,
			&purchaseAddr, &erc20Addr, &subTotal, &salesTax, &total, &totalInCrypto,
		)
		check(err)
		m := CachedMetadata{
			createdByStoreID:        createdByStoreID,
			storeSeq:                storeSeq,
			createdByKeyCardID:      createdByKeyCardID,
			createdByNetworkVersion: createdByNetworkVersion,
			createdAt:               uint64(createdAt.Unix()),
			serverSeq:               serverSeq,
		}
		var e = &Event{}
		e.Signature = signature
		switch eventType {
		case eventTypeStoreManifest:
			assert(storeTokenID != nil)
			assert(domain != nil)
			assert(publishedTagID != nil)
			sm := &StoreManifest{
				EventId:        eID,
				StoreTokenId:   *storeTokenID,
				Domain:         *domain,
				PublishedTagId: *publishedTagID,
			}
			e.Union = &Event_StoreManifest{StoreManifest: sm}
		case eventTypeUpdateManifest:
			assert(manifestUpdateField != nil)
			um := &UpdateManifest{
				EventId: eID,
				Field:   *manifestUpdateField,
			}
			if *manifestUpdateField == UpdateManifest_MANIFEST_FIELD_DOMAIN {
				assert(stringVal != nil)
				um.Value = &UpdateManifest_String_{String_: *stringVal}
			}
			if *manifestUpdateField == UpdateManifest_MANIFEST_FIELD_PUBLISHED_TAG {
				assert(referencedEventID != nil)
				um.Value = &UpdateManifest_TagId{TagId: *referencedEventID}
			} else if *manifestUpdateField == UpdateManifest_MANIFEST_FIELD_ADD_ERC20 || *manifestUpdateField == UpdateManifest_MANIFEST_FIELD_REMOVE_ERC20 {
				assert(addrVal != nil)
				um.Value = &UpdateManifest_Erc20Addr{Erc20Addr: *addrVal}
			}
			e.Union = &Event_UpdateManifest{UpdateManifest: um}
		case eventTypeCreateItem:
			assert(itemID != nil)
			assert(price != nil)
			assert(metadata != nil)
			ci := &CreateItem{
				EventId:  eID,
				Price:    *price,
				Metadata: *metadata,
			}
			e.Union = &Event_CreateItem{CreateItem: ci}
		case eventTypeUpdateItem:
			assert(itemID != nil)
			assert(itemUpdateField != nil)
			ui := &UpdateItem{
				EventId: eID,
				ItemId:  *itemID,
				Field:   *itemUpdateField,
			}
			if *itemUpdateField == UpdateItem_ITEM_FIELD_PRICE {
				assert(price != nil)
				ui.Value = &UpdateItem_Price{Price: *price}
			}
			if *itemUpdateField == UpdateItem_ITEM_FIELD_METADATA {
				assert(metadata != nil)
				ui.Value = &UpdateItem_Metadata{Metadata: *metadata}
			}
			e.Union = &Event_UpdateItem{UpdateItem: ui}
		case eventTypeCreateTag:
			assert(tagID != nil)
			assert(name != nil)
			ct := &CreateTag{
				EventId: eID,
				Name:    *name,
			}
			e.Union = &Event_CreateTag{CreateTag: ct}
		case eventTypeAddToTag:
			assert(tagID != nil)
			assert(itemID != nil)
			at := &AddToTag{
				EventId: eID,
				TagId:   *tagID,
				ItemId:  *itemID,
			}
			e.Union = &Event_AddToTag{AddToTag: at}
		case eventTypeRemoveFromTag:
			assert(tagID != nil)
			assert(itemID != nil)
			rft := &RemoveFromTag{
				EventId: eID,
				TagId:   *tagID,
				ItemId:  *itemID,
			}
			e.Union = &Event_RemoveFromTag{RemoveFromTag: rft}
		case eventTypeRenameTag:
			assert(tagID != nil)
			assert(name != nil)
			rt := &RenameTag{
				EventId: eID,
				TagId:   *tagID,
				Name:    *name,
			}
			e.Union = &Event_RenameTag{RenameTag: rt}
		case eventTypeDeleteTag:
			assert(tagID != nil)
			dt := &DeleteTag{
				EventId: eID,
				TagId:   *tagID,
			}
			e.Union = &Event_DeleteTag{DeleteTag: dt}
		case eventTypeChangeStock:
			assert(itemIds != nil)
			assert(changes != nil)
			assert(len(*itemIds) == len(*changes))
			cs := &ChangeStock{
				EventId: eID,
				ItemIds: *itemIds,
				Diffs:   *changes,
			}
			if cartID != nil {
				cs.CartId = *cartID
				assert(txHash != nil)
				cs.TxHash = *txHash
			}
			e.Union = &Event_ChangeStock{ChangeStock: cs}
		case eventTypeCreateCart:
			assert(cartID != nil)
			cc := &CreateCart{
				EventId: eID,
			}
			e.Union = &Event_CreateCart{CreateCart: cc}
		case eventTypeChangeCart:
			assert(cartID != nil)
			assert(itemID != nil)
			assert(quantity != nil)
			atc := &ChangeCart{
				EventId:  eID,
				CartId:   *cartID,
				ItemId:   *itemID,
				Quantity: *quantity,
			}
			e.Union = &Event_ChangeCart{ChangeCart: atc}
		case eventTypeCartFinalized:
			assert(cartID != nil)
			assert(purchaseAddr != nil)
			assert(subTotal != nil)
			assert(salesTax != nil)
			assert(total != nil)
			assert(totalInCrypto != nil)
			cf := &CartFinalized{
				EventId:       eID,
				CartId:        *cartID,
				PurchaseAddr:  *purchaseAddr,
				SubTotal:      *subTotal,
				SalesTax:      *salesTax,
				Total:         *total,
				TotalInCrypto: *totalInCrypto,
			}
			if erc20Addr != nil {
				cf.Erc20Addr = *erc20Addr
			}
			e.Union = &Event_CartFinalized{CartFinalized: cf}
		case eventTypeCartAbandoned:
			assert(cartID != nil)
			ca := &CartAbandoned{
				EventId: eID,
				CartId:  *cartID,
			}
			e.Union = &Event_CartAbandoned{CartAbandoned: ca}
		default:
			panic(fmt.Errorf("unrecognized type: %s", eventType))
		}
		events = append(events, EventInsert{CachedMetadata: m, evt: e})
	}
	check(rows.Err())
	return events
}

// EventInsert is a struct that represents an event to be inserted into the database
type EventInsert struct {
	CachedMetadata
	evt *Event
}

func newEventInsert(evt *Event, meta CachedMetadata) *EventInsert {
	meta.createdAt = uint64(now().Unix())
	return &EventInsert{
		CachedMetadata: meta,
		evt:            evt,
	}
}

func (r *Relay) writeEvent(evt *Event, cm CachedMetadata) {
	assert(r.writesEnabled)

	nextServerSeq := r.lastUsedServerSeq + 1
	cm.serverSeq = nextServerSeq
	r.lastUsedServerSeq = nextServerSeq

	seqPair := r.storeIdsToStoreSeqs.MustGet(cm.createdByStoreID)
	cm.storeSeq = seqPair.lastUsedStoreSeq + 1
	seqPair.lastUsedStoreSeq = cm.storeSeq

	insert := newEventInsert(evt, cm)
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

var dbEntryInsertColumns = []string{
	"eventType", "eventId", "createdByKeyCardId", "createdByStoreId", "storeSeq", "createdAt", "createdByNetworkSchemaVersion", "serverSeq", "signature",
	"storeTokenId", "domain", "publishedTagId", "manifestUpdateField", "string", "addr", "referencedEventId",
	"itemId", "price", "metadata", "itemUpdateField",
	"name", "tagId",
	"cartId", "quantity", "itemIds", "changes", "txHash",
	"purchaseAddr", "erc20Addr", "subTotal", "salesTax", "total", "totalInCrypto",
	"userWallet", "cardPublicKey"}

func (r *Relay) flushEvents() {
	if len(r.queuedEventInserts) == 0 {
		return
	}
	assert(r.writesEnabled)
	log("relay.flushEvents.start entries=%d", len(r.queuedEventInserts))
	start := now()

	eventTuples := make([][]any, len(r.queuedEventInserts))
	for i, ei := range r.queuedEventInserts {
		eventTuples[i] = formInsert(ei.evt, ei.CachedMetadata)
	}
	assert(r.lastWrittenServerSeq < r.lastUsedServerSeq)
	insertedEntryRows, conflictedEntryRows := r.bulkInsert("events", dbEntryInsertColumns, eventTuples)
	for _, row := range insertedEntryRows {
		rowServerSeq := row[7].(uint64)
		assert(r.lastWrittenServerSeq < rowServerSeq)
		assert(rowServerSeq <= r.lastUsedServerSeq)
		r.lastWrittenServerSeq = rowServerSeq
		rowStoreID := row[3].(eventID)
		rowStoreSeq := row[4].(uint64)
		storeSeqPair := r.storeIdsToStoreSeqs.MustGet(rowStoreID)
		assert(storeSeqPair.lastWrittenStoreSeq < rowStoreSeq)
		assert(rowStoreSeq <= storeSeqPair.lastUsedStoreSeq)
		storeSeqPair.lastWrittenStoreSeq = rowStoreSeq
	}
	assert(r.lastWrittenServerSeq <= r.lastUsedServerSeq)

	r.queuedEventInserts = nil
	log("relay.flushEvents.finish insertedEntries=%d conflictedEntries=%d elapsed=%d", len(insertedEntryRows), len(conflictedEntryRows), took(start))
}

// Loader is an interface for all loaders.
// Loaders represent the read-through cache layer.
type Loader interface {
	applyEvent(*EventInsert)
}

type fieldFn func(*Event, CachedMetadata) eventID

// ReductionLoader is a struct that represents a loader for a specific event type
type ReductionLoader[T CachedEvent] struct {
	db            *Relay
	fieldFn       fieldFn
	loaded        *MapEventIds[T]
	whereFragment string
}

func newReductionLoader[T CachedEvent](r *Relay, fn fieldFn, pgTypes []eventType, pgField string) *ReductionLoader[T] {
	sl := &ReductionLoader[T]{}
	sl.db = r
	sl.fieldFn = fn
	sl.loaded = NewMapEventIds[T]()
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
	assert(!r.sessionIdsToSessionStates.Has(op.sessionID))
	assert(op.sessionVersion != 0)
	assert(op.sessionOps != nil)
	logS(op.sessionID, "relay.startOp.start")
	sessionState := &SessionState{
		dbWorld:    r.ops,
		version:    op.sessionVersion,
		sessionOps: op.sessionOps,
		buffer:     make([]*EventState, 0),
	}
	r.sessionIdsToSessionStates.Set(op.sessionID, sessionState)
	r.lastSeenAtTouch(sessionState)
}

func (op *StopOp) process(r *Relay) {
	sessionState, sessionExists := r.sessionIdsToSessionStates.GetHas(op.sessionID)
	logS(op.sessionID, "relay.stopOp.start exists=%t", sessionExists)
	if sessionExists {
		r.sessionIdsToSessionStates.Delete(op.sessionID)
		r.sendSessionOp(sessionState, op)
	}
}

func (op *HeartbeatOp) process(r *Relay) {
	sessionState := r.sessionIdsToSessionStates.Get(op.sessionID)
	if sessionState == nil {
		logS(op.sessionID, "relay.heartbeatOp.drain")
		return
	}

	r.lastSeenAtTouch(sessionState)
}

func (op *AuthenticateOp) process(r *Relay) {
	// Make sure the session isn't gone or already authenticated.
	sessionState := r.sessionIdsToSessionStates.Get(op.sessionID)
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
	iter := r.sessionIdsToSessionStates.Iter()

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
	crand.Read(ch)

	op.challenge = ch
	sessionState.authChallenge = ch
	sessionState.keyCardID = keyCardID
	r.sendSessionOp(sessionState, op)
	logS(op.sessionID, "relay.authenticateOp.finish elapsed=%d", took(authenticateOpStart))
}

func (op *ChallengeSolvedOp) process(r *Relay) {
	logS(op.sessionID, "relay.challengeSolvedOp.start")
	challengeSolvedOpStart := now()

	sessionState := r.sessionIdsToSessionStates.Get(op.sessionID)
	if sessionState == nil {
		logS(op.sessionID, "relay.challengeSolvedOp.drain")
		return
	} else if sessionState.keyCardID == nil {
		logS(op.sessionID, "relay.challengeSolvedOp.invalidSessionState")
		op.err = &Error{Code: invalidErrorCode, Message: "authentication not started"}
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
	var dbLastAckedstoreSeq uint64
	var dbLastVersion int
	instant := now()
	sessionState.lastSeenAt = instant
	sessionState.lastSeenAtFlushed = instant

	// Index: keyCards(id)
	query = `select unlinkedAt, lastAckedstoreSeq, lastVersion from keyCards where id = $1`
	err = r.connPool.QueryRow(ctx, query, sessionState.keyCardID).Scan(&dbUnlinkedAt, &dbLastAckedstoreSeq, &dbLastVersion)
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
	sessionState.lastStatusedStoreSeq = dbLastAckedstoreSeq
	sessionState.lastBufferedStoreSeq = dbLastAckedstoreSeq
	sessionState.lastPushedStoreSeq = dbLastAckedstoreSeq
	sessionState.lastAckedStoreSeq = dbLastAckedstoreSeq
	sessionState.lastAckedStoreSeqFlushed = dbLastAckedstoreSeq
	query = `update keyCards set lastVersion = $1, lastSeenAt = $2 where id = $3`
	_, err = r.connPool.Exec(ctx, query, sessionState.version, sessionState.lastSeenAt, sessionState.keyCardID)
	check(err)

	// update sessionState
	sessionState.storeID = storeID
	sessionState.initialStatus = false
	sessionState.nextPushIndex = 0
	sessionState.keyCardPublicKey = keyCardPublicKey

	// Establish store seq.
	r.hydrateStores(NewSetEventIds(storeID))
	seqPair, has := r.storeIdsToStoreSeqs.GetHas(sessionState.storeID)
	assert(has)

	// Verify we have valid seq cursor relationships. We will check this whenever we move a cursor.
	err = r.checkCursors(op.sessionID, seqPair, sessionState)
	logS(op.sessionID, "relay.challengeSolvedOp.checkCursors lastWrittenStoreSeq=%d lastUsedstoreSeq=%d lastStatusedstoreSeq=%d lastBufferedstoreSeq=%d lastPushedstoreSeq=%d lastAckedstoreSeq=%d error=%t",
		seqPair.lastWrittenStoreSeq, seqPair.lastUsedStoreSeq, sessionState.lastStatusedStoreSeq, sessionState.lastBufferedStoreSeq, sessionState.lastPushedStoreSeq, sessionState.lastAckedStoreSeq, err != nil)
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
	log("relay.storeRootHash storeId=%s", storeID)

	storeManifest, has := r.storeManifestsByStoreID.get(storeID)
	assertWithMessage(has, "no manifest for storeId")

	// 1. the manifest
	manifestHash := sha3.NewLegacyKeccak256()
	manifestHash.Write(storeManifest.storeTokenID)
	fmt.Fprint(manifestHash, storeManifest.domain)
	manifestHash.Write(storeManifest.publishedTagID)
	log("relay.storeRootHash manifest=%x", manifestHash.Sum(nil))

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
		log("relay.storeRootHash published=%x", publishedItemsHash.Sum(nil))
	}

	// TODO: other tags

	// 3. the stock
	stockHash := sha3.NewLegacyKeccak256()
	stock, has := r.stockByStoreID.get(storeID)
	//assertWithMessage(has, "stock unavailable")
	if has {
		// TODO: we should probably always have a stock that's just empty
		log("relay.storeRootHash.hasStock storeId=%s", storeID)
		// see above
		stockIds := stock.inventory.Keys()
		sort.Sort(stockIds)

		for _, id := range stockIds {
			count := stock.inventory.MustGet(id)
			stockHash.Write(id)
			fmt.Fprintf(stockHash, "%d", count)
		}
	}
	log("relay.storeRootHash stock=%x", stockHash.Sum(nil))

	// final root hash of the three nodes
	rootHash := sha3.NewLegacyKeccak256()
	rootHash.Write(manifestHash.Sum(nil))
	rootHash.Write(publishedItemsHash.Sum(nil))
	rootHash.Write(stockHash.Sum(nil))

	digest := rootHash.Sum(nil)
	took := took(start)
	log("relay.storeRootHash.hash digest=%x took=%d", digest, took)
	r.metric.counterAdd("storeRootHash_took", float64(took))
	return digest
}

func (op *EventWriteOp) process(r *Relay) {
	sessionID := op.sessionID
	requestID := op.im.RequestId
	sessionState := r.sessionIdsToSessionStates.Get(sessionID)
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
	if err := r.ethClient.eventVerify(op.im.Event, sessionState.keyCardPublicKey); err != nil {
		logSR("relay.eventWriteOp.verifyEventFailed err=%s", sessionID, requestID, err.Error())
		op.err = &Error{Code: invalidErrorCode, Message: "invalid signature"}
		r.sendSessionOp(sessionState, op)
		return
	}

	// check and validate write
	e := op.im.Event
	meta := newMetadata(sessionState.keyCardID, sessionState.storeID, uint16(sessionState.version))
	if err := r.checkWrite(e, meta, sessionState); err != nil {
		logSR("relay.eventWriteOp.checkEventFailed code=%s msg=%s", sessionID, requestID, err.Code, err.Message)
		op.err = err
		r.sendSessionOp(sessionState, op)
		return
	}

	// update store
	r.beginSyncTransaction()
	r.writeEvent(e, meta)
	r.commitSyncTransaction()

	// compute resulting hash
	storeSeq := r.storeIdsToStoreSeqs.MustGet(sessionState.storeID)
	if storeSeq.lastUsedStoreSeq >= 3 {
		hash := r.storeRootHash(sessionState.storeID)
		op.newStoreHash = hash
	}
	op.eventSeq = storeSeq.lastWrittenStoreSeq

	r.sendSessionOp(sessionState, op)
}

func (r *Relay) checkWrite(union *Event, m CachedMetadata, sess *SessionState) *Error {
	switch tv := union.Union.(type) {
	case *Event_StoreManifest:
		_, exists := r.storeManifestsByStoreID.get(m.createdByStoreID)
		if exists {
			return &Error{Code: invalidErrorCode, Message: "store already exists"}
		}
	case *Event_UpdateManifest:
		_, exists := r.storeManifestsByStoreID.get(m.createdByStoreID)
		if !exists {
			return notFoundError
		}

		// this feels like a validation step but we dont have access to the relay there
		if tv.UpdateManifest.Field == UpdateManifest_MANIFEST_FIELD_ADD_ERC20 {
			callOpts := &bind.CallOpts{
				Pending: false,
				From:    r.ethClient.wallet,
				Context: context.Background(),
			}

			erc20TokenAddr := tv.UpdateManifest.GetErc20Addr()

			tokenCaller, err := NewERC20Caller(common.Address(erc20TokenAddr), r.ethClient)
			if err != nil {
				return &Error{Code: invalidErrorCode, Message: "failed to create token caller"}
			}
			decimalCount, err := tokenCaller.Decimals(callOpts)
			if err != nil {
				return &Error{Code: invalidErrorCode, Message: fmt.Sprintf("failed to get token decimals: %s", err)}
			}
			if decimalCount < 1 || decimalCount > 18 {
				return &Error{Code: invalidErrorCode, Message: "invalid token decimals"}
			}
			symbol, err := tokenCaller.Symbol(callOpts)
			if err != nil {
				return &Error{Code: invalidErrorCode, Message: fmt.Sprintf("failed to get token symbol: %s", err)}
			}
			if symbol == "" {
				return &Error{Code: invalidErrorCode, Message: "invalid token symbol"}
			}

			tokenName, err := tokenCaller.Name(callOpts)
			if err != nil {
				return &Error{Code: invalidErrorCode, Message: fmt.Sprintf("failed to get token name: %s", err)}
			}
			if tokenName == "" {
				return &Error{Code: invalidErrorCode, Message: "invalid token name"}
			}

		}
	case *Event_CreateItem:
		evt := union.GetCreateItem()
		_, itemExists := r.itemsByItemID.get(evt.EventId)
		if itemExists {
			return &Error{Code: invalidErrorCode, Message: "item already exists"}
		}
	case *Event_UpdateItem:
		evt := union.GetUpdateItem()
		item, itemExists := r.itemsByItemID.get(evt.ItemId)
		if !itemExists {
			return notFoundError
		}
		if !item.createdByStoreID.Equal(sess.storeID) { // not allow to alter data from other stores
			return notFoundError
		}
	case *Event_CreateTag:
		evt := union.GetCreateTag()
		_, tagExists := r.tagsByTagID.get(evt.EventId)
		if tagExists {
			return &Error{Code: invalidErrorCode, Message: "tag already exists"}
		}
	case *Event_AddToTag:
		evt := union.GetAddToTag()
		tag, tagExists := r.tagsByTagID.get(evt.TagId)
		if !tagExists {
			return notFoundError
		}
		if !tag.createdByStoreID.Equal(sess.storeID) { // not allow to alter data from other stores
			return notFoundError
		}
		item, itemExists := r.itemsByItemID.get(evt.ItemId)
		if !itemExists {
			return notFoundError
		}
		if !item.createdByStoreID.Equal(sess.storeID) { // not allow to alter data from other stores
			return notFoundError
		}
	case *Event_RemoveFromTag:
		evt := union.GetRemoveFromTag()
		tag, tagExists := r.tagsByTagID.get(evt.TagId)
		if !tagExists {
			return notFoundError
		}
		if !tag.createdByStoreID.Equal(sess.storeID) { // not allow to alter data from other stores
			return notFoundError
		}
		item, itemExists := r.itemsByItemID.get(evt.ItemId)
		if !itemExists {
			return notFoundError
		}
		if !item.createdByStoreID.Equal(sess.storeID) { // not allow to alter data from other stores
			return notFoundError
		}
	case *Event_RenameTag:
		evt := union.GetRenameTag()
		tag, tagExists := r.tagsByTagID.get(evt.TagId)
		if !tagExists {
			return notFoundError
		}
		if !tag.createdByStoreID.Equal(sess.storeID) { // not allow to alter data from other stores
			return notFoundError
		}
	case *Event_DeleteTag:
		evt := union.GetDeleteTag()
		tag, tagExists := r.tagsByTagID.get(evt.TagId)
		if !tagExists {
			return notFoundError
		}
		if !tag.createdByStoreID.Equal(sess.storeID) { // not allow to alter data from other stores
			return notFoundError
		}
	case *Event_ChangeStock:
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
					return &Error{Code: outOfStockErrorCode, Message: "not enough stock"}
				}
			}
		}
	case *Event_CreateCart:
		evt := union.GetCreateCart()
		_, cartExists := r.cartsByCartID.get(evt.EventId)
		if cartExists {
			return &Error{Code: invalidErrorCode, Message: "cart already exists"}
		}
	case *Event_ChangeCart:
		evt := union.GetChangeCart()
		cart, cartExists := r.cartsByCartID.get(evt.CartId)
		if !cartExists {
			return notFoundError
		}
		if cart.finalized {
			return &Error{Code: invalidErrorCode, Message: "cart already finalized"}
		}
		if !cart.createdByStoreID.Equal(sess.storeID) { // not allow to alter data from other stores
			return notFoundError
		}
		item, itemExists := r.itemsByItemID.get(evt.ItemId)
		if !itemExists {
			return notFoundError
		}
		if !item.createdByStoreID.Equal(sess.storeID) { // not allow to alter data from other stores
			return notFoundError
		}
		stock, has := r.stockByStoreID.get(m.createdByStoreID)
		if !has {
			return &Error{Code: invalidErrorCode, Message: "not enough stock"}
		}
		// TODO: improve locking / also respect inStock in other carts
		inStock, has := stock.inventory.GetHas(evt.ItemId)
		if !has || inStock < evt.Quantity {
			return &Error{Code: invalidErrorCode, Message: "not enough stock"}
		}
		inCart := cart.items.Get(evt.ItemId)
		if evt.Quantity < 0 && inCart+evt.Quantity < 0 {
			return &Error{Code: invalidErrorCode, Message: "not enough items in cart"}
		}
	case *Event_CartAbandoned:
		evt := union.GetCartAbandoned()
		cart, cartExists := r.cartsByCartID.get(evt.CartId)
		if !cartExists {
			return notFoundError
		}
		if !cart.finalized {
			return &Error{Code: invalidErrorCode, Message: "cart is not finalized"}
		}
	default:
		panic(fmt.Errorf("eventWritesOp.checkWrite.unrecognizeType eventType=%T", union.Union))
	}
	return nil
}

func (op *EventPushOp) process(r *Relay) {
	sessionState := r.sessionIdsToSessionStates.Get(op.sessionID)
	if sessionState == nil {
		logS(op.sessionID, "relay.eventPushOp.drain")
		return
	}
	r.lastSeenAtTouch(sessionState)
	for _, entryState := range op.eventStates {
		entryState.acked = true
	}
}

func (op *CommitCartOp) process(r *Relay) {
	ctx := context.Background()
	sessionID := op.sessionID
	requestID := op.im.RequestId
	sessionState := r.sessionIdsToSessionStates.Get(sessionID)
	if sessionState == nil {
		logS(sessionID, "relay.commitCartOp.drain")
		return
	} else if sessionState.keyCardID == nil {
		logSR("relay.commitCartOp.notAuthenticated", sessionID, requestID)
		op.err = notAuthenticatedError
		r.sendSessionOp(sessionState, op)
		return
	}
	start := now()
	logSR("relay.commitCartOp.process", sessionID, requestID)
	r.lastSeenAtTouch(sessionState)

	// sum up cart content
	decimalCtx := apd.BaseContext.WithPrecision(20)
	fiatSubtotal := new(apd.Decimal)
	cart, has := r.cartsByCartID.get(op.im.CartId)
	if !has {
		op.err = notFoundError
		r.sendSessionOp(sessionState, op)
		return
	}
	if cart.finalized {
		op.err = &Error{Code: invalidErrorCode, Message: "cart is already finalized"}
		r.sendSessionOp(sessionState, op)
		return
	}
	if cart.items.Size() == 0 {
		op.err = &Error{Code: invalidErrorCode, Message: "cart is empty"}
		r.sendSessionOp(sessionState, op)
		return
	}

	stock, has := r.stockByStoreID.get(sessionState.storeID)
	if !has {
		op.err = &Error{Code: invalidErrorCode, Message: "not enough stock"}
		r.sendSessionOp(sessionState, op)
		return
	}

	store, has := r.storeManifestsByStoreID.get(sessionState.storeID)
	if !has {
		op.err = &Error{Code: invalidErrorCode, Message: "store not found"}
		r.sendSessionOp(sessionState, op)
		return
	}

	// get all other carts that haven't been paid yet
	otherCartRows, err := r.connPool.Query(ctx, `select cartId from payments where
	createdByStoreId = $1 and
	cartId != $2 and
	cartPayedAt is null`, sessionState.storeID, op.im.CartId)
	check(err)
	otherCartIds := NewMapEventIds[*CachedCart]()
	for otherCartRows.Next() {
		var otherCartID eventID
		check(otherCartRows.Scan(&otherCartID))
		otherCart, has := r.cartsByCartID.get(otherCartID)
		assert(has)
		otherCartIds.Set(otherCartID, otherCart)
	}
	check(otherCartRows.Err())

	// for convenience, sum up all items in the  other carts
	otherCartItemQuantities := NewMapEventIds[int32]()
	otherCartIds.AllWithBreak(func(_ eventID, cart *CachedCart) bool {
		if cart.abandoned {
			return false
		}
		cart.items.AllWithBreak(func(itemId eventID, quantity int32) bool {
			current := otherCartItemQuantities.Get(itemId)
			current += quantity
			otherCartItemQuantities.Set(itemId, current)
			return false
		})
		return false
	})

	// iterate over this cart
	cart.items.AllWithBreak(func(itemId eventID, quantity int32) bool {
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
			op.err = &Error{Code: outOfStockErrorCode, Message: "not enough stock"}
			return true
		}

		usedInOtherCarts := otherCartItemQuantities.Get(itemId)
		if stockItems-usedInOtherCarts < quantity {
			op.err = &Error{Code: outOfStockErrorCode, Message: "not enough stock"}
			return true
		}

		decQuantityt := apd.New(int64(quantity), 0)

		// total += quantity * price
		quantTimesPrice := new(apd.Decimal)
		decimalCtx.Mul(quantTimesPrice, decQuantityt, item.price)
		decimalCtx.Add(fiatSubtotal, fiatSubtotal, quantTimesPrice)
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

	// create payment address for cart content
	var (
		bigTotal = new(big.Int)

		proof       common.Address // TODO
		receiptHash [32]byte

		etherCurrency = common.Address{} // ERC20 would be address(1)

		usignErc20     = len(op.im.Erc20Addr) == 20
		erc20TokenAddr common.Address
	)

	callOpts := &bind.CallOpts{
		Pending: false,
		From:    r.ethClient.wallet,
		Context: context.Background(),
	}

	inBaseTokens := new(apd.Decimal)
	if usignErc20 {
		etherCurrency = common.Address{1}
		erc20TokenAddr = common.Address(op.im.Erc20Addr)
		var has bool
		_, has = store.acceptedErc20s[erc20TokenAddr]
		if !has {
			logSR("relay.commitCartOp.noSuchAcceptedErc20s addr=%s", sessionID, requestID, erc20TokenAddr.Hex())
			op.err = &Error{Code: invalidErrorCode, Message: "erc20 not accepted"}
			r.sendSessionOp(sessionState, op)
			return
		}
		inErc20 := r.prices.FromFiatToERC20(fiatTotal, erc20TokenAddr)

		// get decimals count of this contract
		// TODO: since this is a contract constant we could cache it when adding the token
		tokenCaller, err := NewERC20Caller(erc20TokenAddr, r.ethClient)
		if err != nil {
			logSR("relay.commitCartOp.failedToCreateERC20Caller err=%s", sessionID, requestID, err.Error())
			op.err = &Error{Code: invalidErrorCode, Message: "failed to create erc20 caller"}
			r.sendSessionOp(sessionState, op)
			return
		}
		decimalCount, err := tokenCaller.Decimals(callOpts)
		if err != nil {
			logSR("relay.commitCartOp.erc20DecimalsFailed err=%s", sessionID, requestID, err.Error())
			op.err = &Error{Code: invalidErrorCode, Message: "failed to establish contract decimals"}
			r.sendSessionOp(sessionState, op)
			return
		}

		decimalCtx.Mul(inBaseTokens, inErc20, apd.New(1, int32(decimalCount)))
	} else {
		// convert decimal in USD to ethereum
		inEth := r.prices.FromFiatToCoin(fiatTotal)
		decimalCtx.Mul(inBaseTokens, inEth, apd.New(1, 18))
	}

	bigTotal.SetString(inBaseTokens.Text('f'), 10)

	// TODO: actual proof. for now we just use the hash of the internal cartId as a nonce
	hasher := sha512.New512_256()
	copy(receiptHash[:], hasher.Sum(cart.cartID))

	bigStoreTokenID := new(big.Int).SetBytes(store.storeTokenID)
	ownerAddr, err := r.ethClient.stores.OwnerOf(callOpts, bigStoreTokenID)
	if err != nil {
		op.err = &Error{Code: invalidErrorCode, Message: "failed to establish store owner"}
		r.sendSessionOp(sessionState, op)
		return
	}

	purchaseAddr, err := r.ethClient.paymentFactory.GetPaymentAddress(callOpts, ownerAddr, proof, bigTotal, etherCurrency, receiptHash)
	if err != nil {
		op.err = &Error{Code: invalidErrorCode, Message: "failed to create payment address"}
		r.sendSessionOp(sessionState, op)
		return
	}
	blockNo, err := r.ethClient.BlockNumber(context.Background())
	if err != nil {
		op.err = &Error{Code: invalidErrorCode, Message: "failed to get block number"}
		r.sendSessionOp(sessionState, op)
		return
	}
	log("relay.commitCartOp.paymentAddress addr=%x total=%s currentBlock=%d", purchaseAddr, bigTotal.String(), blockNo)

	// mark cart as finalized by creating the event and updating payments table
	var (
		cf CartFinalized
		w  PaymentWaiter
	)
	cf.EventId = newEventID()
	cf.CartId = cart.cartID
	cf.PurchaseAddr = purchaseAddr.Bytes()
	cf.TotalInCrypto = bigTotal.String()
	cf.SubTotal = roundPrice(fiatSubtotal).Text('f')
	cf.SalesTax = roundPrice(salesTax).Text('f')
	cf.Total = roundPrice(fiatTotal).Text('f')

	op.cartFinalizedID = cf.EventId

	w.waiterID = newRequestID()
	w.cartID = op.im.CartId
	w.cartFinalizedAt = now()
	w.purchaseAddr = purchaseAddr
	w.lastBlockNo.SetInt64(int64(blockNo))
	w.coinsTotal.Set(bigTotal)
	w.coinsPayed.SetInt64(0)

	if usignErc20 {
		cf.Erc20Addr = erc20TokenAddr[:]
		w.erc20TokenAddr = &erc20TokenAddr
	}

	cfMetadata := newMetadata(relayKeyCardID, sessionState.storeID, 1)
	cfEvent := &Event{Union: &Event_CartFinalized{&cf}}
	err = r.ethClient.eventSign(cfEvent)
	if err != nil {
		logSR("relay.commitCartOp.eventSignFailed err=%s", sessionID, requestID, err)
		op.err = &Error{Code: invalidErrorCode, Message: "interal server error"}
		r.sendSessionOp(sessionState, op)
		return
	}
	r.beginSyncTransaction()
	r.writeEvent(cfEvent, cfMetadata)

	seqPair := r.storeIdsToStoreSeqs.MustGet(sessionState.storeID)
	// TODO: we could join against events instead for some of these fields but let's not disrupt this now
	const insertPaymentWaiterQuery = `insert into payments (waiterId, storeSeqNo, createdByStoreId, cartId, cartFinalizedAt, purchaseAddr, lastBlockNo, coinsPayed, coinsTotal, erc20TokenAddr)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`
	_, err = r.syncTx.Exec(ctx, insertPaymentWaiterQuery,
		w.waiterID, seqPair.lastWrittenStoreSeq, cart.createdByStoreID, w.cartID, w.cartFinalizedAt, w.purchaseAddr.Bytes(), w.lastBlockNo, w.coinsPayed, w.coinsTotal, w.erc20TokenAddr)
	check(err)

	r.commitSyncTransaction()

	logSR("relay.commitCartOp.finish took=%d", sessionID, requestID, took(start))
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
	sessionState := r.sessionIdsToSessionStates.Get(sessionID)
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
		crand.Read(buf[:])
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
	uploadURL.Path = "/v1/upload_blob"
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

	r.hydrateStores(NewSetEventIds(op.storeID))

	evt := &Event{
		Union: &Event_NewKeyCard{NewKeyCard: &NewKeyCard{
			EventId:        newEventID(),
			CardPublicKey:  op.keyCardPublicKey,
			UserWalletAddr: op.userWallet[:],
		}},
	}

	err := r.ethClient.eventSign(evt)
	check(err)

	r.beginSyncTransaction()
	meta := newMetadata(relayKeyCardID, op.storeID, 1)
	r.writeEvent(evt, meta)
	r.commitSyncTransaction()
	log("db.KeyCardEnrolledOp.finish storeId=%s took=%d", op.storeID, took(start))
}

// Database processing

func formInsert(e *Event, meta CachedMetadata) []interface{} {
	switch e.Union.(type) {
	case *Event_StoreManifest:
		sm := e.GetStoreManifest()
		return []interface{}{
			eventTypeStoreManifest,       // eventType
			sm.EventId,                   // eventId
			meta.createdByKeyCardID,      // createdByKeyCardId
			meta.createdByStoreID,        // createdByStoreId
			meta.storeSeq,                // storeSeq
			now(),                        // createdAt
			meta.createdByNetworkVersion, // createdByNetworkSchemaVersion
			meta.serverSeq,               // serverSeq
			e.Signature,                  // signature
			sm.StoreTokenId,              // storeTokenId
			sm.Domain,                    // domain
			sm.PublishedTagId,            // publishedTagId
			nil,                          // manifestUpdateField
			nil,                          // string
			nil,                          // addr
			nil,                          // referencedEventId
			nil,                          // itemId
			nil,                          // price
			nil,                          // metadata
			nil,                          // itemUpdateField
			nil,                          // name
			nil,                          // tagId
			nil,                          // cartId
			nil,                          // quantity
			nil,                          // itemIds
			nil,                          // changes
			nil,                          // txHash
			nil,                          // purchaseAddr
			nil,                          // erc20Addr
			nil,                          // subTotal
			nil,                          // salesTax
			nil,                          // total
			nil,                          // totalInCrypto
			nil,                          // userWallet
			nil,                          // cardPublicKey
		}

	case *Event_UpdateManifest:
		um := e.GetUpdateManifest()
		var stringVal *string
		var tagIDVal, addrVal *[]byte
		if v, ok := um.Value.(*UpdateManifest_String_); ok {
			stringVal = &v.String_
		}
		if v, ok := um.Value.(*UpdateManifest_TagId); ok {
			tagIDVal = &v.TagId
		}
		if v, ok := um.Value.(*UpdateManifest_Erc20Addr); ok {
			addrVal = &v.Erc20Addr
		}
		return []interface{}{
			eventTypeUpdateManifest,      // eventType
			um.EventId,                   // eventId
			meta.createdByKeyCardID,      // createdByKeyCardId
			meta.createdByStoreID,        // createdByStoreId
			meta.storeSeq,                // storeSeq
			now(),                        // createdAt
			meta.createdByNetworkVersion, // createdByNetworkSchemaVersion
			meta.serverSeq,               // serverSeq
			e.Signature,                  // signature
			nil,                          // storeTokenId
			nil,                          // domain
			nil,                          // publishedTagId
			um.Field,                     // manifestUpdateField
			stringVal,                    // string
			addrVal,                      // addr
			tagIDVal,                     // referencedEventId
			nil,                          // itemId
			nil,                          // price
			nil,                          // metadata
			nil,                          // itemUpdateField
			nil,                          // name
			nil,                          // tagId
			nil,                          // cartId
			nil,                          // quantity
			nil,                          // itemIds
			nil,                          // changes
			nil,                          // txHash
			nil,                          // purchaseAddr
			nil,                          // erc20Addr
			nil,                          // subTotal
			nil,                          // salesTax
			nil,                          // total
			nil,                          // totalInCrypto
			nil,                          // userWallet
			nil,                          // cardPublicKey
		}

	case *Event_CreateItem:
		ci := e.GetCreateItem()
		return []interface{}{
			eventTypeCreateItem,          // eventType
			ci.EventId,                   // eventId
			meta.createdByKeyCardID,      // createdByKeyCardId
			meta.createdByStoreID,        // createdByStoreId
			meta.storeSeq,                // storeSeq
			now(),                        // createdAt
			meta.createdByNetworkVersion, // createdByNetworkSchemaVersion
			meta.serverSeq,               // serverSeq
			e.Signature,                  // signature
			nil,                          // storeTokenId
			nil,                          // domain
			nil,                          // publishedTagId
			nil,                          // manifestUpdateField
			nil,                          // string
			nil,                          // addr
			nil,                          // referencedEventId
			ci.EventId,                   // itemId
			ci.Price,                     // price
			ci.Metadata,                  // metadata
			nil,                          // itemUpdateField
			nil,                          // name
			nil,                          // tagId
			nil,                          // cartId
			nil,                          // quantity
			nil,                          // itemIds
			nil,                          // changes
			nil,                          // txHash
			nil,                          // purchaseAddr
			nil,                          // erc20Addr
			nil,                          // subTotal
			nil,                          // salesTax
			nil,                          // total
			nil,                          // totalInCrypto
			nil,                          // userWallet
			nil,                          // cardPublicKey
		}

	case *Event_UpdateItem:
		ui := e.GetUpdateItem()
		var price *string
		var metadata *[]byte
		if v, ok := ui.Value.(*UpdateItem_Metadata); ok {
			metadata = &v.Metadata
		}
		if v, ok := ui.Value.(*UpdateItem_Price); ok {
			price = &v.Price
		}
		return []interface{}{
			eventTypeUpdateItem,          // eventType
			ui.EventId,                   // eventId
			meta.createdByKeyCardID,      // createdByKeyCardId
			meta.createdByStoreID,        // createdByStoreId
			meta.storeSeq,                // storeSeq
			now(),                        // createdAt
			meta.createdByNetworkVersion, // createdByNetworkSchemaVersion
			meta.serverSeq,               // serverSeq
			e.Signature,                  // signature
			nil,                          // storeTokenId
			nil,                          // domain
			nil,                          // publishedTagId
			nil,                          // manifestUpdateField
			nil,                          // string
			nil,                          // addr
			nil,                          // referencedEventId
			ui.ItemId,                    // itemId
			price,                        // price
			metadata,                     // metadata
			ui.Field,                     // itemUpdateField
			nil,                          // name
			nil,                          // tagId
			nil,                          // cartId
			nil,                          // quantity
			nil,                          // itemIds
			nil,                          // changes
			nil,                          // txHash
			nil,                          // purchaseAddr
			nil,                          // erc20Addr
			nil,                          // subTotal
			nil,                          // salesTax
			nil,                          // total
			nil,                          // totalInCrypto
			nil,                          // userWallet
			nil,                          // cardPublicKey
		}

	case *Event_CreateTag:
		ct := e.GetCreateTag()
		return []interface{}{
			eventTypeCreateTag,           // eventType
			ct.EventId,                   // eventId
			meta.createdByKeyCardID,      // createdByKeyCardId
			meta.createdByStoreID,        // createdByStoreId
			meta.storeSeq,                // storeSeq
			now(),                        // createdAt
			meta.createdByNetworkVersion, // createdByNetworkSchemaVersion
			meta.serverSeq,               // serverSeq
			e.Signature,                  // signature
			nil,                          // storeTokenId
			nil,                          // domain
			nil,                          // publishedTagId
			nil,                          // manifestUpdateField
			nil,                          // string
			nil,                          // addr
			nil,                          // referencedEventId
			nil,                          // itemId
			nil,                          // price
			nil,                          // metadata
			nil,                          // itemUpdateField
			ct.Name,                      // name
			ct.EventId,                   // tagId
			nil,                          // cartId
			nil,                          // quantity
			nil,                          // itemIds
			nil,                          // changes
			nil,                          // txHash
			nil,                          // purchaseAddr
			nil,                          // erc20Addr
			nil,                          // subTotal
			nil,                          // salesTax
			nil,                          // total
			nil,                          // totalInCrypto
			nil,                          // userWallet
			nil,                          // cardPublicKey
		}

	case *Event_AddToTag:
		att := e.GetAddToTag()
		return []interface{}{
			eventTypeAddToTag,            // eventType
			att.EventId,                  // eventId
			meta.createdByKeyCardID,      // createdByKeyCardId
			meta.createdByStoreID,        // createdByStoreId
			meta.storeSeq,                // storeSeq
			now(),                        // createdAt
			meta.createdByNetworkVersion, // createdByNetworkSchemaVersion
			meta.serverSeq,               // serverSeq
			e.Signature,                  // signature
			nil,                          // storeTokenId
			nil,                          // domain
			nil,                          // publishedTagId
			nil,                          // manifestUpdateField
			nil,                          // string
			nil,                          // addr
			nil,                          // referencedEventId
			att.ItemId,                   // itemId
			nil,                          // price
			nil,                          // metadata
			nil,                          // itemUpdateField
			nil,                          // name
			att.TagId,                    // tagId
			nil,                          // cartId
			nil,                          // quantity
			nil,                          // itemIds
			nil,                          // changes
			nil,                          // txHash
			nil,                          // purchaseAddr
			nil,                          // erc20Addr
			nil,                          // subTotal
			nil,                          // salesTax
			nil,                          // total
			nil,                          // totalInCrypto
			nil,                          // userWallet
			nil,                          // cardPublicKey
		}

	case *Event_RemoveFromTag:
		rft := e.GetRemoveFromTag()
		return []interface{}{
			eventTypeRemoveFromTag,       // eventType
			rft.EventId,                  // eventId
			meta.createdByKeyCardID,      // createdByKeyCardId
			meta.createdByStoreID,        // createdByStoreId
			meta.storeSeq,                // storeSeq
			now(),                        // createdAt
			meta.createdByNetworkVersion, // createdByNetworkSchemaVersion
			meta.serverSeq,               // serverSeq
			e.Signature,                  // signature
			nil,                          // storeTokenId
			nil,                          // domain
			nil,                          // publishedTagId
			nil,                          // manifestUpdateField
			nil,                          // string
			nil,                          // addr
			nil,                          // referencedEventId
			rft.ItemId,                   // itemId
			nil,                          // price
			nil,                          // metadata
			nil,                          // itemUpdateField
			nil,                          // name
			rft.TagId,                    // tagId
			nil,                          // cartId
			nil,                          // quantity
			nil,                          // itemIds
			nil,                          // changes
			nil,                          // txHash
			nil,                          // purchaseAddr
			nil,                          // erc20Addr
			nil,                          // subTotal
			nil,                          // salesTax
			nil,                          // total
			nil,                          // totalInCrypto
			nil,                          // userWallet
			nil,                          // cardPublicKey
		}

	case *Event_RenameTag:
		rnt := e.GetRenameTag()
		return []interface{}{
			eventTypeRenameTag,           // eventType
			rnt.EventId,                  // eventId
			meta.createdByKeyCardID,      // createdByKeyCardId
			meta.createdByStoreID,        // createdByStoreId
			meta.storeSeq,                // storeSeq
			now(),                        // createdAt
			meta.createdByNetworkVersion, // createdByNetworkSchemaVersion
			meta.serverSeq,               // serverSeq
			e.Signature,                  // signature
			nil,                          // storeTokenId
			nil,                          // domain
			nil,                          // publishedTagId
			nil,                          // manifestUpdateField
			nil,                          // string
			nil,                          // addr
			nil,                          // referencedEventId
			nil,                          // itemId
			nil,                          // price
			nil,                          // metadata
			nil,                          // itemUpdateField
			rnt.Name,                     // name
			rnt.TagId,                    // tagId
			nil,                          // cartId
			nil,                          // quantity
			nil,                          // itemIds
			nil,                          // changes
			nil,                          // txHash
			nil,                          // purchaseAddr
			nil,                          // erc20Addr
			nil,                          // subTotal
			nil,                          // salesTax
			nil,                          // total
			nil,                          // totalInCrypto
			nil,                          // userWallet
			nil,                          // cardPublicKey
		}

	case *Event_DeleteTag:
		dt := e.GetDeleteTag()
		return []interface{}{
			eventTypeDeleteTag,           // eventType
			dt.EventId,                   // eventId
			meta.createdByKeyCardID,      // createdByKeyCardId
			meta.createdByStoreID,        // createdByStoreId
			meta.storeSeq,                // storeSeq
			now(),                        // createdAt
			meta.createdByNetworkVersion, // createdByNetworkSchemaVersion
			meta.serverSeq,               // serverSeq
			e.Signature,                  // signature
			nil,                          // storeTokenId
			nil,                          // domain
			nil,                          // publishedTagId
			nil,                          // manifestUpdateField
			nil,                          // string
			nil,                          // addr
			nil,                          // referencedEventId
			nil,                          // itemId
			nil,                          // price
			nil,                          // metadata
			nil,                          // itemUpdateField
			nil,                          // name
			dt.TagId,                     // tagId
			nil,                          // cartId
			nil,                          // quantity
			nil,                          // itemIds
			nil,                          // changes
			nil,                          // txHash
			nil,                          // purchaseAddr
			nil,                          // erc20Addr
			nil,                          // subTotal
			nil,                          // salesTax
			nil,                          // total
			nil,                          // totalInCrypto
			nil,                          // userWallet
			nil,                          // cardPublicKey
		}

	case *Event_CreateCart:
		cc := e.GetCreateCart()
		return []interface{}{
			eventTypeCreateCart,          // eventType
			cc.EventId,                   // eventId
			meta.createdByKeyCardID,      // createdByKeyCardId
			meta.createdByStoreID,        // createdByStoreId
			meta.storeSeq,                // storeSeq
			now(),                        // createdAt
			meta.createdByNetworkVersion, // createdByNetworkSchemaVersion
			meta.serverSeq,               // serverSeq
			e.Signature,                  // signature
			nil,                          // storeTokenId
			nil,                          // domain
			nil,                          // publishedTagId
			nil,                          // manifestUpdateField
			nil,                          // string
			nil,                          // addr
			nil,                          // referencedEventId
			nil,                          // itemId
			nil,                          // price
			nil,                          // metadata
			nil,                          // itemUpdateField
			nil,                          // name
			nil,                          // tagId
			cc.EventId,                   // cartId
			nil,                          // quantity
			nil,                          // itemIds
			nil,                          // changes
			nil,                          // txHash
			nil,                          // purchaseAddr
			nil,                          // erc20Addr
			nil,                          // subTotal
			nil,                          // salesTax
			nil,                          // total
			nil,                          // totalInCrypto
			nil,                          // userWallet
			nil,                          // cardPublicKey
		}

	case *Event_ChangeCart:
		atc := e.GetChangeCart()
		return []interface{}{
			eventTypeChangeCart,          // eventType
			atc.EventId,                  // eventId
			meta.createdByKeyCardID,      // createdByKeyCardId
			meta.createdByStoreID,        // createdByStoreId
			meta.storeSeq,                // storeSeq
			now(),                        // createdAt
			meta.createdByNetworkVersion, // createdByNetworkSchemaVersion
			meta.serverSeq,               // serverSeq
			e.Signature,                  // signature
			nil,                          // storeTokenId
			nil,                          // domain
			nil,                          // publishedTagId
			nil,                          // manifestUpdateField
			nil,                          // string
			nil,                          // addr
			nil,                          // referencedEventId
			atc.ItemId,                   // itemId
			nil,                          // price
			nil,                          // metadata
			nil,                          // itemUpdateField
			nil,                          // name
			nil,                          // tagId
			atc.CartId,                   // cartId
			atc.Quantity,                 // quantity
			nil,                          // itemIds
			nil,                          // changes
			nil,                          // txHash
			nil,                          // purchaseAddr
			nil,                          // erc20Addr
			nil,                          // subTotal
			nil,                          // salesTax
			nil,                          // total
			nil,                          // totalInCrypto
			nil,                          // userWallet
			nil,                          // cardPublicKey
		}

	case *Event_ChangeStock:
		cs := e.GetChangeStock()
		itemIds := cs.ItemIds
		changes := cs.Diffs
		var optCartID *[]byte
		if checkEventID(cs.CartId) {
			optCartID = &cs.CartId
		}
		return []interface{}{
			eventTypeChangeStock,         // eventType
			cs.EventId,                   // eventId
			meta.createdByKeyCardID,      // createdByKeyCardId
			meta.createdByStoreID,        // createdByStoreId
			meta.storeSeq,                // storeSeq
			now(),                        // createdAt
			meta.createdByNetworkVersion, // createdByNetworkSchemaVersion
			meta.serverSeq,               // serverSeq
			e.Signature,                  // signature
			nil,                          // storeTokenId
			nil,                          // domain
			nil,                          // publishedTagId
			nil,                          // manifestUpdateField
			nil,                          // string
			nil,                          // addr
			nil,                          // referencedEventId
			nil,                          // itemId
			nil,                          // price
			nil,                          // metadata
			nil,                          // itemUpdateField
			nil,                          // name
			nil,                          // tagId
			optCartID,                    // cartId
			nil,                          // quantity
			itemIds,                      // itemIds
			changes,                      // changes
			cs.TxHash,                    // txHash
			nil,                          // purchaseAddr
			nil,                          // erc20Addr
			nil,                          // subTotal
			nil,                          // salesTax
			nil,                          // total
			nil,                          // totalInCrypto
			nil,                          // userWallet
			nil,                          // cardPublicKey
		}
	case *Event_CartFinalized:
		cf := e.GetCartFinalized()
		var erc20Addr *[]byte
		if len(cf.Erc20Addr) == 20 {
			erc20Addr = &cf.Erc20Addr
		}
		return []interface{}{
			eventTypeCartFinalized,       // eventType
			cf.EventId,                   // eventId
			meta.createdByKeyCardID,      // createdByKeyCardId
			meta.createdByStoreID,        // createdByStoreId
			meta.storeSeq,                // storeSeq
			now(),                        // createdAt
			meta.createdByNetworkVersion, // createdByNetworkSchemaVersion
			meta.serverSeq,               // serverSeq
			e.Signature,                  // signature
			nil,                          // storeTokenId
			nil,                          // domain
			nil,                          // publishedTagId
			nil,                          // manifestUpdateField
			nil,                          // string
			nil,                          // addr
			nil,                          // referencedEventId
			nil,                          // itemId
			nil,                          // price
			nil,                          // metadata
			nil,                          // itemUpdateField
			nil,                          // name
			nil,                          // tagId
			cf.CartId,                    // cartId
			nil,                          // quantity
			nil,                          // itemIds
			nil,                          // changes
			nil,                          // txHash
			cf.PurchaseAddr,              // purchaseAddr
			erc20Addr,                    // erc20Addr
			cf.SubTotal,                  // subTotal
			cf.SalesTax,                  // salesTax
			cf.Total,                     // total
			cf.TotalInCrypto,             // totalInCrypto
			nil,                          // userWallet
			nil,                          // cardPublicKey
		}

	case *Event_CartAbandoned:
		ca := e.GetCartAbandoned()
		return []interface{}{
			eventTypeCartAbandoned,       // eventType
			ca.EventId,                   // eventId
			meta.createdByKeyCardID,      // createdByKeyCardId
			meta.createdByStoreID,        // createdByStoreId
			meta.storeSeq,                // storeSeq
			now(),                        // createdAt
			meta.createdByNetworkVersion, // createdByNetworkSchemaVersion
			meta.serverSeq,               // serverSeq
			e.Signature,                  // signature
			nil,                          // storeTokenId
			nil,                          // domain
			nil,                          // publishedTagId
			nil,                          // manifestUpdateField
			nil,                          // string
			nil,                          // addr
			nil,                          // referencedEventId
			nil,                          // itemId
			nil,                          // price
			nil,                          // metadata
			nil,                          // itemUpdateField
			nil,                          // name
			nil,                          // tagId
			ca.CartId,                    // cartId
			nil,                          // quantity
			nil,                          // itemIds
			nil,                          // changes
			nil,                          // txHash
			nil,                          // purchaseAddr
			nil,                          // erc20Addr
			nil,                          // subTotal
			nil,                          // salesTax
			nil,                          // total
			nil,                          // totalInCrypto
			nil,                          // userWallet
			nil,                          // cardPublicKey
		}

	case *Event_NewKeyCard:
		nkc := e.GetNewKeyCard()
		return []interface{}{
			eventTypeNewKeyCard,          // eventType
			nkc.EventId,                  // eventId
			meta.createdByKeyCardID,      // createdByKeyCardId
			meta.createdByStoreID,        // createdByStoreId
			meta.storeSeq,                // storeSeq
			now(),                        // createdAt
			meta.createdByNetworkVersion, // createdByNetworkSchemaVersion
			meta.serverSeq,               // serverSeq
			e.Signature,                  // signature
			nil,                          // storeTokenId
			nil,                          // domain
			nil,                          // publishedTagId
			nil,                          // manifestUpdateField
			nil,                          // string
			nil,                          // addr
			nil,                          // referencedEventId
			nil,                          // itemId
			nil,                          // price
			nil,                          // metadata
			nil,                          // itemUpdateField
			nil,                          // name
			nil,                          // tagId
			nil,                          // cartId
			nil,                          // quantity
			nil,                          // itemIds
			nil,                          // changes
			nil,                          // txHash
			nil,                          // purchaseAddr
			nil,                          // erc20Addr
			nil,                          // subTotal
			nil,                          // salesTax
			nil,                          // total
			nil,                          // totalInCrypto
			nkc.UserWalletAddr,           // userWallet
			nkc.CardPublicKey,            // cardPublicKey
		}

		/*
			case Foo:
				ce := e.Get()
				return []interface{}{
					eventTypeUpdateManifest,      // eventType
					ce.EventId,                   // eventId
					meta.createdByKeyCardID,      // createdByKeyCardId
					meta.createdByStoreID,        // createdByStoreId
					meta.storeSeq,                // storeSeq
					now(),                        // createdAt
					meta.createdByNetworkVersion, // createdByNetworkSchemaVersion
					meta.serverSeq,               // serverSeq
					e.Signature,                  // signature
					nil,                          // storeTokenId
					nil,                          // domain
					nil,                          // publishedTagId
					nil,                          // manifestUpdateField
					nil,                          // string
					nil,                          // addr
					nil,                          // referencedEventId
					nil,                          // itemId
					nil,                          // price
					nil,                          // metadata
					nil,                          // itemUpdateField
					nil,                          // name
					nil,                          // tagId
					nil,                          // cartId
					nil,                          // quantity
					nil,                          // itemIds
					nil,                          // changes
					nil,                          // txHash
					nil,                          // purchaseAddr
					nil,                          // erc20Addr
					nil,                          // subTotal
					nil,                          // salesTax
					nil,                          // total
					nil,                          // totalInCrypto
					nil,                          // userWallet
					nil,                          // cardPublicKey
				}
		*/

	default:
		panic(fmt.Errorf("formInsert.unrecognizeType eventType=%T", e.Union))
	}
}

func (r *Relay) debounceSessions() {
	// Process each session.
	// Only log if there is substantial activity because this is polling constantly and usually a no-op.
	start := now()
	ctx := context.Background()

	r.sessionIdsToSessionStates.All(func(sessionId requestID, sessionState *SessionState) {
		// Kick the session if we haven't received any recent messages from it, including ping responses.
		if time.Since(sessionState.lastSeenAt) > sessionKickTimeout {
			r.metric.emit("sessions.kick", 1)
			logS(sessionId, "relay.debounceSessions.kick")
			op := &StopOp{sessionID: sessionId}
			sessionState.sendOp(op)
			return
		}

		// Don't try to do anything else if the session isn't even authenticated yet.
		if sessionState.storeID == nil {
			return
		}

		// If the session is authenticated, we can get user info.
		seqPair := r.storeIdsToStoreSeqs.MustGet(sessionState.storeID)
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
			assert(entryState.storeSeq > sessionState.lastAckedStoreSeq)
			if i == 0 {
				advancedFrom = sessionState.lastAckedStoreSeq
			}
			sessionState.lastAckedStoreSeq = entryState.storeSeq
			advancedTo = entryState.storeSeq
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
		if !sessionState.initialStatus || sessionState.lastStatusedStoreSeq < seqPair.lastWrittenStoreSeq {
			syncStatusStart := now()
			op := &SyncStatusOp{sessionID: sessionId}
			// Index: events(createdByStoreId, storeSeq)
			query := `select count(*) from events e where createdByStoreId = $1
				and storeSeq > $2
				and createdByKeyCardId != $3`
			err := r.connPool.QueryRow(ctx, query, sessionState.storeID, sessionState.lastPushedStoreSeq, sessionState.keyCardID).
				Scan(&op.unpushedEvents)
			if err != pgx.ErrNoRows {
				check(err)
			}
			r.sendSessionOp(sessionState, op)
			sessionState.initialStatus = true
			sessionState.lastStatusedStoreSeq = seqPair.lastWrittenStoreSeq
			if op.unpushedEvents == 0 {
				sessionState.lastBufferedStoreSeq = sessionState.lastStatusedStoreSeq
				sessionState.lastPushedStoreSeq = sessionState.lastStatusedStoreSeq
			}
			// TODO: maybe we should consider making this log line dynamic and just print the types where it's >0 ?
			logS(sessionId, "relay.debounceSessions.syncStatus initialStatus=%t unpushedEvents=%d elapsed=%d", sessionState.initialStatus, op.unpushedEvents, took(syncStatusStart))
		}
		r.assertCursors(sessionId, seqPair, sessionState)

		// Check if more buffering is needed, and if so fill buffer.
		writesNotBuffered := sessionState.lastBufferedStoreSeq < seqPair.lastWrittenStoreSeq
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
			query := `select serverSeq, storeSeq, eventId, eventType, createdByKeyCardId, createdByStoreId, createdAt, signature,
			storeTokenId, domain, publishedTagId, manifestUpdateField, string, addr, referencedEventId, itemId, price,
			metadata, itemUpdateField, name, tagId, cartId, quantity, itemIds, changes, txHash, userWallet, cardPublicKey,
            purchaseAddr, erc20Addr, subTotal, salesTax, total, totalInCrypto
from events
where createdByStoreId = $1
	and storeSeq > $2
	and createdByKeyCardId != $3
order by storeSeq asc limit $4`
			// from entries where userId = $1 and seq > $2 and deviceId != $3 order by seq asc limit $4
			rows, err := r.connPool.Query(ctx, query, sessionState.storeID, sessionState.lastBufferedStoreSeq, sessionState.keyCardID, readsAllowed)
			check(err)
			defer rows.Close()
			for rows.Next() {
				var (
					eventState          = &EventState{}
					storeTokenID        *[]byte
					domain              *string
					publishedTagID      *[]byte
					manifestUpdateField *UpdateManifest_ManifestField
					stringVal           *string
					addrVal             *[]byte
					referencedEventID   *[]byte
					itemID              *[]byte
					price               *string
					metadata            *[]byte
					itemUpdateField     *UpdateItem_ItemField
					name                *string
					tagID               *[]byte
					cartID              *[]byte
					quantity            *int32
					itemIds             *[][]byte
					changes             *[]int32
					txHash              *[]byte
					userWallet          *[]byte
					cardPublicKey       *[]byte
					purchaseAddr        *[]byte
					erc20Addr           *[]byte
					subTotal            *string
					salesTax            *string
					total               *string
					totalInCrypto       *string
				)
				err := rows.Scan(&eventState.serverSeq, &eventState.storeSeq, &eventState.eventID, &eventState.eventType, &eventState.created.byDeviceID, &eventState.created.byStoreID, &eventState.created.at, &eventState.signature,
					&storeTokenID, &domain, &publishedTagID, &manifestUpdateField, &stringVal, &addrVal, &referencedEventID, &itemID, &price, &metadata, &itemUpdateField, &name, &tagID, &cartID, &quantity, &itemIds, &changes, &txHash, &userWallet, &cardPublicKey,
					&purchaseAddr, &erc20Addr, &subTotal, &salesTax, &total, &totalInCrypto,
				)
				check(err)
				reads++
				log("relay.debounceSessions.debug event=%x", eventState.eventID)
				switch eventState.eventType {
				case eventTypeStoreManifest:
					assert(storeTokenID != nil)
					assert(publishedTagID != nil)
					eventState.storeManifest = &StoreManifest{
						EventId:        eventState.eventID,
						StoreTokenId:   *storeTokenID,
						Domain:         *domain,
						PublishedTagId: *publishedTagID,
					}
				case eventTypeUpdateManifest:
					assert(manifestUpdateField != nil)
					um := &UpdateManifest{
						EventId: eventState.eventID,
						Field:   *manifestUpdateField,
					}
					switch *manifestUpdateField {
					case UpdateManifest_MANIFEST_FIELD_DOMAIN:
						assert(stringVal != nil)
						um.Value = &UpdateManifest_String_{String_: *stringVal}
					case UpdateManifest_MANIFEST_FIELD_PUBLISHED_TAG:
						assert(referencedEventID != nil)
						um.Value = &UpdateManifest_TagId{TagId: *referencedEventID}
					case UpdateManifest_MANIFEST_FIELD_ADD_ERC20:
						fallthrough
					case UpdateManifest_MANIFEST_FIELD_REMOVE_ERC20:
						assert(addrVal != nil)
						um.Value = &UpdateManifest_Erc20Addr{*addrVal}
					}
					eventState.updateManifest = um
				case eventTypeCreateItem:
					assert(itemID != nil)
					assert(price != nil)
					assert(metadata != nil)
					eventState.createItem = &CreateItem{
						EventId:  eventState.eventID,
						Price:    *price,
						Metadata: *metadata,
					}
				case eventTypeUpdateItem:
					assert(itemID != nil)
					assert(itemUpdateField != nil)
					assert(price != nil || metadata != nil)
					ui := &UpdateItem{
						EventId: eventState.eventID,
						ItemId:  *itemID,
						Field:   *itemUpdateField,
					}
					if price != nil {
						ui.Value = &UpdateItem_Price{*price}
					}
					if metadata != nil {
						ui.Value = &UpdateItem_Metadata{*metadata}
					}
					eventState.updateItem = ui
				case eventTypeCreateTag:
					assert(name != nil)
					eventState.createTag = &CreateTag{
						EventId: eventState.eventID,
						Name:    *name,
					}
				case eventTypeAddToTag:
					assert(itemID != nil)
					assert(tagID != nil)
					eventState.addToTag = &AddToTag{
						EventId: eventState.eventID,
						ItemId:  *itemID,
						TagId:   *tagID,
					}
				case eventTypeRemoveFromTag:
					assert(itemID != nil)
					assert(tagID != nil)
					eventState.removeFromTag = &RemoveFromTag{
						EventId: eventState.eventID,
						ItemId:  *itemID,
						TagId:   *tagID,
					}
				case eventTypeRenameTag:
					assert(name != nil)
					assert(tagID != nil)
					eventState.renameTag = &RenameTag{
						EventId: eventState.eventID,
						Name:    *name,
						TagId:   *tagID,
					}
				case eventTypeDeleteTag:
					assert(tagID != nil)
					eventState.deleteTag = &DeleteTag{
						EventId: eventState.eventID,
						TagId:   *tagID,
					}
				case eventTypeChangeStock:
					assert(itemIds != nil)
					assert(changes != nil)
					assert(len(*itemIds) == len(*changes))
					cs := &ChangeStock{
						EventId: eventState.eventID,
					}
					if cartID != nil {
						cs.CartId = *cartID
						assert(txHash != nil)
						cs.TxHash = *txHash
					}
					cs.ItemIds = *itemIds
					cs.Diffs = *changes
					eventState.changeStock = cs
				case eventTypeCreateCart:
					assert(cartID != nil)
					eventState.createCart = &CreateCart{
						EventId: eventState.eventID,
					}
				case eventTypeChangeCart:
					assert(itemID != nil)
					assert(cartID != nil)
					assert(quantity != nil)
					eventState.changeCart = &ChangeCart{
						EventId:  eventState.eventID,
						ItemId:   *itemID,
						CartId:   *cartID,
						Quantity: *quantity,
					}
				case eventTypeCartFinalized:
					assert(cartID != nil)
					assert(purchaseAddr != nil)
					assert(subTotal != nil)
					assert(salesTax != nil)
					assert(total != nil)
					assert(totalInCrypto != nil)
					cf := &CartFinalized{
						EventId:       eventState.eventID,
						CartId:        *cartID,
						PurchaseAddr:  *purchaseAddr,
						SubTotal:      *subTotal,
						SalesTax:      *salesTax,
						Total:         *total,
						TotalInCrypto: *totalInCrypto,
					}
					if erc20Addr != nil {
						cf.Erc20Addr = *erc20Addr
					}
					eventState.cartFinalized = cf
				case eventTypeCartAbandoned:
					assert(cartID != nil)
					ca := &CartAbandoned{
						EventId: eventState.eventID,
						CartId:  *cartID,
					}
					eventState.cartAbandoned = ca
				case eventTypeNewKeyCard:
					assert(userWallet != nil)
					assert(cardPublicKey != nil)
					eventState.newKeyCard = &NewKeyCard{
						EventId:        eventState.eventID,
						UserWalletAddr: *userWallet,
						CardPublicKey:  *cardPublicKey,
					}
				default:
					panic(fmt.Errorf("unhandled eventType: %s", eventState.eventType))
				}

				eventState.acked = false
				sessionState.buffer = append(sessionState.buffer, eventState)
				assert(eventState.storeSeq > sessionState.lastBufferedStoreSeq)
				sessionState.lastBufferedStoreSeq = eventState.storeSeq
			}
			check(rows.Err())

			// If the read rows didn't use the full limit, that means we must be at the end
			// of this user's writes.
			if reads < readsAllowed {
				sessionState.lastBufferedStoreSeq = seqPair.lastWrittenStoreSeq
			}

			logS(sessionId, "relay.debounceSessions.read storeId=%s reads=%d readsAllowed=%d bufferLen=%d lastWrittenStoreSeq=%d, lastBufferedstoreSeq=%d elapsed=%d", sessionState.storeID, reads, readsAllowed, len(sessionState.buffer), seqPair.lastWrittenStoreSeq, sessionState.lastBufferedStoreSeq, took(readStart))
			r.metric.emit("relay.events.read", uint64(reads))

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
			sessionState.lastPushedStoreSeq = entryState.storeSeq
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
		if len(sessionState.buffer) == 0 && sessionState.lastAckedStoreSeq < sessionState.lastPushedStoreSeq {
			logS(sessionId, "relay.debounceSessions.advanceStoreSeq reason=emptyBuffer from=%d to=%d", sessionState.lastAckedStoreSeq, sessionState.lastPushedStoreSeq)
			sessionState.lastAckedStoreSeq = sessionState.lastPushedStoreSeq
		}
		r.assertCursors(sessionId, seqPair, sessionState)

		// Flush session state if sufficiently advanced.
		lastAckedstoreSeqNeedsFlush := sessionState.lastAckedStoreSeq-sessionState.lastAckedStoreSeqFlushed > sessionLastAckedstoreSeqFlushLimit
		lastSeenAtNeedsFlush := sessionState.lastSeenAt.Sub(sessionState.lastSeenAtFlushed) > sessionLastSeenAtFlushLimit
		if lastAckedstoreSeqNeedsFlush || lastSeenAtNeedsFlush {
			flushStart := now()
			// Index: devices(id)
			query := `update keyCards set lastAckedstoreSeq = $1, lastSeenAt = $2 where id = $3`
			_, err := r.connPool.Exec(ctx, query, sessionState.lastAckedStoreSeq, sessionState.lastSeenAt, sessionState.keyCardID)
			check(err)
			sessionState.lastAckedStoreSeqFlushed = sessionState.lastAckedStoreSeq
			sessionState.lastSeenAtFlushed = sessionState.lastSeenAt
			logS(sessionId, "relay.debounceSessions.flush lastAckedstoreSeqNeedsFlush=%t lastSeenAtNeedsFlush=%t lastAckedstoreSeq=%d elapsed=%d", lastAckedstoreSeqNeedsFlush, lastSeenAtNeedsFlush, sessionState.lastAckedStoreSeq, took(flushStart))
		}
		// logS(sessionId, "relay.debounce.cursors lastWrittenStoreSeq=%d lastStatusedstoreSeq=%d lastBufferedstoreSeq=%d lastPushedstoreSeq=%d lastAckedstoreSeq=%d", userState.lastWrittenStoreSeq, sessionState.lastStatusedstoreSeq, sessionState.lastBufferedstoreSeq, sessionState.lastPushedstoreSeq, sessionState.lastAckedstoreSeq)
	})

	// Since we're polling this loop constantly, only log if takes a non-trivial amount of time.
	debounceSessionsElapsed := took(start)
	if debounceSessionsElapsed > 0 {
		r.metric.emit("relay.debounceSessions.elapsed", uint64(debounceSessionsElapsed))
		log("relay.debounceSessions.finish sessions=%d elapsed=%d", r.sessionIdsToSessionStates.Size(), debounceSessionsElapsed)
	}
}

// TODO: should be one per store
var relayKeyCardID requestID

func init() {
	relayKeyCardID = newRequestID()
	copy(relayKeyCardID[:], []byte("relay"))
}

// PaymentWaiter is a struct that holds the state of a cart that is waiting for payment.
type PaymentWaiter struct {
	waiterID        requestID
	cartID          eventID
	cartFinalizedAt time.Time
	purchaseAddr    common.Address
	lastBlockNo     SQLStringBigInt
	coinsPayed      SQLStringBigInt
	coinsTotal      SQLStringBigInt

	// (optional) contract of the erc20 that we are looking for
	erc20TokenAddr *common.Address

	// set if cart was payed
	cartPayedAt *time.Time
	cartPayedTx *common.Hash
}

var (
	bigZero = big.NewInt(0)
	bigOne  = big.NewInt(1)
)

func (r *Relay) watchEthereumPayments() {
	log("relay.watchEthereumPayments.start")

	var (
		start = now()
		ctx   = context.Background()

		// this is the block iterator
		lowestLastBlock = new(big.Int)

		waiters = make(map[common.Address]PaymentWaiter)
	)

	openPaymentsQry := `SELECT waiterId, cartId, cartFinalizedAt, purchaseAddr, lastBlockNo, coinsPayed, coinsTotal
	FROM payments
	WHERE cartPayedAt IS NULL
		AND erc20TokenAddr IS NULL -- see watchErc20Payments()
		AND cartFinalizedAt >= NOW() - INTERVAL '1 day' ORDER BY lastBlockNo asc;`
	rows, err := r.connPool.Query(ctx, openPaymentsQry)
	check(err)
	defer rows.Close()
	for rows.Next() {
		var waiter PaymentWaiter
		err := rows.Scan(&waiter.waiterID, &waiter.cartID, &waiter.cartFinalizedAt, &waiter.purchaseAddr, &waiter.lastBlockNo, &waiter.coinsPayed, &waiter.coinsTotal)
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
		return
	}

	log("relay.watchEthereumPayments.dbRead elapsed=%d waiters=%d lowestLastBlock=%s", took(start), len(waiters), lowestLastBlock)

	// Get the latest block number
	currentBlockNoInt, err := r.ethClient.BlockNumber(ctx)
	check(err)
	currentBlockNo := big.NewInt(int64(currentBlockNoInt))

	r.beginSyncTransaction()

	for {
		if currentBlockNo.Cmp(lowestLastBlock) == -1 {
			// nothing to do
			log("relay.watchEthereumPayments.noNewBlocks current=%d", currentBlockNoInt)
			break
		}
		// check each block for transactions
		block, err := r.ethClient.BlockByNumber(ctx, lowestLastBlock)
		if err != nil {
			check(fmt.Errorf("relay.watchEthereumPayments.failedToGetBlock block=%s err=%s", lowestLastBlock, err))
		}

		for _, tx := range block.Transactions() {
			to := tx.To()
			if to == nil {
				continue // contract creation
			}
			waiter, has := waiters[*to]
			if has {
				log("relay.watchEthereumPayments.checkTx waiter.lastBlockNo=%s checkingBlock=%s tx=%s to=%s", waiter.lastBlockNo.String(), block.Number().String(), tx.Hash().String(), tx.To().String())
				cartID := waiter.cartID
				cart, has := r.cartsByCartID.get(cartID)
				assertWithMessage(has, fmt.Sprintf("cart not found for cartId=%s", cartID))

				meta := CachedMetadata{
					createdByKeyCardID:      relayKeyCardID,
					createdByStoreID:        cart.createdByStoreID,
					createdByNetworkVersion: 1,
				}
				r.hydrateStores(NewSetEventIds(cart.createdByStoreID))

				// found a transaction to the purchase address
				// check if it's the right amount
				inTx := tx.Value()
				waiter.coinsPayed.Add(&waiter.coinsPayed.Int, inTx)
				if waiter.coinsPayed.Cmp(&waiter.coinsTotal.Int) != -1 {
					// it is larger or equal

					// emit changeStock event
					cs := &ChangeStock{
						EventId: newEventID(),
						CartId:  cartID,
						TxHash:  tx.Hash().Bytes(),
					}

					// fill diff
					i := 0
					cs.ItemIds = make([][]byte, cart.items.Size())
					cs.Diffs = make([]int32, cart.items.Size())
					cart.items.All(func(itemId eventID, quantity int32) {
						cs.ItemIds[i] = itemId
						cs.Diffs[i] = -quantity
						i++
					})

					evt := &Event{Union: &Event_ChangeStock{ChangeStock: cs}}
					err = r.ethClient.eventSign(evt)
					check(err)
					r.writeEvent(evt, meta)

					// update DB state
					const markCartAsPayedQuery = `UPDATE payments SET cartPayedAt = NOW(), cartPayedTx = $1 WHERE cartId = $2;`
					_, err := r.syncTx.Exec(ctx, markCartAsPayedQuery, tx.Hash().Bytes(), cartID)
					check(err)

					delete(waiters, waiter.purchaseAddr)
					log("relay.watchEthereumPayments.completed cartId=%s", cartID)
				} else {
					// it is still smaller
					log("relay.watchEthereumPayments.partial cartId=%s inTx=%s subTotal=%s", cartID, inTx.String(), waiter.coinsPayed.String())
					// update subtotal
					const updateSubtotalQuery = `UPDATE payments SET coinsPayed = $1 WHERE cartId = $2;`
					_, err := r.syncTx.Exec(ctx, updateSubtotalQuery, waiter.coinsPayed, cartID)
					check(err)
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
			const updateLastBlockNoQuery = `UPDATE payments SET lastBlockNo = lastBlockNo + 1 WHERE cartId = $1;`
			cartID := waiter.cartID
			_, err = r.syncTx.Exec(ctx, updateLastBlockNoQuery, cartID)
			check(err)
			log("relay.watchEthereumPayments.advance cartId=%x newLastBlock=%s", cartID, waiter.lastBlockNo.String())
		}
		// increment iterator
		lowestLastBlock.Add(lowestLastBlock, bigOne)
	}

	r.commitSyncTransaction()

	stillWaiting := len(waiters)
	log("relay.watchEthereumPayments.finish elapsed=%d openWaiters=%d", took(start), stillWaiting)
	r.metric.emit("relay_payments_eth_open", uint64(stillWaiting))
}

var transferSignatureErc20 = crypto.Keccak256Hash([]byte("Transfer(address,address,uint256)"))

func (r *Relay) watchErc20Payments() {
	log("relay.watchErc20Payments.start")

	var (
		start = now()
		ctx   = context.Background()

		// this is the block iterator
		lowestLastBlock = new(big.Int)

		waiters         = make(map[common.Hash]PaymentWaiter)
		erc20AddressSet = make(map[common.Address]struct{})
	)

	openPaymentsQry := `SELECT waiterId, cartId, cartFinalizedAt, purchaseAddr, lastBlockNo, coinsPayed, coinsTotal, erc20TokenAddr
		FROM payments
		WHERE cartPayedAt IS NULL
			AND erc20TokenAddr IS NOT NULL -- see watchErc20Payments()
			AND cartFinalizedAt >= NOW() - INTERVAL '1 day' ORDER BY lastBlockNo asc;`
	rows, err := r.connPool.Query(ctx, openPaymentsQry)
	check(err)
	defer rows.Close()
	for rows.Next() {
		var waiter PaymentWaiter
		err := rows.Scan(&waiter.waiterID, &waiter.cartID, &waiter.cartFinalizedAt, &waiter.purchaseAddr, &waiter.lastBlockNo, &waiter.coinsPayed, &waiter.coinsTotal, &waiter.erc20TokenAddr)
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
		return
	}

	// Get the latest block number.
	currentBlockNoInt, err := r.ethClient.BlockNumber(ctx)
	check(err)
	log("relay.watchErc20Payments.starting currentBlock=%d", currentBlockNoInt)
	currentBlockNo := big.NewInt(int64(currentBlockNoInt))

	// turn set into a list
	erc20Addresses := make([]common.Address, len(erc20AddressSet))
	i := 0
	for addr := range erc20AddressSet {
		copy(erc20Addresses[i][:], addr[:])
		i++
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	qry := ethereum.FilterQuery{
		Addresses: erc20Addresses,
		FromBlock: lowestLastBlock,
		ToBlock:   currentBlockNo,
		Topics: [][]common.Hash{
			{transferSignatureErc20},
			// TODO: it would seem that {transferSignatureErc20, {}, purchaseAddrAsHash} would be the right filter, but it doesn't work
			// See the following article but i'm not willing to do all that just right now
			// https://dave-appleton.medium.com/overcoming-ethclients-filter-restrictions-81e232a8eccd
		},
	}
	logs, err := r.ethClient.FilterLogs(timeoutCtx, qry)
	check(err)

	r.beginSyncTransaction()

	// iterate over all matching logs of events from that erc20 contract with the transfer signature
	for _, vLog := range logs {
		// log("relay.watchErc20Payments.checking block=%d", vLog.BlockNumber)
		// log("relay.watchErc20Payments.checking topics=%#v", vLog.Topics[1:])
		fromHash := vLog.Topics[1]
		toHash := vLog.Topics[2]

		waiter, has := waiters[toHash]
		if has && waiter.erc20TokenAddr.Cmp(vLog.Address) == 0 {
			// We found a transfer to our address!
			cartID := waiter.cartID

			cart, has := r.cartsByCartID.get(cartID)
			assertWithMessage(has, fmt.Sprintf("cart not found for cartId=%s", cartID))

			meta := CachedMetadata{
				createdByKeyCardID:      relayKeyCardID,
				createdByStoreID:        cart.createdByStoreID,
				createdByNetworkVersion: 1,
			}
			r.hydrateStores(NewSetEventIds(cart.createdByStoreID))

			evts, err := r.ethClient.erc20ContractABI.Unpack("Transfer", vLog.Data)
			if err != nil {
				log("relay.watchErc20Payments.transferErc20.failedToUnpackTransfer err=%s", err)
				continue
			}

			inTx, ok := evts[0].(*big.Int)
			assertWithMessage(ok, fmt.Sprintf("unexpected unpack result for field 0 - type=%T", evts[0]))
			log("relay.watchErc20Payments.foundTransfer cartId=%s from=%s to=%s amount=%s", cartID, fromHash.Hex(), toHash.Hex(), inTx.String())

			waiter.coinsPayed.Add(&waiter.coinsPayed.Int, inTx)
			if waiter.coinsPayed.Cmp(&waiter.coinsTotal.Int) != -1 {
				// it is larger or equal

				const markCartAsPayedQuery = `UPDATE payments SET cartPayedAt = NOW(), cartPayedTx = $1 WHERE cartId = $2;`
				_, err := r.syncTx.Exec(ctx, markCartAsPayedQuery, vLog.TxHash.Bytes(), cartID)
				check(err)

				// emit changeStock
				cs := &ChangeStock{
					EventId: newEventID(),
					CartId:  cartID,
					TxHash:  toHash.Bytes(),
				}

				// fill diff
				i := 0
				cs.ItemIds = make([][]byte, cart.items.Size())
				cs.Diffs = make([]int32, cart.items.Size())
				cart.items.All(func(itemId eventID, quantity int32) {
					cs.ItemIds[i] = itemId
					cs.Diffs[i] = -quantity
					i++
				})

				evt := &Event{Union: &Event_ChangeStock{ChangeStock: cs}}
				err = r.ethClient.eventSign(evt)
				check(err)
				r.writeEvent(evt, meta)
				delete(waiters, toHash)
				log("relay.watchErc20Payments.completed cartId=%s", cartID)

			} else {
				// it is still smaller
				log("relay.watchErc20Payments.partial cartId=%s inTx=%s subTotal=%s", cartID, inTx.String(), waiter.coinsPayed.String())
				// update subtotal
				const updateSubtotalQuery = `UPDATE payments SET coinsPayed = $1 WHERE cartId = $2;`
				_, err = r.syncTx.Exec(ctx, updateSubtotalQuery, waiter.coinsPayed, cartID)
				check(err)
			}
		}
		for _, waiter := range waiters {
			// only advance those waiters which last blocks are lower then the block we just checked
			if waiter.lastBlockNo.Cmp(big.NewInt(int64(vLog.BlockNumber))) == -1 {
				continue
			}
			// move up block number
			const updateLastBlockNoQuery = `UPDATE payments SET lastBlockNo = $2 WHERE cartId = $1;`
			_, err = r.syncTx.Exec(ctx, updateLastBlockNoQuery, waiter.cartID, currentBlockNo.String())
			check(err)
			log("relay.watchErc20Payments.advance cartId=%x newLastBlock=%s", waiter.cartID, waiter.lastBlockNo.String())
		}
	}

	r.commitSyncTransaction()
	stillWaiting := len(waiters)
	log("relay.watchErc20Payments.finish elapsed=%d openWaiters=%d", took(start), stillWaiting)
	r.metric.emit("relay_payments_erc20_open", uint64(stillWaiting))
}

func (r *Relay) memoryStats() {
	start := now()
	log("relay.memoryStats.start")

	// Shared between old and sharing worlds.
	sessionCount := r.sessionIdsToSessionStates.Size()
	sessionVersionCounts := make(map[uint]uint64)
	r.sessionIdsToSessionStates.All(func(sessionId requestID, sessionState *SessionState) {
		sessionVersionCount := sessionVersionCounts[sessionState.version]
		sessionVersionCounts[sessionState.version] = sessionVersionCount + 1
	})
	r.metric.emit("sessions.active", uint64(sessionCount))
	for version, versionCount := range sessionVersionCounts {
		r.metric.emit(fmt.Sprintf("sessions.active.version.%d", version), versionCount)
	}
	r.metric.emit("relay.stores.cached", uint64(r.storeIdsToStoreSeqs.Size()))

	r.metric.emit("relay.ops.queued", uint64(len(r.ops)))
	// r.metric.emit("relay.events.cached", uint64(r.eventsById.loaded.Size()))

	// Go runtime memory information
	var runtimeMemory runtime.MemStats
	runtime.ReadMemStats(&runtimeMemory)
	r.metric.emit("go.runtime.heapalloc", runtimeMemory.HeapAlloc)
	r.metric.emit("go.runtime.inuse", runtimeMemory.HeapInuse)
	r.metric.emit("go.runtime.gcpauses", runtimeMemory.PauseTotalNs)

	memoryStatsElapsed := took(start)
	r.metric.emit("relay.memoryStats.elapsed", uint64(memoryStatsElapsed))
	log("relay.memoryStats.finish elapsed=%d", memoryStatsElapsed)
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
	paymentWatcherTimer := NewReusableTimer(newEthereumBlockInterval)
	tickStatsTimer := NewReusableTimer(tickStatsInterval)

	tickTypeToElapseds := make(map[tickType]time.Duration, len(allTickTypes))
	for _, tt := range allTickTypes {
		tickTypeToElapseds[tt] = 0
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
			r.debounceSessions()
			debounceSessionsTimer.Rewind()

		case <-memoryStatsTimer.C:
			tickType, tickSelected = timeTick(ttMemoryStats)
			r.memoryStats()
			memoryStatsTimer.Rewind()

		case <-paymentWatcherTimer.C:
			tickType, tickSelected = timeTick(ttPaymentWatcher)
			r.watchEthereumPayments()
			r.watchErc20Payments()
			paymentWatcherTimer.Rewind()

		case <-tickStatsTimer.C:
			tickType, tickSelected = timeTick(ttTickStats)
			for tt, e := range tickTypeToElapseds {
				if e.Milliseconds() > 0 {
					r.metric.emit(fmt.Sprintf("relay.run.tick.%s.elapsed", tt.String()), uint64(e.Milliseconds()))
				}
				tickTypeToElapseds[tt] = 0
			}
			tickStatsTimer.Rewind()
		}

		assert(tickType != ttInvalid)
		assert(!tickSelected.IsZero())
		tickWait := tickSelected.Sub(tickStart)
		tickElapsed := time.Since(tickSelected)
		tickTypeToElapseds[ttWait] += tickWait
		e, ok := tickTypeToElapseds[tickType]
		assert(ok)
		e += tickElapsed
		tickTypeToElapseds[tickType] = e
		if tickElapsed > tickBlockThreshold {
			log("relay.run.tick.block type=%s elapsed=%d", tickType, tickElapsed.Milliseconds())
		}
	}
}

// Metric maps a name to a prometheus metric.
type Metric struct {
	name2gauge   map[string]prometheus.Gauge
	name2counter map[string]prometheus.Counter
}

func newMetric() *Metric {
	return &Metric{
		name2gauge:   make(map[string]prometheus.Gauge),
		name2counter: make(map[string]prometheus.Counter),
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

func sessionsHandleFunc(version uint, db *Relay) func(http.ResponseWriter, *http.Request) {
	log("relay.sessionsHandleFunc version=%d", version)
	return func(w http.ResponseWriter, r *http.Request) {
		conn, _, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			log("relay.upgradeError %+v", err)
			return
		}
		sess := newSession(version, conn, db.ops, db.metric)
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
				r.metric.counterAdd("blob_pinata_elapsed", float64(took(startPin)))
			}()
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{"ipfs_path": uploadedCid.String(), "url": "https://cloudflare-ipfs.com" + uploadedCid.String()})
		return 0, nil
	}
	return func(w http.ResponseWriter, req *http.Request) {
		code, err := fn(w, req)
		if err != nil {
			jsonEnc := json.NewEncoder(w)
			log("relay.blobUploadHandler err=%s", err)
			w.WriteHeader(code)
			jsonEnc.Encode(map[string]any{"handler": "getBlobUpload", "error": err.Error()})
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

		opts := &bind.CallOpts{
			Pending: false,
			From:    r.ethClient.wallet,
			Context: req.Context(),
		}
		var bigTokenID big.Int
		bigTokenID.SetBytes(data.StoreTokenID)

		has, err := r.ethClient.stores.HasAtLeastAccess(opts, &bigTokenID, userWallet, 1)
		if err != nil {
			return http.StatusInternalServerError, fmt.Errorf("contract call error: %w", err)
		}
		log("relay.enrollKeyCard.verifyAccess storeTokenID=%s userWallet=%s has=%v", bigTokenID.String(), userWallet.Hex(), has)
		if !has {
			return http.StatusForbidden, errors.New("access denied")
		}

		storeID := r.getOrCreateInternalStoreID(bigTokenID)
		const insertKeyCard = `insert into keyCards (id, storeId, cardPublicKey, userWalletAddr, linkedAt, lastAckedStoreSeq, lastSeenAt, lastVersion)
		VALUES ($1, $2, $3, $4, now(), 0, now(), 1)`
		_, err = r.connPool.Exec(context.Background(), insertKeyCard, newRequestID(), storeID, data.KeyCardPublicKey, userWallet)
		check(err)

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{"success": true})
		go func() {
			r.opsInternal <- &KeyCardEnrolledInternalOp{
				storeID:          storeID,
				keyCardPublicKey: data.KeyCardPublicKey,
				userWallet:       userWallet,
			}
		}()
		return 0, nil
	}
	return func(w http.ResponseWriter, req *http.Request) {
		code, err := fn(w, req)
		if err != nil {
			jsonEnc := json.NewEncoder(w)
			log("relay.enrollKeyCard err=%s", err)
			w.WriteHeader(code)
			jsonEnc.Encode(map[string]any{"handler": "enrollKeyCard", "error": err.Error()})
			return
		}
	}
}

func healthHandleFunc(syncPool *pgxpool.Pool) func(http.ResponseWriter, *http.Request) {
	log("relay.healthHandleFunc")
	return func(w http.ResponseWriter, r *http.Request) {
		start := now()
		log("relay.health.start")
		ctx := context.Background()
		var res int
		err := syncPool.QueryRow(ctx, `select 1`).Scan(&res)
		if err != nil {
			log("relay.health.dbs.fail")
			w.WriteHeader(500)
			fmt.Fprintln(w, "database unavailable")
			return
		}

		log("relay.health.pass")
		fmt.Fprintln(w, "health OK")
		log("relay.health.finish elapsed=%d", took(start))
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

	// open metrics and pprof after relay & ethclient booted
	openPProfEndpoint()
	go metric.connect()

	go emitUptime(metric)

	mux := http.NewServeMux()

	// We expect some of these endpoints to be accessed only from sync* or
	// share* DNS endpoints, but don't worry right now about limiting
	// access by hostname.

	for _, v := range networkVersions {
		mux.HandleFunc(fmt.Sprintf("/v%d/sessions", v), sessionsHandleFunc(v, r))
		mux.HandleFunc(fmt.Sprintf("/v%d/enroll_key_card", v), enrollKeyCardHandleFunc(v, r))

		mux.HandleFunc(fmt.Sprintf("/v%d/upload_blob", v), uploadBlobHandleFunc(v, r))
	}

	// Internal engineering APIs.
	mux.HandleFunc("/health", healthHandleFunc(r.connPool))

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
