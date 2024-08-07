// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

// Package main implements the relay server for a massMarket shop
package main

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	ipfsFiles "github.com/ipfs/boxo/files"
	ipfsPath "github.com/ipfs/boxo/path"
	ipfsRpc "github.com/ipfs/kubo/client/rpc"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/miolini/datacounter"
	"github.com/multiformats/go-multiaddr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/cors"
	"github.com/spruceid/siwe-go"
	"github.com/ssgreg/repeat"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// Server configuration.
const (
	sessionLastSeenAtFlushLimit     = 30 * time.Second
	sessionLastAckedKCSeqFlushLimit = 4096
	sessionBufferSizeRefill         = limitMaxOutRequests * limitMaxOutBatchSize
	sessionBufferSizeMax            = limitMaxOutRequests * limitMaxOutBatchSize * 2

	watcherTimeout           = 5 * time.Second
	databaseDebounceInterval = 100 * time.Millisecond
	tickStatsInterval        = 1 * time.Second
	tickBlockThreshold       = 50 * time.Millisecond
	memoryStatsInterval      = 5 * time.Second
	emitUptimeInterval       = 10 * time.Second

	databaseOpsChanSize           = 64 * 1024
	databasePropagationEventLimit = 5000

	maxItemMedataBytes = 5 * 1024
)

// set by build script via ldflags
var release = "unset"

// Toggle high-volume log traffic.
var (
	logMessages = false
	logMetrics  = false

	sessionPingInterval   = 15 * time.Second
	sessionKickTimeout    = 3 * sessionPingInterval
	ethereumBlockInterval = 15 * time.Second
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

	// optional - mostly for testing
	pingIntervalStr := os.Getenv("PING_INTERVAL")
	optPingInterval, err := time.ParseDuration(pingIntervalStr)
	if pingIntervalStr != "" && err == nil {
		sessionPingInterval = optPingInterval
	}

	kickTimeoutStr := os.Getenv("KICK_TIMEOUT")
	optKickTimeout, err := time.ParseDuration(kickTimeoutStr)
	if kickTimeoutStr != "" && err == nil {
		sessionKickTimeout = optKickTimeout
	}

	ethereumBlockIntervalStr := os.Getenv("ETH_BLOCK_INTERVAL")
	optBlockInterval, err := time.ParseDuration(ethereumBlockIntervalStr)
	if ethereumBlockIntervalStr != "" && err == nil {
		ethereumBlockInterval = optBlockInterval
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
	Message: "Key Card was removed from the Shop",
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
	sessionID      requestID
	im             *EventWriteRequest
	decodedShopEvt *ShopEvent
	newShopHash    []byte
	eventSeq       uint64
	err            *Error
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

// EventLoopPingInternalOp is used by the health check
// to make sure relay.run() is responsive
type EventLoopPingInternalOp struct {
	done chan<- struct{}
}

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
	shopID            eventID
	keyCardIsGuest    bool
	keyCardDatabaseID requestID
	keyCardPublicKey  []byte
	userWallet        common.Address

	done chan struct{}
}

// PaymentFoundInternalOp is created by payment watchers
type PaymentFoundInternalOp struct {
	orderID eventID
	txHash  common.Hash

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
	events := make([]*SignedEvent, len(op.eventStates))
	var err error
	for i, eventState := range op.eventStates {
		eventState.eventID.assert()
		events[i] = &eventState.encodedEvent
		assert(eventState.encodedEvent.Event != nil)
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

func validateShopManifest(_ uint, event *ShopManifest) *Error {
	return coalesce(
		validateEventID(event.EventId, "event_id"),
		validateBytes(event.ShopTokenId, "shop_token_id", 32),
		validateURL(event.Domain, "domain"),
		validateBytes(event.PublishedTagId, "published_tag_id", 32),
	)
}

func validateUpdateShopManifest(_ uint, event *UpdateShopManifest) *Error {
	errs := []*Error{validateEventID(event.EventId, "event_id")}
	hasOpt := false
	if str := event.Name; str != nil {
		errs = append(errs, validateString(*str, "name", 100))
		hasOpt = true
	}
	if str := event.Description; str != nil {
		errs = append(errs, validateString(*str, "description", 1024))
		hasOpt = true
	}
	if str := event.ProfilePictureUrl; str != nil {
		errs = append(errs, validateURL(*str, "profile_picture_url"))
		hasOpt = true
	}
	if d := event.Domain; d != nil {
		errs = append(errs, validateURL(*d, "domain"))
		hasOpt = true
	}
	if pt := event.PublishedTagId; len(pt) > 0 {
		errs = append(errs, validateEventID(pt, "published_tag_id"))
		hasOpt = true
	}
	if adds := event.AddAcceptedCurrencies; len(adds) > 0 {
		// TODO: validate chain ids?
		for i, add := range adds {
			errMsg := fmt.Sprintf("add_accepted_currency[%d].addr", i)
			errs = append(errs, validateEthAddressBytes(add.TokenAddr, errMsg))
		}
		hasOpt = true
	}
	if removes := event.RemoveAcceptedCurrencies; len(removes) > 0 {
		for i, remove := range removes {
			errMsg := fmt.Sprintf("remove_accepted_currency[%d].addr", i)
			errs = append(errs, validateEthAddressBytes(remove.TokenAddr, errMsg))
		}
		hasOpt = true
	}
	if base := event.SetBaseCurrency; base != nil {
		errs = append(errs, validateEthAddressBytes(base.TokenAddr, "set_base_currencty.addr"))
		hasOpt = true
	}
	if base := event.AddPayee; base != nil {
		errs = append(errs,
			validateString(base.Name, "add_payee.name", 128),
			validateEthAddressBytes(base.Addr, "add_payee.addr"),
		)
		hasOpt = true
	}
	if base := event.RemovePayee; base != nil {
		errs = append(errs, validateEthAddressBytes(base.Addr, "remove_payee.addr"))
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

func validateUpdateShippingDetails(_ uint, event *UpdateOrder_AddressDetails) *Error {
	return coalesce(
		validateString(event.Name, "name", 1024),
		validateString(event.Address1, "address1", 128),
		validateString(event.City, "city", 128),
		validateString(event.PostalCode, "postal_code", 25),
		validateString(event.Country, "country", 50),
		validateString(event.PhoneNumber, "phone_number", 20),
	)
}

func validateUpdateOrder(v uint, event *UpdateOrder) *Error {
	errs := []*Error{
		validateEventID(event.EventId, "event_id"),
		validateEventID(event.OrderId, "order_id"),
	}
	switch tv := event.Action.(type) {
	case *UpdateOrder_ChangeItems_:
		errs = append(errs, validateChangeItems(v, tv.ChangeItems))
	case *UpdateOrder_ItemsFinalized_:
		errs = append(errs, &Error{Code: ErrorCodes_INVALID, Message: "OrderFinalized is not allowed in EventWriteRequest"})
	case *UpdateOrder_OrderCanceled_:
		errs = append(errs, validateOrderCanceled(v, tv.OrderCanceled))
	case *UpdateOrder_UpdateShippingDetails:
		errs = append(errs, validateUpdateShippingDetails(v, tv.UpdateShippingDetails))
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

const shopEventTypeURL = "type.googleapis.com/market.mass.ShopEvent"

func (im *EventWriteRequest) validate(version uint) *Error {
	if version < 2 {
		return minimumVersionError
	}
	var decodedEvt ShopEvent
	if u := im.Event.Event.TypeUrl; u != shopEventTypeURL {
		log("eventWriteRequest.validate: unexpected anypb typeURL: %s", u)
		return &Error{Code: ErrorCodes_INVALID, Message: "unsupported typeURL for event"}
	}
	if pberr := im.Event.Event.UnmarshalTo(&decodedEvt); pberr != nil {
		log("eventWriteRequest.validate: anypb unmarshal failed: %s", pberr.Error())
		return &Error{Code: ErrorCodes_INVALID, Message: "invalid protobuf encoding"}
	}
	if err := validateBytes(im.Event.Signature, "event.signature", signatureBytes); err != nil {
		return err
	}
	var err *Error
	switch union := decodedEvt.Union.(type) {
	case *ShopEvent_ShopManifest:
		err = validateShopManifest(version, union.ShopManifest)
	case *ShopEvent_UpdateShopManifest:
		err = validateUpdateShopManifest(version, union.UpdateShopManifest)
	case *ShopEvent_CreateItem:
		err = validateCreateItem(version, union.CreateItem)
	case *ShopEvent_UpdateItem:
		err = validateUpdateItem(version, union.UpdateItem)
	case *ShopEvent_CreateTag:
		err = validateCreateTag(version, union.CreateTag)
	case *ShopEvent_UpdateTag:
		err = validateUpdateTag(version, union.UpdateTag)
	case *ShopEvent_ChangeStock:
		err = validateChangeStock(version, union.ChangeStock)
	case *ShopEvent_CreateOrder:
		err = validateCreateOrder(version, union.CreateOrder)
	case *ShopEvent_UpdateOrder:
		err = validateUpdateOrder(version, union.UpdateOrder)
	case *ShopEvent_NewKeyCard:
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
	var decodedEvt ShopEvent
	if pberr := im.Event.Event.UnmarshalTo(&decodedEvt); pberr != nil {
		// TODO: somehow fix double decode
		check(pberr)
	}
	op := &EventWriteOp{sessionID: sess.id, im: im, decodedShopEvt: &decodedEvt}
	sess.sendDatabaseOp(op)
}

func (op *EventWriteOp) handle(sess *Session) {
	om := op.im.response(op.err).(*EventWriteResponse)
	if op.err == nil {
		om.NewShopHash = op.newShopHash
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
	if curr := im.Currency; curr != nil {
		errs = append(errs, validateEthAddressBytes(curr.TokenAddr, "currency.token_addr"))
	} else {
		errs = append(errs, &Error{Code: ErrorCodes_INVALID, Message: "commit items needs to know the selected currency"})
	}
	errs = append(errs, validateString(im.PayeeName, "payee_name", 32))
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
	} else {
		logSR("relay.CommitItemsToOrderOpFailed code=%s message=%s",
			sess.id,
			op.im.RequestId,
			op.err.Code,
			op.err.Message)
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

	kcSeq uint64
	acked bool

	encodedEvent SignedEvent
}

// SessionState represents the state of a client in the database.
type SessionState struct {
	version               uint
	authChallenge         []byte
	sessionOps            chan SessionOp
	keyCardID             requestID
	keyCardPublicKey      []byte
	keyCardOfAGuest       bool
	shopID                eventID
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
	eventID                 eventID
	referenceID             eventID
	createdByShopID         eventID
	createdByKeyCardID      requestID
	createdByNetworkVersion uint16
	createdAt               uint64 // TODO: maybe change to time.Time
	// TODO: updatedAt uint64
	serverSeq uint64
	shopSeq   uint64
}

func newMetadata(keyCardID requestID, shopID eventID, version uint16) CachedMetadata {
	var metadata CachedMetadata
	metadata.createdByKeyCardID = keyCardID
	metadata.createdByShopID = shopID
	metadata.createdByNetworkVersion = version
	return metadata
}

type cachedShopCurrency struct {
	Addr    common.Address
	ChainID uint64
}
type cachedCurrenciesMap map[cachedShopCurrency]struct{}

type cachedShopPayee struct {
	cachedShopCurrency
	isEndpoint bool
}

// CachedShopManifest is latest reduction of a ShopManifest.
// It combines the intial ShopManifest and all UpdateShopManifests
type CachedShopManifest struct {
	CachedMetadata

	shopTokenID        []byte
	domain             string
	publishedTagID     eventID
	payees             map[string]cachedShopPayee
	acceptedCurrencies cachedCurrenciesMap
	baseCurrency       *cachedShopCurrency

	validKeyCardPublicKeys requestIDSlice
	validKeyCardIDs        *MapRequestIDs[keyCardIdWithGuest]

	init sync.Once
}

type keyCardIdWithGuest struct {
	id      requestID
	isGuest bool
}

func (current *CachedShopManifest) getValidKeyCardIDs(pool *pgxpool.Pool) []keyCardIdWithGuest {
	// turn pubkeys into keyCardIDs

	valid := make([]keyCardIdWithGuest, len(current.validKeyCardPublicKeys))
	i := 0

	for _, publicKey := range current.validKeyCardPublicKeys {
		kcId, has := current.validKeyCardIDs.GetHas(publicKey)
		if !has {
			// TODO: potentially batch these
			const cardIdQry = `select id, isGuest from keyCards
where shopId = $1 and unlinkedAt is null and cardPublicKey = $2`
			row := pool.QueryRow(context.TODO(), cardIdQry, current.createdByShopID, publicKey)

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

func (current *CachedShopManifest) update(union *ShopEvent, meta CachedMetadata) {
	current.init.Do(func() {
		current.acceptedCurrencies = make(cachedCurrenciesMap)
		current.payees = make(map[string]cachedShopPayee)
		current.validKeyCardIDs = NewMapRequestIDs[keyCardIdWithGuest]()
	})
	switch union.Union.(type) {
	case *ShopEvent_ShopManifest:
		sm := union.GetShopManifest()
		current.CachedMetadata = meta
		current.shopTokenID = sm.ShopTokenId
		current.domain = sm.Domain
		current.publishedTagID = sm.PublishedTagId
	case *ShopEvent_UpdateShopManifest:
		um := union.GetUpdateShopManifest()
		if d := um.Domain; d != nil {
			current.domain = *d
		}
		if pt := um.PublishedTagId; len(pt) > 0 {
			current.publishedTagID = pt
		}
		if adds := um.AddAcceptedCurrencies; len(adds) > 0 {
			for _, add := range adds {
				c := cachedShopCurrency{
					common.Address(add.TokenAddr),
					add.ChainId,
				}
				current.acceptedCurrencies[c] = struct{}{}
			}
		}
		if rms := um.RemoveAcceptedCurrencies; len(rms) > 0 {
			for _, rm := range rms {
				c := cachedShopCurrency{
					common.Address(rm.TokenAddr),
					rm.ChainId,
				}
				delete(current.acceptedCurrencies, c)
			}
		}
		if bc := um.SetBaseCurrency; bc != nil {
			current.baseCurrency = &cachedShopCurrency{
				Addr:    common.Address(bc.TokenAddr),
				ChainID: bc.ChainId,
			}
		}
		if p := um.AddPayee; p != nil {
			_, taken := current.payees[p.Name]
			assert(!taken)
			payee := cachedShopPayee{}
			payee.Addr = common.Address(p.Addr)
			payee.ChainID = p.ChainId
			payee.isEndpoint = p.CallAsContract
			current.payees[p.Name] = payee
		}
		if p := um.RemovePayee; p != nil {
			delete(current.payees, p.Name)
		}
	case *ShopEvent_NewKeyCard:
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

func (current *CachedItem) update(union *ShopEvent, meta CachedMetadata) {
	var err error
	switch union.Union.(type) {
	case *ShopEvent_CreateItem:
		assert(!current.inited)
		ci := union.GetCreateItem()
		current.CachedMetadata = meta
		current.itemID = ci.EventId
		current.price, _, err = apd.NewFromString(ci.Price)
		check(err)
		current.metadata = ci.Metadata
		current.inited = true
	case *ShopEvent_UpdateItem:
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

func (current *CachedTag) update(evt *ShopEvent, meta CachedMetadata) {
	if current.items == nil && !current.inited {
		current.items = NewSetEventIDs()
	}
	switch evt.Union.(type) {
	case *ShopEvent_CreateTag:
		assert(!current.inited)
		current.CachedMetadata = meta
		ct := evt.GetCreateTag()
		current.name = ct.Name
		current.tagID = ct.EventId
		current.inited = true

	case *ShopEvent_UpdateTag:
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

func (current *CachedOrder) update(evt *ShopEvent, meta CachedMetadata) {
	if current.items == nil && !current.inited {
		current.items = NewMapEventIDs[int32]()
	}
	switch evt.Union.(type) {
	case *ShopEvent_CreateOrder:
		assert(!current.inited)
		ct := evt.GetCreateOrder()
		current.CachedMetadata = meta
		current.orderID = ct.EventId
		current.inited = true
	case *ShopEvent_UpdateOrder:
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
		case *UpdateOrder_UpdateShippingDetails:
			// noop - data isn't used by the relay
		default:
			panic(fmt.Sprintf("unhandled event type: %T", evt.Union))
		}
	case *ShopEvent_ChangeStock:
		current.payed = true
		cs := evt.GetChangeStock()
		current.txHash = common.Hash(cs.TxHash)
	default:
		panic(fmt.Sprintf("unhandled event type: %T", evt.Union))

	}
}

// CachedStock is the latest reduction of a Shop's stock.
// It combines all ChangeStock events
type CachedStock struct {
	CachedMetadata

	inventory *MapEventIDs[int32]
}

func (current *CachedStock) update(evt *ShopEvent, _ CachedMetadata) {
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
	update(*ShopEvent, CachedMetadata)
}

type KeyCardEvent struct {
	keyCardId  requestID
	serverSeq  uint64
	keyCardSeq uint64
}

// SeqPairKeyCard helps with writing events to the database
type SeqPairKeyCard struct {
	lastUsedKCSeq    uint64
	lastWrittenKCSeq uint64
}

// ShopState helps with writing events to the database
type ShopState struct {
	lastUsedShopSeq    uint64
	lastWrittenShopSeq uint64

	keyCards []requestID
}

// IO represents the input/output of the server.
type IO struct {
	metric *Metric

	connPool *pgxpool.Pool
	ethereum *ethRPCService

	prices priceConverter

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

	baseURL *url.URL

	watcherContextERC20       context.Context
	watcherContextERC20Cancel context.CancelFunc

	watcherContextEther       context.Context
	watcherContextEtherCancel context.CancelFunc

	// persistence
	syncTx                  pgx.Tx
	queuedEventInserts      []*EventInsert
	keyCardIDsToKeyCardSeqs *MapRequestIDs[*SeqPairKeyCard]
	shopIdsToShopState      *MapEventIDs[*ShopState]
	lastUsedServerSeq       uint64
	lastWrittenServerSeq    uint64

	// caching layer
	shopManifestsByShopID *ReductionLoader[*CachedShopManifest]
	itemsByItemID         *ReductionLoader[*CachedItem]
	tagsByTagID           *ReductionLoader[*CachedTag]
	ordersByOrderID       *ReductionLoader[*CachedOrder]
	stockByShopID         *ReductionLoader[*CachedStock]
	allLoaders            []Loader
}

func newRelay(metric *Metric) *Relay {
	r := &Relay{}

	var err error
	r.baseURL, err = url.Parse(mustGetEnvString("RELAY_BASE_URL"))
	check(err)

	r.ethereum = newEthRPCService()
	r.watcherContextERC20, r.watcherContextERC20Cancel = context.WithCancel(context.Background())

	r.watcherContextEther, r.watcherContextEtherCancel = context.WithCancel(context.Background())

	if cgAPIKey := os.Getenv("COINGECKO_API_KEY"); cgAPIKey != "" {
		r.prices = newCoinGecko(cgAPIKey, "usd", "ethereum")
	} else {
		r.prices = testingConverter{}
	}

	r.sessionIDsToSessionStates = NewMapRequestIDs[*SessionState]()
	r.opsInternal = make(chan RelayOp)

	r.ops = make(chan RelayOp, databaseOpsChanSize)
	r.shopIdsToShopState = NewMapEventIDs[*ShopState]()
	r.keyCardIDsToKeyCardSeqs = NewMapRequestIDs[*SeqPairKeyCard]()

	shopFieldFn := func(evt *ShopEvent, meta CachedMetadata) eventID {
		return meta.createdByShopID
	}
	r.shopManifestsByShopID = newReductionLoader[*CachedShopManifest](r, shopFieldFn, []eventType{eventTypeShopManifest, eventTypeUpdateShopManifest, eventTypeNewKeyCard}, "createdByShopId")
	itemsFieldFn := func(evt *ShopEvent, meta CachedMetadata) eventID {
		switch evt.Union.(type) {
		case *ShopEvent_CreateItem:
			return evt.GetCreateItem().EventId
		case *ShopEvent_UpdateItem:
			return evt.GetUpdateItem().ItemId
		case *ShopEvent_NewKeyCard:
			return evt.GetNewKeyCard().EventId
		}
		return nil
	}
	r.itemsByItemID = newReductionLoader[*CachedItem](r, itemsFieldFn, []eventType{eventTypeCreateItem, eventTypeUpdateItem}, "referenceId")
	tagsFieldFn := func(evt *ShopEvent, meta CachedMetadata) eventID {
		switch evt.Union.(type) {
		case *ShopEvent_CreateTag:
			return evt.GetCreateTag().EventId
		case *ShopEvent_UpdateTag:
			return evt.GetUpdateTag().TagId
		}
		return nil
	}
	r.tagsByTagID = newReductionLoader[*CachedTag](r, tagsFieldFn, []eventType{
		eventTypeCreateTag,
		eventTypeUpdateTag,
	}, "referenceId")

	ordersFieldFn := func(evt *ShopEvent, meta CachedMetadata) eventID {
		switch evt.Union.(type) {
		case *ShopEvent_CreateOrder:
			return evt.GetCreateOrder().EventId
		case *ShopEvent_UpdateOrder:
			return evt.GetUpdateOrder().OrderId
		case *ShopEvent_ChangeStock:
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

	r.stockByShopID = newReductionLoader[*CachedStock](r, shopFieldFn, []eventType{eventTypeChangeStock}, "createdByShopId")

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
	debug("relay.bulkInsert table=%s columns=%d rows=%d insertedRows=%d conflictingRows=%d elapsed=%d", table, len(columns), len(rows), len(insertedRows), len(conflictingRows), took(start))
	return insertedRows, conflictingRows
}

func (r *Relay) assertCursors(sessionID requestID, seqPair *SeqPairKeyCard, sessionState *SessionState) {
	err := r.checkCursors(sessionID, seqPair, sessionState)
	check(err)
}

func (r *Relay) checkCursors(_ requestID, seqPair *SeqPairKeyCard, sessionState *SessionState) error {
	if seqPair.lastUsedKCSeq < seqPair.lastWrittenKCSeq {
		return fmt.Errorf("cursor lastUsedShopSeq(%d) < lastWrittenShopSeq(%d)", seqPair.lastUsedKCSeq, seqPair.lastWrittenKCSeq)
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

func (r *Relay) hydrateShops(shopIds *SetEventIDs) {
	start := now()
	ctx := context.Background()
	novelShopIds := NewSetEventIDs()
	shopIds.All(func(shopId eventID) {
		if !r.shopIdsToShopState.Has(shopId) {
			novelShopIds.Add(shopId)
		}
	})
	if sz := novelShopIds.Size(); sz > 0 {
		novelShopIds.All(func(shopId eventID) {
			seqPair := &ShopState{}
			r.shopIdsToShopState.Set(shopId, seqPair)
		})
		for _, novelShopIdsSubslice := range subslice(novelShopIds.Slice(), 256) {
			// Index: events(createdByShopId, shopSeq)
			query := `select createdByShopId, max(shopSeq) from events where createdByShopId = any($1) group by createdByShopId`
			rows, err := r.connPool.Query(ctx, query, novelShopIdsSubslice)
			check(err)
			defer rows.Close()
			for rows.Next() {
				var shopID eventID
				var lastWrittenShopSeq *uint64
				err := rows.Scan(&shopID, &lastWrittenShopSeq)
				check(err)
				seqPair := r.shopIdsToShopState.MustGet(shopID)
				if lastWrittenShopSeq != nil {
					seqPair.lastWrittenShopSeq = *lastWrittenShopSeq
					seqPair.lastUsedShopSeq = *lastWrittenShopSeq
				}
			}
			check(rows.Err())
		}
	}
	elapsed := took(start)
	if novelShopIds.Size() > 0 || elapsed > 1 {
		log("relay.hydrateShops shops=%d novelShops=%d elapsed=%d", shopIds.Size(), novelShopIds.Size(), elapsed)
		r.metric.counterAdd("hydrate_users", float64(novelShopIds.Size()))
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
	query := fmt.Sprintf(`select serverSeq, shopSeq, eventId, referenceId, eventType, createdByKeyCardId, createdByShopId, createdAt, createdByNetworkSchemaVersion, encoded from events where %s order by serverSeq asc`, whereFragment)
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
		err := rows.Scan(&m.serverSeq, &m.shopSeq, &m.eventID, &m.referenceID, &eventType, &m.createdByKeyCardID, &m.createdByShopID, &createdAt, &m.createdByNetworkVersion, &encoded)
		check(err)
		m.createdAt = uint64(createdAt.Unix())
		var e ShopEvent
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
	evt     *ShopEvent
	pbany   *SignedEvent
}

func newEventInsert(evt *ShopEvent, meta CachedMetadata, abstract *SignedEvent) *EventInsert {
	meta.createdAt = uint64(now().Unix())
	return &EventInsert{
		CachedMetadata: meta,
		evt:            evt,
		pbany:          abstract,
	}
}

func (r *Relay) writeEvent(evt *ShopEvent, cm CachedMetadata, abstract *SignedEvent) {
	assert(r.writesEnabled)

	nextServerSeq := r.lastUsedServerSeq + 1
	cm.serverSeq = nextServerSeq
	r.lastUsedServerSeq = nextServerSeq

	shopSeqPair := r.shopIdsToShopState.MustGet(cm.createdByShopID)
	cm.shopSeq = shopSeqPair.lastUsedShopSeq + 1
	shopSeqPair.lastUsedShopSeq = cm.shopSeq

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

var dbEventInsertColumns = []string{"eventType", "eventId", "createdByKeyCardId", "createdByShopId", "shopSeq", "createdAt", "createdByNetworkSchemaVersion", "serverSeq", "encoded", "signature", "referenceID"}

func formInsert(ins *EventInsert) []interface{} {
	var (
		evtType eventType
		evtID   eventID
		refID   *eventID // used to stich together related events
	)
	switch ins.evt.Union.(type) {
	case *ShopEvent_ShopManifest:
		evtType = eventTypeShopManifest
		evtID = ins.evt.GetShopManifest().EventId
	case *ShopEvent_UpdateShopManifest:
		evtType = eventTypeUpdateShopManifest
		evtID = ins.evt.GetUpdateShopManifest().EventId
	case *ShopEvent_CreateItem:
		evtType = eventTypeCreateItem
		evtID = ins.evt.GetCreateItem().EventId
		refID = &evtID
	case *ShopEvent_UpdateItem:
		evtType = eventTypeUpdateItem
		ui := ins.evt.GetUpdateItem()
		evtID = ui.EventId
		refID = (*eventID)(&ui.ItemId)
	case *ShopEvent_CreateTag:
		evtType = eventTypeCreateTag
		evtID = ins.evt.GetCreateTag().EventId
		refID = &evtID
	case *ShopEvent_UpdateTag:
		evtType = eventTypeUpdateTag
		ut := ins.evt.GetUpdateTag()
		evtID = ut.EventId
		refID = (*eventID)(&ut.TagId)
	case *ShopEvent_ChangeStock:
		evtType = eventTypeChangeStock
		cs := ins.evt.GetChangeStock()
		evtID = cs.EventId
		if len(cs.OrderId) > 0 {
			refID = (*eventID)(&cs.OrderId)
		}
	case *ShopEvent_CreateOrder:
		evtType = eventTypeCreateOrder
		cc := ins.evt.GetCreateOrder()
		evtID = cc.EventId
		refID = &evtID
	case *ShopEvent_UpdateOrder:
		evtType = eventTypeUpdateOrder
		uo := ins.evt.GetUpdateOrder()
		evtID = uo.EventId
		refID = (*eventID)(&uo.OrderId)
	case *ShopEvent_NewKeyCard:
		evtType = eventTypeNewKeyCard
		evtID = ins.evt.GetNewKeyCard().EventId
	default:
		panic(fmt.Errorf("formInsert.unrecognizeType eventType=%T", ins.evt.Union))
	}
	return []interface{}{
		evtType,                     // eventType
		evtID,                       // eventId
		ins.createdByKeyCardID,      // createdByKeyCardId
		ins.createdByShopID,         // createdByShopId
		ins.shopSeq,                 // shopSeq
		now(),                       // createdAt
		ins.createdByNetworkVersion, // createdByNetworkSchemaVersion
		ins.serverSeq,               // serverSeq
		ins.pbany.Event.Value,       // encoded
		ins.pbany.Signature,         // signature
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
		rowShopID := row[3].(eventID)
		rowShopSeq := row[4].(uint64)
		shopSeqPair := r.shopIdsToShopState.MustGet(rowShopID)
		assert(shopSeqPair.lastWrittenShopSeq < rowShopSeq)
		assert(rowShopSeq <= shopSeqPair.lastUsedShopSeq)
		shopSeqPair.lastWrittenShopSeq = rowShopSeq
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

// returns true if the event is owned by the passed shop and keyCard
func (r *Relay) doesSessionOwnEvent(session *SessionState, eventID eventID) bool {
	ctx := context.Background()

	// crawl all keyCards of this user
	const checkOrderOwnershipQuery = `select count(*) from events
where createdByKeyCardId in (select id from keycards where userWalletAddr = (select userWalletAddr from keyCards where id = $1))
and createdByShopId = $2
and eventId = $3`
	var found int
	err := r.connPool.QueryRow(ctx, checkOrderOwnershipQuery, session.keyCardID, session.shopID, eventID).Scan(&found)
	check(err)
	return found == 1
}

// Loader is an interface for all loaders.
// Loaders represent the read-through cache layer.
type Loader interface {
	applyEvent(*EventInsert)
}

type fieldFn func(*ShopEvent, CachedMetadata) eventID

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
	var shopID requestID
	logS(op.sessionID, "relay.authenticateOp.idsQuery")
	ctx := context.Background()
	// Index: keyCards(publicKey)
	query := `select id, shopId from keyCards
	where cardPublicKey = $1 and unlinkedAt is null`
	err := r.connPool.QueryRow(ctx, query, op.im.PublicKey).Scan(&keyCardID, &shopID)
	if err == pgx.ErrNoRows {
		logS(op.sessionID, "relay.authenticateOp.idsQuery.noSuchKeyCard")
		op.err = notFoundError
		r.sendSessionOp(sessionState, op)
		return
	}
	check(err)
	logS(op.sessionID, "relay.authenticateOp.ids keyCardId=%s shopId=%s", keyCardID, shopID)

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
	} else if sessionState.shopID != nil {
		logS(op.sessionID, "relay.challengeSolvedOp.alreadyAuthenticated")
		op.err = alreadyAuthenticatedError
		r.sendSessionOp(sessionState, op)
		return
	}

	var keyCardPublicKey []byte
	var shopID eventID

	logS(op.sessionID, "relay.challengeSolvedOp.query")
	ctx := context.Background()
	// Index: keyCards(publicKey)
	query := `select cardPublicKey, shopId from keyCards
	where id = $1 and unlinkedAt is null`
	err := r.connPool.QueryRow(ctx, query, sessionState.keyCardID).Scan(&keyCardPublicKey, &shopID)
	if err == pgx.ErrNoRows {
		logS(op.sessionID, "relay.challengeSolvedOp.query.noSuchKeyCard")
		op.err = notFoundError
		r.sendSessionOp(sessionState, op)
		return
	}
	check(err)
	logS(op.sessionID, "relay.challengeSolvedOp.ids keyCardId=%s shopId=%s", sessionState.keyCardID, shopID)

	err = verifyChallengeResponse(keyCardPublicKey, sessionState.authChallenge, op.im.Signature)
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

	sessionState.shopID = shopID
	sessionState.initialStatus = false
	sessionState.nextPushIndex = 0
	sessionState.keyCardPublicKey = keyCardPublicKey

	// Establish shop seq.
	r.hydrateShops(NewSetEventIDs(sessionState.shopID))
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
	logS(op.sessionID, "relay.challengeSolvedOp.finish elapsed=%d", took(challengeSolvedOpStart))
}

// compute current shop hash
//
// until we need to verify proofs this is a pretty simple merkle tree with three intermediary nodes
// 1. the manifest
// 2. all published items (TODO: other tags?)
// 3. the stock counts
func (r *Relay) shopRootHash(shopID eventID) []byte {
	start := now()
	//log("relay.shopRootHash shopId=%s", shopID)

	shopManifest, has := r.shopManifestsByShopID.get(shopID)
	assertWithMessage(has, "no manifest for shopId")

	// 1. the manifest
	manifestHash := sha3.NewLegacyKeccak256()
	manifestHash.Write(shopManifest.shopTokenID)
	_, _ = fmt.Fprint(manifestHash, shopManifest.domain)
	manifestHash.Write(shopManifest.publishedTagID)
	//log("relay.shopRootHash manifest=%x", manifestHash.Sum(nil))

	// 2. all items in the published set
	publishedItemsHash := sha3.NewLegacyKeccak256()
	publishedTag, has := r.tagsByTagID.get(shopManifest.publishedTagID)
	if has {
		// iterating over sets is randomized in Go, sort them for consistency
		publishedItemIds := publishedTag.items.Slice()
		sort.Sort(publishedItemIds)

		for _, itemID := range publishedItemIds {
			item, has := r.itemsByItemID.get(itemID)
			assertWithMessage(has, fmt.Sprintf("failed to load published itemId=%s", itemID))
			publishedItemsHash.Write(item.itemID)
		}
		//log("relay.shopRootHash published=%x", publishedItemsHash.Sum(nil))
	}

	// TODO: other tags

	// 3. the stock
	stockHash := sha3.NewLegacyKeccak256()
	stock, has := r.stockByShopID.get(shopID)
	//assertWithMessage(has, "stock unavailable")
	if has {
		// TODO: we should probably always have a stock that's just empty
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
	if err := op.im.Event.Verify(sessionState.keyCardPublicKey); err != nil {
		logSR("relay.eventWriteOp.verifyEventFailed err=%s", sessionID, requestID, err.Error())
		op.err = &Error{Code: ErrorCodes_INVALID, Message: "invalid signature"}
		r.sendSessionOp(sessionState, op)
		return
	}

	meta := newMetadata(sessionState.keyCardID, sessionState.shopID, uint16(sessionState.version))
	if err := r.checkShopEventWriteConsistency(op.decodedShopEvt, meta, sessionState); err != nil {
		logSR("relay.eventWriteOp.checkEventFailed code=%s msg=%s", sessionID, requestID, err.Code, err.Message)
		op.err = err
		r.sendSessionOp(sessionState, op)
		return
	}

	// update shop
	r.beginSyncTransaction()
	r.writeEvent(op.decodedShopEvt, meta, op.im.Event)
	r.commitSyncTransaction()

	// compute resulting hash
	shopSeq := r.shopIdsToShopState.MustGet(sessionState.shopID)
	if shopSeq.lastUsedShopSeq >= 3 {
		hash := r.shopRootHash(sessionState.shopID)
		op.newShopHash = hash
	}
	op.eventSeq = shopSeq.lastWrittenShopSeq

	r.sendSessionOp(sessionState, op)
}

func (r *Relay) checkShopEventWriteConsistency(union *ShopEvent, m CachedMetadata, sess *SessionState) *Error {
	manifest, shopExists := r.shopManifestsByShopID.get(m.createdByShopID)
	shopManifestExists := shopExists && len(manifest.shopTokenID) > 0

	switch tv := union.Union.(type) {

	case *ShopEvent_ShopManifest:
		if sess.keyCardOfAGuest {
			return notFoundError
		}
		if shopManifestExists {
			return &Error{Code: ErrorCodes_INVALID, Message: "shop already exists"}
		}

	case *ShopEvent_UpdateShopManifest:
		if !shopManifestExists {
			return notFoundError
		}
		if sess.keyCardOfAGuest {
			return notFoundError
		}
		if p := tv.UpdateShopManifest.AddPayee; p != nil {
			if _, has := manifest.payees[p.Name]; has {
				return &Error{Code: ErrorCodes_INVALID, Message: "payee nickname already taken"}
			}
			for name, payee := range manifest.payees {
				if bytes.Equal(payee.Addr[:], p.Addr) && payee.ChainID == p.ChainId {
					return &Error{Code: ErrorCodes_INVALID, Message: "conflicting payee: " + name}
				}
			}
		}
		if p := tv.UpdateShopManifest.RemovePayee; p != nil {
			if _, has := manifest.payees[p.Name]; !has {
				return notFoundError
			}
		}
		// this feels like a pre-op validation step but we dont have access to the relay there
		if adds := tv.UpdateShopManifest.AddAcceptedCurrencies; len(adds) > 0 {
			for _, add := range adds {
				// check if already assigned
				c := cachedShopCurrency{
					common.Address(add.TokenAddr),
					add.ChainId,
				}
				if _, has := manifest.acceptedCurrencies[c]; has {
					return &Error{Code: ErrorCodes_INVALID, Message: "currency already in use"}
				}
				if !bytes.Equal(ZeroAddress[:], add.TokenAddr) {
					// validate existance of contract
					err := r.ethereum.CheckValidERC20Metadata(add.ChainId, common.Address(add.TokenAddr))
					if err != nil {
						return err
					}
				}
			}
		}
		if base := tv.UpdateShopManifest.SetBaseCurrency; base != nil {
			if !bytes.Equal(ZeroAddress[:], base.TokenAddr) {
				err := r.ethereum.CheckValidERC20Metadata(base.ChainId, common.Address(base.TokenAddr))
				if err != nil {
					return err
				}
			}
		}
	case *ShopEvent_CreateItem:
		if !shopManifestExists || sess.keyCardOfAGuest {
			log("relay.checkEventWrite.createItem manifestExists=%v isGuest=%v", shopManifestExists, sess.keyCardOfAGuest)
			return notFoundError
		}
		evt := union.GetCreateItem()
		_, itemExists := r.itemsByItemID.get(evt.EventId)
		if itemExists {
			return &Error{Code: ErrorCodes_INVALID, Message: "item already exists"}
		}

	case *ShopEvent_UpdateItem:
		if !shopManifestExists || sess.keyCardOfAGuest {
			log("relay.checkEventWrite.updateItem manifestExists=%v isGuest=%v", shopManifestExists, sess.keyCardOfAGuest)
			return notFoundError
		}
		evt := union.GetUpdateItem()
		item, itemExists := r.itemsByItemID.get(evt.ItemId)
		if !itemExists {
			return notFoundError
		}
		if !item.createdByShopID.Equal(sess.shopID) { // not allow to alter data from other shop
			return notFoundError
		}

	case *ShopEvent_CreateTag:
		if !shopManifestExists || sess.keyCardOfAGuest {
			return notFoundError
		}
		evt := union.GetCreateTag()
		_, tagExists := r.tagsByTagID.get(evt.EventId)
		if tagExists {
			return &Error{Code: ErrorCodes_INVALID, Message: "tag already exists"}
		}

	case *ShopEvent_UpdateTag:
		if !shopManifestExists || sess.keyCardOfAGuest {
			return notFoundError
		}
		evt := union.GetUpdateTag()
		tag, tagExists := r.tagsByTagID.get(evt.TagId)
		if !tagExists {
			return notFoundError
		}
		if !tag.createdByShopID.Equal(sess.shopID) { // not allow to alter data from other shops
			return notFoundError
		}
		if id := evt.AddItemId; len(id) > 0 {
			item, itemExists := r.itemsByItemID.get(id)
			if !itemExists {
				return notFoundError
			}
			if !item.createdByShopID.Equal(sess.shopID) { // not allow to alter data from other shops
				return notFoundError
			}
		}
		if id := evt.RemoveItemId; len(id) > 0 {
			item, itemExists := r.itemsByItemID.get(id)
			if !itemExists {
				return notFoundError
			}
			if !item.createdByShopID.Equal(sess.shopID) { // not allow to alter data from other shops
				return notFoundError
			}
		}
		if d := evt.Delete; d != nil && *d == false {
			return &Error{Code: ErrorCodes_INVALID, Message: "Can't undelete a tag"}
		}

	case *ShopEvent_ChangeStock:
		if !shopManifestExists || sess.keyCardOfAGuest {
			log("relay.checkEventWrite.changeStock manifestExists=%v isGuest=%v", shopManifestExists, sess.keyCardOfAGuest)
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
			if !item.createdByShopID.Equal(sess.shopID) { // not allow to alter data from other shops
				return notFoundError
			}
			shopStock, shopStockExists := r.stockByShopID.get(m.createdByShopID)
			if shopStockExists {
				items, has := shopStock.inventory.GetHas(itemID)
				if has && items+change < 0 {
					return &Error{Code: ErrorCodes_OUT_OF_STOCK, Message: "not enough stock"}
				}
			}
		}

	case *ShopEvent_CreateOrder:
		if !shopManifestExists {
			return notFoundError
		}
		evt := union.GetCreateOrder()
		_, orderExists := r.ordersByOrderID.get(evt.EventId)
		if orderExists {
			return &Error{Code: ErrorCodes_INVALID, Message: "order already exists"}
		}

	case *ShopEvent_UpdateOrder:
		if !shopManifestExists {
			return notFoundError
		}
		evt := union.GetUpdateOrder()
		order, orderExists := r.ordersByOrderID.get(evt.OrderId)
		if !orderExists {
			return notFoundError
		}
		if !order.createdByShopID.Equal(sess.shopID) { // not allow to alter data from other shops
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
			if !item.createdByShopID.Equal(sess.shopID) { // not allow to alter data from other shops
				return notFoundError
			}
			stock, has := r.stockByShopID.get(m.createdByShopID)
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

var (
	// TODO: defined in geth?
	ZeroAddress common.Address
)

func (op *CommitItemsToOrderOp) process(r *Relay) {
	ctx := context.Background()
	sessionID := op.sessionID
	requestID := op.im.RequestId
	sessionState := r.sessionIDsToSessionStates.Get(sessionID)
	if sessionState == nil {
		logS(sessionID, "relay.commitOrderOp.drain")
		return
	} else if sessionState.keyCardID == nil {
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

	stock, has := r.stockByShopID.get(sessionState.shopID)
	if !has {
		op.err = &Error{Code: ErrorCodes_INVALID, Message: "not enough stock"}
		r.sendSessionOp(sessionState, op)
		return
	}

	shop, has := r.shopManifestsByShopID.get(sessionState.shopID)
	if !has {
		op.err = &Error{Code: ErrorCodes_INVALID, Message: "shop not found"}
		r.sendSessionOp(sessionState, op)
		return
	}

	chosenCurrency := cachedShopCurrency{
		common.Address(op.im.Currency.TokenAddr),
		op.im.Currency.ChainId,
	}
	_, has = shop.acceptedCurrencies[chosenCurrency]
	if !has {
		op.err = &Error{Code: ErrorCodes_INVALID, Message: "chosen currency not available"}
		r.sendSessionOp(sessionState, op)
		return
	}

	// get all other orders that haven't been paid yet
	otherOrderRows, err := r.connPool.Query(ctx, `select orderId from payments where
	createdByShopId = $1 and
	orderId != $2 and
	orderPayedAt is null`, sessionState.shopID, op.im.OrderId)
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

		if !item.createdByShopID.Equal(sessionState.shopID) { // not allow to alter data from other shops
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

		usignErc20 = !bytes.Equal(ZeroAddress[:], chosenCurrency.Addr[:])
	)

	inBaseTokens := new(apd.Decimal)
	if usignErc20 {
		inErc20 := r.prices.FromFiatToERC20(fiatTotal, chosenCurrency.Addr)

		// get decimals count of this contract
		// TODO: since this is a contract constant we could cache it when adding the token
		tok, err := r.ethereum.GetERC20Metadata(chosenCurrency.ChainID, chosenCurrency.Addr)
		if err != nil {
			op.err = &Error{Code: ErrorCodes_INVALID, Message: err.Error()}
			r.sendSessionOp(sessionState, op)
			return
		}

		// let's not assume these contracts are static code
		if err := tok.validate(); err != nil {
			op.err = err
			r.sendSessionOp(sessionState, op)
			return
		}

		_, err = decimalCtx.Mul(inBaseTokens, inErc20, apd.New(1, int32(tok.decimals)))
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

	bigShopTokenID := new(big.Int).SetBytes(shop.shopTokenID)

	ownerAddr, err := r.ethereum.GetOwnerOfShop(bigShopTokenID)
	if err != nil {
		op.err = &Error{Code: ErrorCodes_INVALID, Message: err.Error()}
		r.sendSessionOp(sessionState, op)
		return
	}

	payee, has := shop.payees[op.im.PayeeName]
	if !has {
		op.err = &Error{Code: ErrorCodes_INVALID, Message: "no such payee"}
		r.sendSessionOp(sessionState, op)
		return
	}

	if payee.ChainID != chosenCurrency.ChainID {
		op.err = &Error{Code: ErrorCodes_INVALID, Message: "payee and chosenCurrency chain_id mismatch"}
		r.sendSessionOp(sessionState, op)
		return
	}

	// ttl
	blockNo, err := r.ethereum.GetCurrentBlockNumber(chosenCurrency.ChainID)
	if err != nil {
		logSR("relay.commitOrderOp.blockNumberFailed err=%s", sessionID, requestID, err)
		op.err = &Error{Code: ErrorCodes_INVALID, Message: "failed to get current block number"}
		r.sendSessionOp(sessionState, op)
		return
	}
	bigBlockNo := new(big.Int).SetInt64(int64(blockNo))

	block, err := r.ethereum.GetBlockByNumber(chosenCurrency.ChainID, bigBlockNo)
	if err != nil {
		logSR("relay.commitOrderOp.blockByNumberFailed block=%d err=%s", sessionID, requestID, blockNo, err)
		op.err = &Error{Code: ErrorCodes_INVALID, Message: "failed to get block by number"}
		r.sendSessionOp(sessionState, op)
		return
	}

	var pr = PaymentRequest{}
	pr.ChainId = new(big.Int).SetUint64(payee.ChainID)
	pr.Ttl = new(big.Int).SetUint64(block.Time() + DefaultPaymentTTL)
	pr.Order = receiptHash
	pr.Currency = chosenCurrency.Addr
	pr.Amount = bigTotal
	pr.PayeeAddress = payee.Addr
	pr.IsPaymentEndpoint = payee.isEndpoint
	pr.ShopId = bigShopTokenID
	// TODO: calculate signature
	pr.ShopSignature = bytes.Repeat([]byte{0}, 64)

	paymentId, paymentAddr, err := r.ethereum.GetPaymentIDAndAddress(chosenCurrency.ChainID, &pr, ownerAddr)
	if err != nil {
		op.err = &Error{Code: ErrorCodes_INVALID, Message: err.Error()}
		r.sendSessionOp(sessionState, op)
		return
	}

	logSR("relay.commitOrderOp.paymentRequest id=%x addr=%x total=%s currentBlock=%d", sessionID, requestID, paymentId, paymentAddr, bigTotal.String(), blockNo)

	// mark order as finalized by creating the event and updating payments table
	var (
		fin UpdateOrder_ItemsFinalized
		w   PaymentWaiter
	)
	fin.PaymentId = paymentId

	fin.SubTotal = roundPrice(fiatSubtotal).Text('f')
	fin.SalesTax = roundPrice(salesTax).Text('f')
	fin.Total = roundPrice(fiatTotal).Text('f')

	fin.Ttl = pr.Ttl.String()
	fin.OrderHash = receiptHash[:]
	fin.CurrencyAddr = chosenCurrency.Addr[:]
	var uint256 = make([]byte, 32)
	bigTotal.FillBytes(uint256)
	fin.TotalInCrypto = uint256
	fin.PayeeAddr = payee.Addr[:]
	fin.IsPaymentEndpoint = payee.isEndpoint
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
	w.purchaseAddr = paymentAddr
	w.chainID = chosenCurrency.ChainID
	w.lastBlockNo.SetInt64(int64(blockNo))
	w.coinsTotal.Set(bigTotal)
	w.coinsPayed.SetInt64(0)
	w.paymentId = paymentId

	if usignErc20 {
		w.erc20TokenAddr = &chosenCurrency.Addr
	}

	cfMetadata := newMetadata(relayKeyCardID, sessionState.shopID, currentRelayVersion)
	cfEvent := &ShopEvent{Union: &ShopEvent_UpdateOrder{update}}

	cfAny, err := anypb.New(cfEvent)
	if err != nil {
		op.err = &Error{Code: ErrorCodes_INVALID, Message: "interal server error"}
		r.sendSessionOp(sessionState, op)
		return
	}

	sig, err := r.ethereum.signEvent(cfAny.Value)
	if err != nil {
		op.err = &Error{Code: ErrorCodes_INVALID, Message: "interal server error"}
		r.sendSessionOp(sessionState, op)
		return
	}

	r.beginSyncTransaction()
	r.writeEvent(cfEvent, cfMetadata, &SignedEvent{Event: cfAny, Signature: sig})

	seqPair := r.shopIdsToShopState.MustGet(sessionState.shopID)
	const insertPaymentWaiterQuery = `insert into payments (waiterId, shopSeqNo, createdByShopId, orderId, orderFinalizedAt, purchaseAddr, lastBlockNo, coinsPayed, coinsTotal, erc20TokenAddr, paymentId, chainId)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`
	_, err = r.syncTx.Exec(ctx, insertPaymentWaiterQuery,
		w.waiterID, seqPair.lastUsedShopSeq, order.createdByShopID, w.orderID, w.orderFinalizedAt, w.purchaseAddr.Bytes(), w.lastBlockNo, w.coinsPayed, w.coinsTotal, w.erc20TokenAddr, w.paymentId, w.chainID)
	check(err)

	r.commitSyncTransaction()

	op.orderFinalizedID = update.EventId

	if usignErc20 {
		ctx = context.TODO()
		r.watcherContextERC20Cancel()
		r.watcherContextERC20, r.watcherContextERC20Cancel = context.WithCancel(ctx)
	} else {
		ctx = context.TODO()
		r.watcherContextEtherCancel()
		r.watcherContextEther, r.watcherContextEtherCancel = context.WithCancel(ctx)
	}

	logSR("relay.commitOrderOp.finish took=%d", sessionID, requestID, took(start))
	r.sendSessionOp(sessionState, op)
}

func (op *GetBlobUploadURLOp) process(r *Relay) {
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
	uploadURL = *r.baseURL
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
	log("db.KeyCardEnrolledOp.start shopId=%s", op.shopID)
	start := now()

	r.hydrateShops(NewSetEventIDs(op.shopID))

	ctx := context.Background()
	r.beginSyncTransaction()

	// get other keycards for public key
	const previousKeyCardsQuery = `select id from keyCards where userWalletAddr = $1 and id != $2 and shopId = $3`
	prevRows, err := r.syncTx.Query(ctx, previousKeyCardsQuery, op.userWallet, op.keyCardDatabaseID, op.shopID)
	check(err)
	defer prevRows.Close()

	sameUserOrdersMap := NewMapRequestIDs[*SetEventIDs]()
	for prevRows.Next() {
		var kcId requestID
		err = prevRows.Scan(&kcId)
		check(err)

		sameUserOrdersMap.Set(kcId, NewSetEventIDs())
	}
	check(prevRows.Err())

	// replay previous shop history
	const existingShopEventsQuery = `select eventId, eventType, serverSeq, createdByKeyCardId, referenceId
from events
where createdByShopId = $1
order by serverSeq`
	evtRows, err := r.connPool.Query(ctx, existingShopEventsQuery, op.shopID)
	check(err)
	defer evtRows.Close()

	var kcEvents []KeyCardEvent
	kcSeqs := r.keyCardIDsToKeyCardSeqs.GetOrCreate(op.keyCardDatabaseID, func(_ requestID) *SeqPairKeyCard { return &SeqPairKeyCard{} })
	for evtRows.Next() {
		var (
			kcEvt              KeyCardEvent
			eventType          eventType
			createdByKeyCardID requestID
			evtID              eventID
			referenceID        *eventID
		)
		err = evtRows.Scan(&evtID, &eventType, &kcEvt.serverSeq, &createdByKeyCardID, &referenceID)
		check(err)

		switch eventType {
		// staff + that customer
		case eventTypeNewKeyCard:
			fallthrough
		case eventTypeChangeStock:
			fallthrough
		case eventTypeCreateOrder:
			s := sameUserOrdersMap.GetOrCreate(createdByKeyCardID, func(_ requestID) *SetEventIDs { return NewSetEventIDs() })
			s.Add(evtID)
			fallthrough
		case eventTypeUpdateOrder:
			isFromRelay := bytes.Equal(createdByKeyCardID, relayKeyCardID)

			orders, has := sameUserOrdersMap.GetHas(createdByKeyCardID)

			// if its a guest, they get an event if its from one of their previous keycards,
			// or if it's a keycard from a clerk
			if op.keyCardIsGuest && !(has || (referenceID != nil && orders.Has(*referenceID) && isFromRelay)) {
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
			keyCardEventRows[i] = []interface{}{ue.keyCardId, ue.keyCardSeq, ue.serverSeq}
		}
		insertedRows, _ := r.bulkInsert("keyCardEvents", []string{"keyCardId", "keyCardSeq", "serverSeq"}, keyCardEventRows)
		assertWithMessage(len(insertedRows) == len(kcEvents), "new keycard log isnt empty")
	}

	// emit new keycard event
	evt := &ShopEvent{
		Union: &ShopEvent_NewKeyCard{NewKeyCard: &NewKeyCard{
			EventId:        newEventID(),
			CardPublicKey:  op.keyCardPublicKey,
			UserWalletAddr: op.userWallet[:],
		}},
	}

	var sigEvt SignedEvent
	sigEvt.Event, err = anypb.New(evt)
	check(err)

	sigEvt.Signature, err = r.ethereum.signEvent(sigEvt.Event.Value)
	check(err)

	meta := newMetadata(relayKeyCardID, op.shopID, currentRelayVersion)
	r.writeEvent(evt, meta, &sigEvt)

	r.commitSyncTransaction()
	close(op.done)
	log("db.KeyCardEnrolledOp.finish shopId=%s took=%d", op.shopID, took(start))
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
		createdByShopID:         order.createdByShopID,
		createdByNetworkVersion: currentRelayVersion,
	}
	r.hydrateShops(NewSetEventIDs(order.createdByShopID))
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

	evt := &ShopEvent{Union: &ShopEvent_ChangeStock{ChangeStock: cs}}

	var sigEvt SignedEvent
	sigEvt.Event, err = anypb.New(evt)
	check(err)

	sigEvt.Signature, err = r.ethereum.signEvent(sigEvt.Event.Value)
	check(err)

	r.writeEvent(evt, meta, &sigEvt)
	r.commitSyncTransaction()
	log("db.paymentFoundInternalOp.finish orderID=%s took=%d", op.orderID, took(start))
	close(op.done)
}

func (op *EventLoopPingInternalOp) getSessionID() requestID { panic("not implemented") }
func (op *EventLoopPingInternalOp) setErr(_ *Error)         { panic("not implemented") }

func (op *EventLoopPingInternalOp) process(r *Relay) {
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
			r.metric.counterAdd("sessions_kick", 1)
			logS(sessionId, "relay.debounceSessions.kick")
			op := &StopOp{sessionID: sessionId}
			r.sendSessionOp(sessionState, op)
			return
		}

		// Don't try to do anything else if the session isn't even authenticated yet.
		if sessionState.shopID == nil {
			return
		}

		// If the session is authenticated, we can get user info.
		seqPair := r.keyCardIDsToKeyCardSeqs.MustGet(sessionState.keyCardID)
		r.assertCursors(sessionId, seqPair, sessionState)

		// Calculate the new keyCard seq up to which the device has acked all pushes.
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
			logS(sessionId, "relay.debounceSessions.advanceKCSeq reason=entries from=%d to=%d", advancedFrom, advancedTo)
			r.assertCursors(sessionId, seqPair, sessionState)
		}

		// Check if a sync status is needed, and if so query and send it.
		// Use the boolean to ensure we always send an initial sync status for the session,
		// including if the user has no writes yet.
		// If everything for the device has been pushed, advance the buffered and pushed cursors too.
		if !sessionState.initialStatus || sessionState.lastStatusedKCSeq < seqPair.lastWrittenKCSeq {
			syncStatusStart := now()
			op := &SyncStatusOp{sessionID: sessionId}
			// Index: keyCardEvents(keyCardId, serverSeq) -> events(createdByShopId, serverSeq)
			query := `select count(*) from keyCardEvents kce, events e
where kce.serverSeq = e.serverSeq
  and e.createdByShopId = $1
  and kce.keyCardSeq > $2
  and e.createdByKeyCardId != $3`
			err := r.connPool.QueryRow(ctx, query, sessionState.shopID, sessionState.lastPushedKCSeq, sessionState.keyCardID).
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
			logS(sessionId, "relay.debounceSessions.syncStatus initialStatus=%t unpushedEvents=%d elapsed=%d", sessionState.initialStatus, op.unpushedEvents, took(syncStatusStart))
			r.assertCursors(sessionId, seqPair, sessionState)
		}

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
			// Index: events(shopId, shopSeq)
			query := `select kce.keycardseq, e.eventId, e.encoded, e.signature
from events e, keyCardEvents kce
where kce.serverSeq = e.serverSeq
    and e.createdByShopId = $1
    and kce.keyCardSeq > $2
    and kce.keyCardId = $3
	and e.createdByKeyCardId != $3
order by kce.keyCardSeq asc limit $4`
			rows, err := r.connPool.Query(ctx, query, sessionState.shopID, sessionState.lastPushedKCSeq, sessionState.keyCardID, readsAllowed)
			check(err)
			defer rows.Close()
			for rows.Next() {
				var (
					eventState         = &EventState{}
					encoded, signature []byte
				)
				err := rows.Scan(&eventState.kcSeq, &eventState.eventID, &encoded, &signature)
				check(err)
				reads++
				// log("relay.debounceSessions.debug event=%x", eventState.eventID)

				eventState.acked = false
				sessionState.buffer = append(sessionState.buffer, eventState)
				assert(eventState.kcSeq > sessionState.lastBufferedKCSeq)
				sessionState.lastBufferedKCSeq = eventState.kcSeq

				// re-create pb object from encoded database data
				eventState.encodedEvent.Event = &anypb.Any{
					// TODO: would prever to not craft this manually
					TypeUrl: shopEventTypeURL,
					Value:   encoded,
				}
				eventState.encodedEvent.Signature = signature
			}
			check(rows.Err())

			// If the read rows didn't use the full limit, that means we must be at the end
			// of this user's writes.
			if reads < readsAllowed {
				sessionState.lastBufferedKCSeq = seqPair.lastWrittenKCSeq
			}

			logS(sessionId, "relay.debounceSessions.read shopId=%s reads=%d readsAllowed=%d bufferLen=%d lastWrittenKCSeq=%d, lastBufferedKCSeq=%d elapsed=%d", sessionState.shopID, reads, readsAllowed, len(sessionState.buffer), seqPair.lastWrittenKCSeq, sessionState.lastBufferedKCSeq, took(readStart))
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
		// logS(sessionId, "relay.debounce.cursors lastWrittenKCSeq=%d lastStatusedshopSeq=%d lastBufferedshopSeq=%d lastPushedshopSeq=%d lastAckedKCSeq=%d", userState.lastWrittenKCSeq, sessionState.lastStatusedshopSeq, sessionState.lastBufferedshopSeq, sessionState.lastPushedshopSeq, sessionState.lastAckedKCSeq)
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
	debug("relay.debounceEventPropagations.list events=%d took=%d", len(eventIds), took(start))

	// Read in event data for listed event IDs.
	readStart := now()
	events := r.readEvents(`eventId = any($1)`, eventIds)
	debug("relay.debounceEventPropagations.read took=%d", took(readStart))

	// Compute new keyCardEvent tuples propagating for all listed events.
	deriveStart := now()
	keyCardEvents := make([]*KeyCardEvent, 0)

	// FIXME: guest overhaul
	sameUserOrdersMap := NewMapRequestIDs[*SetEventIDs]()

	for _, e := range events {
		shopState, exists := r.shopManifestsByShopID.get(e.createdByShopID)
		assert(exists)
		fanOutKeyCards := shopState.getValidKeyCardIDs(r.connPool)

		// FIXME: guest overhaul
		query = `select eventID from events where eventType = 'createOrder' and createdByKeyCardID = $1`
		for _, kc := range fanOutKeyCards {
			if kc.isGuest {
				s := sameUserOrdersMap.GetOrCreate(kc.id, func(key requestID) *SetEventIDs { return NewSetEventIDs() })
				rows, err := r.connPool.Query(ctx, query, kc.id)
				check(err)
				for rows.Next() {
					var evtID eventID
					err = rows.Scan(&evtID)
					check(err)
					s.Add(evtID)
				}
				check(rows.Err())
				rows.Close()
			}
		}

		switch e.evtType {

		// staff + that customer
		// -===================-
		case eventTypeCreateOrder:
			fallthrough
		case eventTypeUpdateOrder:
			isFromRelay := bytes.Equal(e.createdByKeyCardID, relayKeyCardID)

			for _, kc := range fanOutKeyCards {
				orders, hasOrders := sameUserOrdersMap.GetHas(kc.id)
				if !kc.isGuest || (e.createdByKeyCardID.Equal(kc.id) || (isFromRelay && hasOrders && orders.Has(e.referenceID))) {
					keyCardEvents = append(keyCardEvents, &KeyCardEvent{
						keyCardId: kc.id,
						serverSeq: e.serverSeq,
					})
				}
			}

		// public
		// -====-
		case eventTypeNewKeyCard:
			// first user
			if len(fanOutKeyCards) == 0 {
				keyCardEvents = append(keyCardEvents, &KeyCardEvent{
					keyCardId: e.createdByKeyCardID,
					serverSeq: e.serverSeq,
				})
			}
			fallthrough
		case eventTypeShopManifest:
			fallthrough
		case eventTypeUpdateShopManifest:
			fallthrough
		case eventTypeCreateItem:
			fallthrough
		case eventTypeUpdateItem:
			fallthrough
		case eventTypeCreateTag:
			fallthrough
		// TODO: just for the demo
		case eventTypeChangeStock:
			fallthrough
		case eventTypeUpdateTag:
			for _, kc := range fanOutKeyCards {
				keyCardEvents = append(keyCardEvents, &KeyCardEvent{
					keyCardId: kc.id,
					serverSeq: e.serverSeq,
				})
			}
		default:
			panic(fmt.Sprintf("unhandeled event type: %s", e.evtType))
		}
	}
	for _, kce := range keyCardEvents {
		kce.keyCardId.assert()
		assert(kce.serverSeq != 0)
		assert(kce.keyCardSeq == 0)
	}
	debug("relay.debounceEventPropagations.derive keyCardEvents=%d took=%d", len(keyCardEvents), took(deriveStart))

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
	debug("relay.debounceEventPropagations.enrich took=%d", took(enrichStart))

	// Insert derived and enriched keyCardEvents.
	insertStart := now()
	keyCardEventRows := make([][]any, len(keyCardEvents))
	for i, ue := range keyCardEvents {
		keyCardEventRows[i] = []interface{}{ue.keyCardId, ue.keyCardSeq, ue.serverSeq}
	}
	insertedRows, _ := r.bulkInsert("keyCardEvents", []string{"keyCardId", "keyCardSeq", "serverSeq"}, keyCardEventRows)
	for _, row := range insertedRows {
		kcID := row[0].(requestID)
		kcSeq := row[1].(uint64)
		seqPair := r.keyCardIDsToKeyCardSeqs.MustGet(kcID)
		assert(seqPair.lastWrittenKCSeq < kcSeq)
		assert(kcSeq <= seqPair.lastUsedKCSeq)
		seqPair.lastWrittenKCSeq = kcSeq
	}
	debug("relay.debounceEventPropagations.insert inserted=%d took=%d", len(insertedRows), took(insertStart))

	// Delete from eventPropagations now that we've completed these propagations.
	deleteStart := now()
	query = `delete from eventPropagations ep where eventId = any($1)`
	_, err = r.connPool.Exec(ctx, query, eventIds)
	check(err)
	debug("relay.debounceEventPropagations.delete took=%d", took(deleteStart))

	debug("relay.debounceEventPropagations.finish took=%d", took(start))
}

func (r *Relay) memoryStats() {
	start := now()
	debug("relay.memoryStats.start")

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
	r.metric.emit("relay.cached.shops", uint64(r.shopIdsToShopState.Size()))

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
	debug("relay.memoryStats.finish took=%d", memoryStatsTook)
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
	mu                sync.Mutex
	name2gauge        map[string]prometheus.Gauge
	name2counter      map[string]prometheus.Counter
	httpStatusCodes   *prometheus.CounterVec
	httpResponseTimes *prometheus.GaugeVec
}

func newMetric() *Metric {
	return &Metric{
		name2gauge:   make(map[string]prometheus.Gauge),
		name2counter: make(map[string]prometheus.Counter),
		httpStatusCodes: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "http_response_codes",
		}, []string{"status", "path"}),
		httpResponseTimes: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "http_response_times",
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

	m.mu.Lock()
	defer m.mu.Unlock()

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
	m.mu.Lock()
	defer m.mu.Unlock()

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

func (r *Relay) getOrCreateInternalShopID(shopTokenID big.Int) eventID {
	var (
		shopID eventID
		ctx    = context.Background()
	)
	err := r.connPool.QueryRow(ctx, `select id from shops where tokenId = $1`, shopTokenID.String()).Scan(&shopID)
	if err == nil {
		return shopID
	}
	if err != pgx.ErrNoRows {
		check(err)
	}

	shopID = newEventID()
	_, err = r.connPool.Exec(ctx, `insert into shops (id, tokenId) values ($1, $2)`, shopID, shopTokenID.String())
	check(err)
	return shopID
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

		var dlURL = *r.baseURL
		dlURL.Path = uploadedCid.String()

		const status = http.StatusCreated
		w.WriteHeader(status)
		err = json.NewEncoder(w).Encode(map[string]any{"ipfs_path": dlURL.Path, "url": dlURL.String()})
		if err != nil {
			log("relay.blobUpload.writeFailed err=%s", err)
			// returning nil since responding with an error is not possible at this point
		}
		return status, nil
	}
	return func(w http.ResponseWriter, req *http.Request) {
		start := now()
		code, err := fn(w, req)
		r.metric.httpStatusCodes.WithLabelValues(strconv.Itoa(code), req.URL.Path).Inc()
		r.metric.httpResponseTimes.WithLabelValues(strconv.Itoa(code), req.URL.Path).Set(tookF(start))
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

func ipfsCatHandleFunc() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		client, err := getIpfsClient(ctx, 0, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		ipfsPath, err := ipfsPath.NewPath(req.URL.Path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()

		node, err := client.Unixfs().Get(ctx, ipfsPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		sz, err := node.Size()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		f, ok := node.(ipfsFiles.File)
		if !ok {
			http.Error(w, "Not a file", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(int(sz)))
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, f)
	}
}

// once a user is registered, they need to sign their keycard
func enrollKeyCardHandleFunc(_ uint, r *Relay) func(http.ResponseWriter, *http.Request) {
	type requestData struct {
		Message   string `json:"message"`
		Signature []byte `json:"signature"`
	}

	fn := func(w http.ResponseWriter, req *http.Request) (int, error) {
		var data requestData
		err := json.NewDecoder(req.Body).Decode(&data)
		if err != nil {
			return http.StatusBadRequest, fmt.Errorf("invalid json: %w", err)
		}

		recoveredPubKey, err := ecrecoverEIP191([]byte(data.Message), data.Signature)
		if err != nil {
			return http.StatusBadRequest, fmt.Errorf("invalid signature: %w", err)
		}

		recoveredECDSAPubKey, err := crypto.UnmarshalPubkey(recoveredPubKey)
		if err != nil {
			return http.StatusBadRequest, fmt.Errorf("unmarshalPubkey failed: %w", err)
		}
		userWallet := crypto.PubkeyToAddress(*recoveredECDSAPubKey)

		msg, err := siwe.ParseMessage(data.Message)
		if err != nil {
			return http.StatusBadRequest, fmt.Errorf("invalid ERC-4361 message: %w", err)
		}

		referer := req.Referer()
		if referer != "" {
			// website logging into the relay as a remote service
			refererURL, err := url.Parse(referer)
			if err != nil {
				return http.StatusBadRequest, fmt.Errorf("bad referer")
			}

			// assuming the enrollment is directly on the relay
			if msg.GetDomain() != refererURL.Host {
				return http.StatusBadRequest, fmt.Errorf("referered domain did not match")
			}

			siweUri := msg.GetURI()
			if siweUri.Host != refererURL.Host {
				return http.StatusBadRequest, fmt.Errorf("refered URI did not match")
			}

			/* TODO: not sure how to scope this
			if siweUri.Path != req.URL.Path {
				return http.StatusBadRequest, fmt.Errorf("URI path did not match")
			}
			*/

		} else {
			// assuming the enrollment is directly on the relay
			if msg.GetDomain() != r.baseURL.Host {
				return http.StatusBadRequest, fmt.Errorf("domain did not match")
			}

			siweUri := msg.GetURI()
			if siweUri.Host != r.baseURL.Host {
				return http.StatusBadRequest, fmt.Errorf("domain did not match")
			}

			if siweUri.Path != req.URL.Path {
				return http.StatusBadRequest, fmt.Errorf("URI path did not match")
			}
		}

		if userWallet.Cmp(msg.GetAddress()) != 0 {
			return http.StatusBadRequest, fmt.Errorf("recovered and supplied address dont match")
		}

		if msg.GetNonce() != "00000000" {
			return http.StatusBadRequest, fmt.Errorf("invalid nonce")
		}

		resources := msg.GetResources()
		if n := len(resources); n != 3 {
			return http.StatusBadRequest, fmt.Errorf("expected 3 resources but got %d", n)
		}

		resRelayID := resources[0]
		if resRelayID.Scheme != "mass-relayid" {
			return http.StatusBadRequest, fmt.Errorf("unexpected url scheme for relayid")
		}
		var relayShopID big.Int
		_, ok := relayShopID.SetString(resRelayID.Opaque, 10)
		if !ok {
			return http.StatusBadRequest, fmt.Errorf("invalid relayID")
		}
		if relayShopID.Cmp(r.ethereum.relayTokenID) != 0 {
			return http.StatusBadRequest, fmt.Errorf("request is not for this relay")
		}

		resShopID := resources[1]
		if resShopID.Scheme != "mass-shopid" {
			return http.StatusBadRequest, fmt.Errorf("unexpected url scheme for shopid")
		}
		var shopTokenID big.Int
		_, ok = shopTokenID.SetString(resShopID.Opaque, 10)
		if !ok {
			return http.StatusBadRequest, fmt.Errorf("invalid shopID")
		}

		resKeyCard := resources[2]
		if resKeyCard.Scheme != "mass-keycard" {
			return http.StatusBadRequest, fmt.Errorf("unexpected url scheme for keyCard")
		}

		keyCardStr := strings.TrimPrefix(resKeyCard.Opaque, "0x")
		keyCardPublicKey, err := hex.DecodeString(keyCardStr)
		if err != nil {
			return http.StatusBadRequest, fmt.Errorf("invalid hex encoding of keycard: %w", err)
		}

		if n := len(keyCardPublicKey); n != 64 {
			return http.StatusBadRequest, fmt.Errorf("keyCardPublicKey length is not 64 but %d", n)
		}

		//  check if shop exists
		_, err = r.ethereum.GetOwnerOfShop(&shopTokenID)
		if err != nil {
			return http.StatusBadRequest, fmt.Errorf("no owner for shop: %w", err)
		}

		var isGuest bool = req.URL.Query().Get("guest") == "1"
		if !isGuest {
			has, err := r.ethereum.ClerkHasAccess(&shopTokenID, userWallet)
			if err != nil {
				return http.StatusInternalServerError, fmt.Errorf("contract call error: %w", err)
			}
			log("relay.enrollKeyCard.verifyAccess shopTokenID=%s userWallet=%s has=%v", shopTokenID.String(), userWallet.Hex(), has)
			if !has {
				return http.StatusForbidden, errors.New("access denied")
			}
		}

		dbCtx := context.Background()
		shopID := r.getOrCreateInternalShopID(shopTokenID)
		newKeyCardID := newRequestID()
		const insertKeyCard = `insert into keyCards (id, shopId, cardPublicKey, userWalletAddr, linkedAt, lastAckedKCSeq, lastSeenAt, lastVersion, isGuest)
		VALUES ($1, $2, $3, $4, now(), 0, now(), $5, $6)`
		_, err = r.connPool.Exec(dbCtx, insertKeyCard, newKeyCardID, shopID, keyCardPublicKey, userWallet, currentRelayVersion, isGuest)
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

		op := &KeyCardEnrolledInternalOp{
			shopID:            shopID,
			keyCardIsGuest:    isGuest,
			keyCardDatabaseID: newKeyCardID,
			keyCardPublicKey:  keyCardPublicKey,
			userWallet:        userWallet,
			done:              make(chan struct{}),
		}
		r.opsInternal <- op
		<-op.done
		return http.StatusCreated, nil
	}
	return func(w http.ResponseWriter, req *http.Request) {
		start := now()
		code, err := fn(w, req)
		r.metric.httpStatusCodes.WithLabelValues(strconv.Itoa(code), req.URL.Path).Inc()
		r.metric.httpResponseTimes.WithLabelValues(strconv.Itoa(code), req.URL.Path).Set(tookF(start))
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
				log("relay.health.errFailed error=%s", err)
			}
			return
		}

		wait, op := NewEventLoopPing()
		r.opsInternal <- op

		select {
		case <-time.After(15 * time.Second):
			log("relay.health.evtLoop.fail")
			w.WriteHeader(500)
			r.metric.httpStatusCodes.WithLabelValues("500", req.URL.Path).Inc()
			_, err = fmt.Fprintln(w, "event loop unavailable")
			if err != nil {
				log("relay.health.errFailed error=%s", err)
			}
			return
		case <-wait:
		}

		log("relay.health.pass")
		_, err = fmt.Fprintln(w, "health OK")
		if err != nil {
			log("relay.health.okFailed error=%s", err)
			return
		}
		r.metric.httpStatusCodes.WithLabelValues("200", req.URL.Path).Inc()
		r.metric.httpResponseTimes.WithLabelValues("200", req.URL.Path).Set(tookF(start))
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
	log("relay.start port=%d logMessages=%t simulateErrorRate=%d simulateIgnoreRate=%d sessionPingInterval=%s, sessionKickTimeout=%s",
		port, logMessages, simulateErrorRate, simulateIgnoreRate, sessionPingInterval, sessionKickTimeout)

	metric := newMetric()

	r := newRelay(metric)
	r.connect()
	r.writesEnabled = true
	go r.run()

	// spawn payment watchers
	type watcher struct {
		name string
		fn   func(*ethClient) error
	}
	var (
		fns = []watcher{
			{"paymentMade", r.subscribeFilterLogsPaymentsMade},
			{"erc20", r.subscribeFilterLogsERC20Transfers},
			{"vanilla-eth", r.subscribeNewHeadsForEther},
		}
	)

	for _, geth := range r.ethereum.chains {
		for _, w := range fns {
			go func(w watcher, c *ethClient) {
				log("watcher.spawned name=%s chainId=%d", w.name, c.chainID)

				ticker := NewReusableTimer(ethereumBlockInterval / 2)
				countError := repeat.FnOnError(repeat.FnES(func(err error) {
					debug("watcher.error name=%s chainId=%d err=%s", w.name, c.chainID, err)
					r.metric.counterAdd("relay_watchError_error", 1)
				}))
				waitForNextBlock := repeat.FnOnSuccess(repeat.FnS(func() {
					log("watcher.success name=%s", w.name)
					/* this is "a bit" ugly.
					   go doesn't let us add select cases conditionally.
					   but we only need break out early (context cancel) for etherByAddress since that is using newHeads
					   this is in reality only needed to make the tests performant, too.
					   without this, the payment in the test might happen before the watcher resets
					*/
					if w.name == "vanilla-eth" {
						select {
						case <-ticker.C:
							debug("watcher.blockTimerDone name=%s", w.name)
						case <-r.watcherContextEther.Done():
							debug("watcher.etherCanceled name=%s", w.name)
						}
					} else {
						<-ticker.C
					}
					ticker.Rewind()
				}))
				delay := repeat.FullJitterBackoff(250 * time.Millisecond)
				delay.MaxDelay = ethereumBlockInterval
				_ = repeat.Repeat(repeat.Fn(func() error { return w.fn(c) }),
					waitForNextBlock,
					countError,
					repeat.WithDelay(delay.Set()),
				)
				panic("unreachable")
			}(w, geth)
		}
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

	// Reliablity Kludge
	mux.HandleFunc("/ipfs/", ipfsCatHandleFunc())

	corsOpts := cors.Options{
		AllowedOrigins: []string{"*"},
	}
	if isDevEnv {
		mux.HandleFunc("/testing/discovery", r.ethereum.discoveryHandleFunc)
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
