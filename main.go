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
	"encoding/binary"
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
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
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
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Server configuration.
const (
	sessionLastSeenAtFlushLimit   = 30 * time.Second
	sessionLastAckedSeqFlushLimit = 4096
	sessionBufferSizeRefill       = limitMaxOutRequests * limitMaxOutBatchSize
	sessionBufferSizeMax          = limitMaxOutRequests * limitMaxOutBatchSize * 2

	watcherTimeout           = 5 * time.Second
	databaseDebounceInterval = 100 * time.Millisecond
	tickStatsInterval        = 1 * time.Second
	tickBlockThreshold       = 50 * time.Millisecond
	memoryStatsInterval      = 5 * time.Second
	emitUptimeInterval       = 10 * time.Second

	databaseOpsChanSize           = 64 * 1024
	databasePropagationEventLimit = 5000

	DefaultPaymentTTL = 60 * 60 * 24
)

// set by build script via ldflags
var release = "unset"

var (
	// TODO: defined in geth?
	ZeroAddress common.Address
)

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
	networkVersions            = []uint{3}
	currentRelayVersion uint16 = 3
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

// Op are operations that are sent to the database
type Op interface {
	getSessionID() sessionID // Generated
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
	sessionID      sessionID
	sessionVersion uint
	sessionOps     chan SessionOp
	err            *Error
}

// StopOp stops a session
type StopOp struct {
	sessionID sessionID
	err       *Error
}

// HeartbeatOp triggers a PingRequest to the connected client
type HeartbeatOp struct {
	sessionID sessionID
	err       *Error
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
	err            *Error
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

type SubscriptionRequestOp struct {
	sessionID      sessionID
	requestID      *RequestId
	im             *SubscriptionRequest
	subscriptionID uint16
	err            *Error
}

type SubscriptionCancelOp struct {
	sessionID sessionID
	requestID *RequestId
	im        *SubscriptionCancelRequest
	err       *Error
}

// SubscriptionPushOp sends an EventPushRequest to the client
type SubscriptionPushOp struct {
	sessionID      sessionID
	subscriptionID uint16
	eventStates    []*EventState
	err            *Error
}

// GetBlobUploadURLOp processes a GetBlobUploadURLRequest from the client
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
	shopID shopID
	user   common.Address
	add    bool
	txHash common.Hash
}

// PaymentFoundInternalOp is created by payment watchers
type PaymentFoundInternalOp struct {
	orderID   uint64
	shopID    shopID
	txHash    *Hash
	blockHash *Hash

	done chan struct{}
}

// App/Client Sessions
type responseHandler func(*Session, *RequestId, *Envelope_GenericResponse)

// Session represents a connection to a client
type Session struct {
	id                sessionID
	version           uint
	conn              net.Conn
	messages          chan *Envelope
	lastRequestId     int64
	activeInRequests  *MapInts[int64, time.Time]
	activeOutRequests *MapInts[int64, responseHandler]
	activePushes      *MapInts[int64, SessionOp]
	ops               chan SessionOp
	databaseOps       chan RelayOp
	metric            *Metric
	stopping          bool
}

func newSession(version uint, conn net.Conn, databaseOps chan RelayOp, metric *Metric) *Session {
	return &Session{
		// TODO: maybe persist and count sessions
		id:                sessionID(rand.Uint64()),
		version:           version,
		conn:              conn,
		activeInRequests:  NewMapInts[int64, time.Time](),
		activeOutRequests: NewMapInts[int64, responseHandler](),
		activePushes:      NewMapInts[int64, SessionOp](),
		// TODO: Think more carefully about channel sizes.
		messages:    make(chan *Envelope, limitMaxInRequests*2),
		ops:         make(chan SessionOp, (limitMaxInRequests+limitMaxOutRequests)*2),
		databaseOps: databaseOps,
		metric:      metric,
		stopping:    false,
	}
}

func (sess *Session) nextRequestId() *RequestId {
	next := sess.lastRequestId + 1
	reqId := &RequestId{Raw: next}
	sess.lastRequestId = next
	return reqId
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
			logS(sess.id, "session.reader.errored err=%s", err)
			op := &StopOp{sessionID: sess.id}
			sess.sendDatabaseOp(op)
			return
		}

		select {
		case sess.messages <- im:
		default:
			panic(fmt.Errorf("sessionId=%d session.reader.sendMessage.blocked %+v", sess.id, im))
		}
	}
}

const limitMaxMessageSize = 128 * 1024

func (sess *Session) readerReadMessage() (*Envelope, error) {
	bytes, err := wsutil.ReadClientBinary(sess.conn)
	if err != nil {
		logS(sess.id, "session.reader.readMessage.readError %+v", err)
		return nil, err
	}

	if n := len(bytes); n > limitMaxMessageSize {
		logS(sess.id, "session.reader.readMessage.tooLarge %d", n)
		return nil, fmt.Errorf("message too large")

	}

	var envl Envelope
	err = proto.Unmarshal(bytes, &envl)
	if err != nil {
		logS(sess.id, "session.reader.readMessage.envelopeUnmarshalError %+v", err)
		return nil, err
	}

	if logMessages {
		logS(sess.id, "session.reader.readMessage requestId=%d type=%T length=%d", envl.RequestId.Raw, envl.Message, len(bytes))
	}

	if envl.Message == nil {
		return nil, fmt.Errorf("envelope without a message")
	}
	if envl.RequestId == nil || envl.RequestId.Raw == 0 {
		return nil, fmt.Errorf("invalid request ID")
	}

	sess.metric.counterAdd("sessions_messages_read", 1)
	sess.metric.counterAdd("sessions_messages_read_bytes", float64(len(bytes)))
	typeName := strings.TrimPrefix(fmt.Sprintf("%T", envl.Message), "*main.Envelope_")
	sess.metric.counterAdd("sessions_messages_read_type_"+typeName, 1)

	return &envl, nil
}

func (sess *Session) writeResponse(reqID *RequestId, resp *Envelope_GenericResponse) {
	envl := &Envelope{
		RequestId: reqID,
		Message:   &Envelope_Response{resp},
	}
	requestID := reqID.Raw

	// Note that this inbound requestId has been responded to.
	started := sess.activeInRequests.MustGet(requestID)
	sess.activeInRequests.Delete(requestID)

	// Emit overall time the request took to process, from reading the request
	// to writing the response.
	sess.metric.counterAdd("sessions_messages_write_elapsed", float64(took(started)))

	// If we're sending an error, log it for our own visibility.
	responseErr := resp.GetError()
	if responseErr != nil {
		logS(sess.id, "session.writeMessage.errorResponse requestId=%d code=%s message=\"%s\"", requestID, responseErr.Code, responseErr.Message)
		sess.metric.counterAdd("sessions_messages_write_error", 1)
	}

	bytes, err := proto.Marshal(envl)
	check(err)

	err = wsutil.WriteServerBinary(sess.conn, bytes)
	if err != nil {
		logS(sess.id, "session.writeMessage.writeError %+v", err)
		op := &StopOp{sessionID: sess.id}
		sess.sendDatabaseOp(op)
		return
	}

	if logMessages {
		logS(sess.id, "session.writeResponse requestId=%d type=%T length=%d", requestID, envl.Message, len(bytes))
	}
	sess.metric.counterAdd("sessions_messages_write", 1)
	sess.metric.counterAdd("sessions_messages_write_bytes", float64(len(bytes)))
	typeName := strings.TrimPrefix(fmt.Sprintf("%T", envl.Message), "*main.Envelope_")
	sess.metric.counterAdd("sessions_messages_response_type_"+typeName, 1)
}

func (sess *Session) writeRequest(reqID *RequestId, msg isEnvelope_Message) {
	envl := &Envelope{
		RequestId: reqID,
		Message:   msg,
	}
	requestID := reqID.Raw

	// Note that this requestId is outbound.
	assert(!sess.activeOutRequests.Has(requestID))
	var handler responseHandler
	switch tv := msg.(type) {
	case *Envelope_PingRequest:
		handler = handlePingResponse
	case *Envelope_SyncStatusRequest:
		handler = handleSyncStatusResponse
	case *Envelope_SubscriptionPushRequest:
		handler = handleSubscriptionPushResponse
	default:
		panic(fmt.Sprintf("unhandled request type: %T", tv))
	}
	sess.activeOutRequests.Set(requestID, handler)

	bytes, err := proto.Marshal(envl)
	check(err)

	err = wsutil.WriteServerBinary(sess.conn, bytes)
	if err != nil {
		logS(sess.id, "session.writeMessage.writeError %+v", err)
		op := &StopOp{sessionID: sess.id}
		sess.sendDatabaseOp(op)
		return
	}

	if logMessages {
		logS(sess.id, "session.writeRequest requestId=%d type=%T length=%d", requestID, envl.Message, len(bytes))
	}
	sess.metric.counterAdd("sessions_messages_write", 1)
	sess.metric.counterAdd("sessions_messages_write_bytes", float64(len(bytes)))
	typeName := strings.TrimPrefix(fmt.Sprintf("%T", envl.Message), "*main.Envelope_")
	sess.metric.counterAdd("sessions_messages_request_type_"+typeName, 1)
}

func (sess *Session) handleMessage(im *Envelope) {
	// This accounting and verification happen here, instead of readMessage (which would be symmetric
	// with comparable code in writeMessage) because we need everything to happen in the same
	// goroutine, and readMessage is on a separate goroutine.

	requestID := im.GetRequestId()
	// If the client does not we can't coherently respond to them.
	if requestID == nil {
		logS(sess.id, "session.handleMessage.invalidRequestIdError requestType=%T", im.Message)
		op := &StopOp{sessionID: sess.id}
		sess.sendDatabaseOp(op)
		return
	}

	var handlerFn responseHandler
	if irm, isReq := im.isRequest(); isReq {
		// Requests must not duplicate client-originating request IDs.
		// If the client makes this error we can't coherently respond to them.
		if sess.activeInRequests.Has(requestID.Raw) {
			logS(sess.id, "session.handleMessage.duplicateRequestIdError requestId=%s requestType=%T", requestID, irm)
			op := &StopOp{sessionID: sess.id}
			sess.sendDatabaseOp(op)
			return
		}

		// Note that this requestId is inbound.
		sess.activeInRequests.Set(requestID.Raw, now())

		if logMessages {
			logS(sess.id, "session.handleMessage.newRequest requestId=%d type=%T", requestID.Raw, im.Message)
		}
		// Requests must not exceed concurrency limits.
		if sess.activeInRequests.Size() > limitMaxInRequests {
			logS(sess.id, "session.handleMessage.tooManyConcurrentRequestsError requestId=%s requestType=%T", requestID, irm)
			om := newGenericResponse(tooManyConcurrentRequestsError)
			sess.writeResponse(requestID, om)
			return
		}

		// Validate request.
		err := irm.validate(sess.version)
		if err != nil {
			logS(sess.id, "session.handleMessage.validationError requestId=%s requestType=%T", requestID, irm)
			om := newGenericResponse(err)
			sess.writeResponse(requestID, om)
			return
		}

		// Potentially insert simulate errors and ignores.
		randError := rand.Intn(100)
		if randError < simulateErrorRate {
			logS(sess.id, "session.handleMessage.simulateError requestId=%s requestType=%T", requestID, irm)
			om := newGenericResponse(simulateError)
			sess.writeResponse(requestID, om)
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
		var has bool
		handlerFn, has = sess.activeOutRequests.GetHas(requestID.Raw)
		if !has {
			logS(sess.id, "session.handleMessage.unknownRequestIdError requestId=%s requestType=%T", requestID, im)
			op := &StopOp{sessionID: sess.id}
			sess.sendDatabaseOp(op)
			return
		}

		// Note that this outbound requestId has been responded to.
		sess.activeOutRequests.Delete(requestID.Raw)
	}

	// Handle message-specific logic.
	switch tv := im.Message.(type) {
	case *Envelope_Response:
		assert(handlerFn != nil)
		handlerFn(sess, im.RequestId, tv.Response)

	case *Envelope_AuthRequest:
		tv.AuthRequest.handle(sess, im.RequestId)
	case *Envelope_ChallengeSolutionRequest:
		tv.ChallengeSolutionRequest.handle(sess, im.RequestId)

	case *Envelope_GetBlobUploadUrlRequest:
		tv.GetBlobUploadUrlRequest.handle(sess, im.RequestId)

	case *Envelope_EventWriteRequest:
		tv.EventWriteRequest.handle(sess, im.RequestId)

	case *Envelope_SubscriptionRequest:
		tv.SubscriptionRequest.handle(sess, im.RequestId)
	case *Envelope_SubscriptionCancelRequest:
		tv.SubscriptionCancelRequest.handle(sess, im.RequestId)

	default:
		panic(fmt.Sprintf("envelope.handle: unhandled message type! %T", tv))
	}
}

func newGenericResponse(err *Error) *Envelope_GenericResponse {
	r := &Envelope_GenericResponse{}
	if err != nil {
		r.Response = &Envelope_GenericResponse_Error{Error: err}
	}
	return r
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
	sess.writeRequest(sess.nextRequestId(), &Envelope_PingRequest{&PingRequest{}})
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
	reqId := sess.nextRequestId()
	msg := &Envelope_SyncStatusRequest{
		&SyncStatusRequest{
			UnpushedEvents: op.unpushedEvents,
		},
	}
	sess.writeRequest(reqId, msg)
}

func handleSyncStatusResponse(sess *Session, reqID *RequestId, resp *Envelope_GenericResponse) {
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

func (im *GetBlobUploadURLRequest) handle(sess *Session, reqId *RequestId) {
	op := &GetBlobUploadURLOp{
		requestID: reqId,
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
	reqID := sess.nextRequestId()
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
	if base := event.BaseCurrency; base != nil {
		errs = append(errs, base.Address.validate("base_currencty.addr"))
	} else {
		errs = append(errs, &Error{Code: ErrorCodes_INVALID, Message: "base_currency is required"})
	}
	for i, payee := range event.Payees {
		field := fmt.Sprintf("payee[%d].addr", i)
		errs = append(errs, payee.validate(field))
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
	if base := event.SetBaseCurrency; base != nil {
		errs = append(errs, base.Address.validate("set_base_currencty.addr"))
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
	if !hasOpt {
		errs = append(errs, &Error{Code: ErrorCodes_INVALID, Message: "updateManifest has no options set"})
	}
	return coalesce(errs...)
}

func validateListing(_ uint, event *Listing) *Error {
	errs := []*Error{
		validateObjectID(event.Id, "id"),
		validateBytes(event.BasePrice.Raw, "base_price", 32),
		validateString(event.BaseInfo.Title, "base_info.title", 512),
		validateString(event.BaseInfo.Description, "base_info.description", 16*1024),
	}
	for i, u := range event.BaseInfo.Images {
		errs = append(errs, validateURL(u, fmt.Sprintf("base_info.images[%d]: invalid url", i)))
	}
	return coalesce(errs...)
}

func validateUpdateListing(_ uint, event *UpdateListing) *Error {
	errs := []*Error{
		validateObjectID(event.Id, "id"),
	}
	hasOpt := false
	if pr := event.BasePrice; pr != nil {
		errs = append(errs, validateBytes(event.BasePrice.Raw, "base_price", 32))
		hasOpt = true
	}
	if meta := event.BaseInfo; meta != nil {
		if meta.Title != "" {
			errs = append(errs, validateString(event.BaseInfo.Title, "base_info.title", 512))
		}
		if meta.Description != "" {
			errs = append(errs, validateString(event.BaseInfo.Description, "base_info.description", 16*1024))
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
	for i, ro := range event.RemoveOptions {
		field := fmt.Sprintf("remove_options[%d]", i)
		errs = append(errs, validateObjectID(ro, field))
		hasOpt = true
	}
	for i, rv := range event.RemoveVariations {
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
	if event.Id == 0 {
		return &Error{Code: ErrorCodes_INVALID, Message: "ID can't be zero"}
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
	case *UpdateOrder_Canceled_:
		errs = append(errs, validateOrderCanceled(v, tv.Canceled))
	case *UpdateOrder_InvoiceAddress:
		errs = append(errs, validateUpdateShippingDetails(v, tv.InvoiceAddress))
	case *UpdateOrder_ShippingAddress:
		errs = append(errs, validateUpdateShippingDetails(v, tv.ShippingAddress))
	case *UpdateOrder_CommitItems_:
		// noop
	case *UpdateOrder_ChoosePayment:
		errs = append(errs, validateUpdateOrderPaymentMenthod(v, tv.ChoosePayment))
	case *UpdateOrder_PaymentDetails:
		errs = append(errs, &Error{Code: ErrorCodes_INVALID, Message: "PaymentDetails can not bet written in EventWriteRequest"})
	}
	return coalesce(errs...)
}

func validateOrderCanceled(_ uint, event *UpdateOrder_Canceled) *Error {
	if event.CanceldAt == nil {
		return &Error{Code: ErrorCodes_INVALID, Message: "timestamp can't be unset"}
	}
	if event.CanceldAt.Seconds == 0 {
		return &Error{Code: ErrorCodes_INVALID, Message: "timestamp can't be 0"}
	}
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

func (im *SubscriptionRequest) validate(version uint) *Error {
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

func (im *SubscriptionCancelRequest) validate(version uint) *Error {
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

// Database

// EventState represents the state of an event in the database.
type EventState struct {
	seq   uint64
	acked bool

	encodedEvent SignedEvent
}

// SessionState represents the state of a client in the database.
type SessionState struct {
	version           uint
	authChallenge     []byte
	sessionOps        chan SessionOp
	keyCardID         keyCardID
	keyCardPublicKey  []byte
	keyCardOfAGuest   bool
	shopID            shopID
	lastSeenAt        time.Time
	lastSeenAtFlushed time.Time
	subscriptions     map[uint16]*SubscriptionState
}

type SubscriptionState struct {
	shopID              shopID
	buffer              []*EventState
	initialStatus       bool
	lastStatusedSeq     uint64
	lastBufferedSeq     uint64
	lastPushedSeq       uint64
	nextPushIndex       int
	lastAckedSeq        uint64
	lastAckedSeqFlushed uint64
	whereFragment       string
}

// CachedMetadata represents data cached which is common to all events
type CachedMetadata struct {
	objectID                *uint64
	createdByShopID         shopID
	createdByKeyCardID      keyCardID
	createdByNetworkVersion uint16
	serverSeq               uint64
	shopSeq                 uint64

	// helper fields
	writtenByRelay bool
}

func newMetadata(keyCardID keyCardID, shopID shopID, version uint16) CachedMetadata {
	var metadata CachedMetadata
	assert(keyCardID != 0)
	metadata.createdByKeyCardID = keyCardID
	metadata.createdByShopID = shopID
	metadata.createdByNetworkVersion = version
	return metadata
}

type cachedShopCurrency struct {
	Addr    common.Address
	ChainID uint64
}

func (sc *ShopCurrency) cached() cachedShopCurrency {
	assert(sc.Address != nil && sc.Address.validate("") == nil)
	assert(sc.ChainId != 0)
	return cachedShopCurrency{
		Addr:    common.Address(sc.Address.Raw),
		ChainID: sc.ChainId,
	}
}

func (a cachedShopCurrency) Equal(b cachedShopCurrency) bool {
	return a.ChainID == b.ChainID && a.Addr.Cmp(b.Addr) == 0
}

type cachedCurrenciesMap map[cachedShopCurrency]struct{}

// CachedShopManifest is latest reduction of a ShopManifest.
// It combines the intial ShopManifest and all UpdateShopManifests
type CachedShopManifest struct {
	CachedMetadata

	shopTokenID        []byte
	payees             map[string]*Payee
	acceptedCurrencies cachedCurrenciesMap
	baseCurrency       cachedShopCurrency

	init sync.Once
}

func (current *CachedShopManifest) update(union *ShopEvent, meta CachedMetadata) {
	current.init.Do(func() {
		current.acceptedCurrencies = make(cachedCurrenciesMap)
		current.payees = make(map[string]*Payee)
	})
	switch union.Union.(type) {
	case *ShopEvent_Manifest:
		sm := union.GetManifest()
		current.CachedMetadata = meta
		current.shopTokenID = sm.TokenId.Raw
		for _, add := range sm.AcceptedCurrencies {
			current.acceptedCurrencies[cachedShopCurrency{
				common.Address(add.Address.Raw),
				add.ChainId,
			}] = struct{}{}
		}
		for _, payee := range sm.Payees {
			_, has := current.payees[payee.Name]
			assert(!has)
			current.payees[payee.Name] = payee
		}
		current.baseCurrency = cachedShopCurrency{
			common.Address(sm.BaseCurrency.Address.Raw),
			sm.BaseCurrency.ChainId,
		}
	case *ShopEvent_UpdateManifest:
		um := union.GetUpdateManifest()
		if adds := um.AddAcceptedCurrencies; len(adds) > 0 {
			for _, add := range adds {
				c := cachedShopCurrency{
					common.Address(add.Address.Raw),
					add.ChainId,
				}
				current.acceptedCurrencies[c] = struct{}{}
			}
		}
		if rms := um.RemoveAcceptedCurrencies; len(rms) > 0 {
			for _, rm := range rms {
				c := cachedShopCurrency{
					common.Address(rm.Address.Raw),
					rm.ChainId,
				}
				delete(current.acceptedCurrencies, c)
			}
		}
		if bc := um.SetBaseCurrency; bc != nil {
			current.baseCurrency = cachedShopCurrency{
				Addr:    common.Address(bc.Address.Raw),
				ChainID: bc.ChainId,
			}
		}
		if p := um.AddPayee; p != nil {
			_, taken := current.payees[p.Name]
			assert(!taken)
			current.payees[p.Name] = p
		}
		if p := um.RemovePayee; p != nil {
			delete(current.payees, p.Name)
		}
	}
}

// CachedItem is the latest reduction of an Item.
// It combines the initial CreateItem and all UpdateItems
type CachedItem struct {
	CachedMetadata
	inited bool

	value *Listing

	// utility map
	// optionID:variationID
	options map[uint64]map[uint64]*ListingVariation
}

func (current *CachedItem) update(union *ShopEvent, meta CachedMetadata) {
	switch tv := union.Union.(type) {
	case *ShopEvent_Listing:
		assert(!current.inited)
		current.CachedMetadata = meta
		current.value = tv.Listing
		current.options = make(map[uint64]map[uint64]*ListingVariation)
		current.inited = true
	case *ShopEvent_UpdateListing:
		assert(current.inited)
		current.CachedMetadata = meta
		ui := tv.UpdateListing
		if p := ui.BasePrice; p != nil {
			current.value.BasePrice = p
		}
		if meta := ui.BaseInfo; meta != nil {
			if t := meta.Title; t != "" {
				current.value.BaseInfo.Title = t
			}
			if d := meta.Description; d != "" {
				current.value.BaseInfo.Description = d
			}
			if i := meta.Images; i != nil {
				current.value.BaseInfo.Images = i
			}
		}
		// TODO: the stuff below here is a pile of poo. we shouldn't reduce the amount of duplication here
		for _, add := range ui.AddOptions {
			_, has := current.options[add.Id]
			assert(!has)
			newOpt := make(map[uint64]*ListingVariation, len(add.Variations))
			for _, variation := range add.Variations {
				newOpt[variation.Id] = variation
			}
			current.options[add.Id] = newOpt
			current.value.Options = append(current.value.Options, add)
		}
		for _, rm := range ui.RemoveOptions {
			_, has := current.options[rm]
			assert(has)
			delete(current.options, rm)
			found := -1
			opts := current.value.Options
			for idx, opt := range opts {
				if opt.Id == rm {
					found = idx
					break
				}
			}
			assert(found != -1)
			opts = append(opts[:found], opts[found+1:]...)
			current.value.Options = opts
		}
		for _, add := range ui.AddVariations {
			opt, has := current.options[add.OptionId]
			assert(has)
			opt[add.Variation.Id] = add.Variation
			found := -1
			opts := current.value.Options
			for idx, opt := range opts {
				if opt.Id == add.OptionId {
					found = idx
					break
				}
			}
			assert(found != -1)
			opts[found].Variations = append(opts[found].Variations, add.Variation)
		}
		for _, rm := range ui.RemoveVariations {
			for _, vars := range current.options {
				_, has := vars[rm]
				if has {
					delete(vars, rm)
				}
			}
			found := [2]int{-1, -1}
			opts := current.value.Options
			for idxOpt, opt := range opts {
				for idxVar, variation := range opt.Variations {
					if variation.Id == rm {
						found[0] = idxOpt
						found[1] = idxVar
						break
					}
				}
			}
			assert(found[0] != -1)
			foundVars := opts[found[0]].Variations
			foundVars = append(foundVars[:found[1]], foundVars[found[1]+1:]...)
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

	tagID   uint64
	name    string
	deleted bool
	items   *SetInts[uint64]
}

func (current *CachedTag) update(evt *ShopEvent, meta CachedMetadata) {
	if current.items == nil && !current.inited {
		current.items = NewSetInts[uint64]()
	}
	switch evt.Union.(type) {
	case *ShopEvent_Tag:
		assert(!current.inited)
		current.CachedMetadata = meta
		ct := evt.GetTag()
		current.name = ct.Name
		current.tagID = ct.Id
		current.inited = true
	case *ShopEvent_UpdateTag:
		assert(current.items != nil)
		ut := evt.GetUpdateTag()
		for _, id := range ut.AddListingIds {
			current.items.Add(id)
		}
		for _, id := range ut.RemoveListingIds {
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
	inited bool

	order Order

	paymentId []byte
	items     *MapInts[combinedID, uint32]
}

func (current *CachedOrder) update(evt *ShopEvent, meta CachedMetadata) {
	if current.items == nil && !current.inited {
		current.items = NewMapInts[combinedID, uint32]()
	}
	switch msg := evt.Union.(type) {
	case *ShopEvent_CreateOrder:
		assert(!current.inited)
		ct := msg.CreateOrder
		current.CachedMetadata = meta
		current.order.Id = ct.Id
		current.order.State = Order_STATE_OPEN
		current.inited = true
	case *ShopEvent_UpdateOrder:
		uo := msg.UpdateOrder

		switch action := uo.Action.(type) {
		case *UpdateOrder_ChangeItems_:
			ci := action.ChangeItems
			for _, id := range ci.Adds {
				sid := newCombinedID(id.ListingId, id.VariationIds...)
				count := current.items.Get(sid)
				count += id.Quantity
				current.items.Set(sid, count)
			}
			for _, id := range ci.Removes {
				sid := newCombinedID(id.ListingId, id.VariationIds...)
				count := current.items.Get(sid)
				assert(count > id.Quantity)
				count -= id.Quantity
				current.items.Set(sid, count)
			}
		case *UpdateOrder_InvoiceAddress:
			current.order.InvoiceAddress = action.InvoiceAddress
		case *UpdateOrder_ShippingAddress:
			current.order.ShippingAddress = action.ShippingAddress
		case *UpdateOrder_PaymentDetails:
			fin := action.PaymentDetails
			current.paymentId = fin.PaymentId.Raw
			current.order.State = Order_STATE_COMMITED
		case *UpdateOrder_Canceled_:
			current.order.State = Order_STATE_CANCELED
		case *UpdateOrder_Paid:
			current.order.State = Order_STATE_PAID
			current.order.Paid = action.Paid
		}
	default:
		panic(fmt.Sprintf("unhandled event type: %T", evt.Union))

	}
}

// CachedStock is the latest reduction of a Shop's stock.
// It combines all ChangeStock events
type CachedStock struct {
	CachedMetadata

	inventory *MapInts[combinedID, int32]
}

type combinedID struct {
	listingID uint64

	// uint64 ids delimited by :
	// side-stepping the problem that you can't have a slice in a comparable struct
	variations string
}

func (cid combinedID) Hash() common.Hash {
	var buf [8]byte
	hasher := sha3.NewLegacyKeccak256()
	binary.BigEndian.PutUint64(buf[:], cid.listingID)
	hasher.Write(buf[:])

	if cid.variations != "" {
		varStrs := strings.Split(cid.variations, ":")
		for _, vidStr := range varStrs {
			vid, err := strconv.ParseUint(vidStr, 10, 64)
			check(err)
			binary.BigEndian.PutUint64(buf[:], vid)
			hasher.Write(buf[:])
		}
	}
	return common.Hash(hasher.Sum(nil))
}

func newCombinedID(listingID uint64, variations ...uint64) combinedID {
	slices.Sort(variations)
	varStr := make([]string, len(variations))
	for i, v := range variations {
		varStr[i] = strconv.FormatUint(v, 10)
	}
	return combinedID{
		listingID:  listingID,
		variations: strings.Join(varStr, ":"),
	}
}

func (cid combinedID) Variations() []uint64 {
	if cid.variations == "" {
		return nil
	}
	varStrs := strings.Split(cid.variations, ":")
	vids := make([]uint64, len(varStrs))
	var err error
	for i, vidstr := range varStrs {
		vids[i], err = strconv.ParseUint(vidstr, 10, 64)
		check(err)
	}

	return vids
}

func (current *CachedStock) update(evt *ShopEvent, _ CachedMetadata) {
	cs := evt.GetChangeInventory()
	if cs == nil {
		return
	}
	if current.inventory == nil {
		current.inventory = NewMapInts[combinedID, int32]()
	}

	cid := newCombinedID(cs.Id, cs.VariationIds...)
	stock := current.inventory.Get(cid)
	stock += cs.Diff
	current.inventory.Set(cid, stock)
}

// CachedEvent is the interface for all cached events
type CachedEvent interface {
	comparable
	update(*ShopEvent, CachedMetadata)
}

// ShopState helps with writing events to the database
type ShopState struct {
	lastUsedSeq    uint64
	lastWrittenSeq uint64

	relayKeyCardID             keyCardID
	lastWrittenRelayEventNonce uint64
	shopTokenID                Uint256
}

func (ss *ShopState) nextRelayEventNonce() uint64 {
	next := ss.lastWrittenRelayEventNonce + 1
	ss.lastWrittenRelayEventNonce = next
	return next
}

// IO represents the input/output of the server.
type IO struct {
	metric *Metric

	connPool *pgxpool.Pool
	ethereum *ethRPCService

	prices priceConverter
}

// Relay is the main server struct and represents the database layer
type Relay struct {
	writesEnabled bool // ensures to only create new events if set to true

	IO
	sessionIDsToSessionStates *MapInts[sessionID, *SessionState]
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
	syncTx               pgx.Tx
	queuedEventInserts   []*EventInsert
	shopIdsToShopState   *MapInts[shopID, *ShopState]
	lastUsedServerSeq    uint64
	lastWrittenServerSeq uint64

	// caching layer
	shopManifestsByShopID *ReductionLoader[*CachedShopManifest]
	itemsByItemID         *ReductionLoader[*CachedItem]
	stockByShopID         *ReductionLoader[*CachedStock]
	tagsByTagID           *ReductionLoader[*CachedTag]
	ordersByOrderID       *ReductionLoader[*CachedOrder]
	allLoaders            []Loader
}

func newRelay(metric *Metric) *Relay {
	r := &Relay{}

	var err error
	r.baseURL, err = url.Parse(mustGetEnvString("RELAY_BASE_URL"))
	check(err)

	r.ethereum = newEthRPCService(nil)
	r.watcherContextERC20, r.watcherContextERC20Cancel = context.WithCancel(context.Background())
	r.watcherContextEther, r.watcherContextEtherCancel = context.WithCancel(context.Background())

	if cgAPIKey := os.Getenv("COINGECKO_API_KEY"); cgAPIKey != "" {
		r.prices = newCoinGecko(cgAPIKey, "usd", r.ethereum)
	} else {
		r.prices = testingConverter{}
	}

	r.sessionIDsToSessionStates = NewMapInts[sessionID, *SessionState]()
	r.opsInternal = make(chan RelayOp)
	r.ops = make(chan RelayOp, databaseOpsChanSize)
	r.shopIdsToShopState = NewMapInts[shopID, *ShopState]()

	shopFieldFn := func(evt *ShopEvent, meta CachedMetadata) uint64 {
		return uint64(meta.createdByShopID)
	}
	r.shopManifestsByShopID = newReductionLoader[*CachedShopManifest](r, shopFieldFn, []eventType{eventTypeManifest, eventTypeUpdateManifest, eventTypeAccount}, "createdByShopId")

	itemsFieldFn := func(evt *ShopEvent, meta CachedMetadata) uint64 {
		switch tv := evt.Union.(type) {
		case *ShopEvent_Listing:
			return tv.Listing.Id
		case *ShopEvent_UpdateListing:
			return tv.UpdateListing.Id
		}
		return 0
	}
	r.itemsByItemID = newReductionLoader[*CachedItem](r, itemsFieldFn, []eventType{eventTypeListing, eventTypeUpdateListing}, "objectID")
	r.stockByShopID = newReductionLoader[*CachedStock](r, shopFieldFn, []eventType{eventTypeChangeInventory}, "createdByShopId")
	tagsFieldFn := func(evt *ShopEvent, meta CachedMetadata) uint64 {
		switch tv := evt.Union.(type) {
		case *ShopEvent_Tag:
			return tv.Tag.Id
		case *ShopEvent_UpdateTag:
			return tv.UpdateTag.Id
		}
		return 0
	}
	r.tagsByTagID = newReductionLoader[*CachedTag](r, tagsFieldFn, []eventType{
		eventTypeTag,
		eventTypeUpdateTag,
	}, "objectID")

	ordersFieldFn := func(evt *ShopEvent, meta CachedMetadata) uint64 {
		switch tv := evt.Union.(type) {
		case *ShopEvent_CreateOrder:
			return tv.CreateOrder.Id
		case *ShopEvent_UpdateOrder:
			return tv.UpdateOrder.Id
		}
		return 0
	}
	r.ordersByOrderID = newReductionLoader[*CachedOrder](r, ordersFieldFn, []eventType{
		eventTypeCreateOrder,
		eventTypeUpdateOrder,
	}, "objectID")

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
			fmt.Println("[DEBUG/bulkInsertFail]")
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

func (r *Relay) assertCursors(sid sessionID, shopState *ShopState, state *SubscriptionState) {
	err := r.checkCursors(sid, shopState, state)
	check(err)
}

func (r *Relay) checkCursors(sid sessionID, shopState *ShopState, state *SubscriptionState) error {
	if shopState.lastUsedSeq < shopState.lastWrittenSeq {
		return fmt.Errorf("cursor[%d]: lastUsedShopSeq(%d) < lastWrittenShopSeq(%d)", sid, shopState.lastUsedSeq, shopState.lastWrittenSeq)
	}
	if shopState.lastWrittenSeq < state.lastStatusedSeq {
		return fmt.Errorf("cursor[%d]: lastWrittenSeq(%d) < lastStatusedSeq(%d)", sid, shopState.lastWrittenSeq, state.lastStatusedSeq)
	}
	if state.lastStatusedSeq < state.lastBufferedSeq {
		return fmt.Errorf("cursor[%d]: lastStatusedSeq(%d) < lastBufferedSeq(%d)", sid, state.lastStatusedSeq, state.lastBufferedSeq)
	}
	if state.lastBufferedSeq < state.lastPushedSeq {
		return fmt.Errorf("cursor[%d]: lastBufferedSeq(%d) < lastPushedSeq(%d)", sid, state.lastBufferedSeq, state.lastPushedSeq)
	}
	if state.lastPushedSeq < state.lastAckedSeq {
		return fmt.Errorf("cursor[%d]: lastPushedSeq(%d) < lastAckedSeq(%d)", sid, state.lastPushedSeq, state.lastAckedSeq)
	}
	return nil
}

func (r *Relay) sendSessionOp(sessionState *SessionState, op SessionOp) {
	select {
	case sessionState.sessionOps <- op:
	default:
		panic(fmt.Errorf("relay.sendSessionOp.blocked keyCardId=%d %+v", sessionState.keyCardID, op))
	}
}

func (r *Relay) lastSeenAtTouch(sessionState *SessionState) time.Time {
	n := now()
	sessionState.lastSeenAt = n
	return n
}

// used during keycard enroll. creates the keycard
// only use this inside transactions
func (r *Relay) getOrCreateInternalShopID(shopTokenID big.Int) shopID {
	var (
		err       error
		sid       shopID
		relayKCID keyCardID
		ctx       = context.Background()
	)
	assert(r.syncTx != nil)
	tx := r.syncTx

	err = tx.QueryRow(ctx, `select id from shops where tokenId = $1`, shopTokenID.String()).Scan(&sid)
	if err == nil {
		return sid
	}
	if err != pgx.ErrNoRows {
		check(err)
	}

	const qryInsertShop = `insert into shops (tokenId, createdAt) values ($1, now()) returning id`
	err = tx.QueryRow(ctx, qryInsertShop, shopTokenID.String()).Scan(&sid)
	check(err)

	const qryInsertRelayKeyCard = `insert into relayKeyCards (cardPublicKey, shopId, lastUsedAt, lastWrittenEventNonce) values ($1, $2, now(), 0) returning id`
	err = tx.QueryRow(ctx, qryInsertRelayKeyCard, r.ethereum.keyPair.CompressedPubKey(), sid).Scan(&relayKCID)
	check(err)

	// the hydrate call in enrollKeyCard will not be able to read/select the above insert
	assert(!r.shopIdsToShopState.Has(sid))
	r.shopIdsToShopState.Set(sid, &ShopState{
		relayKeyCardID: relayKCID,
	})

	return sid
}

func (r *Relay) hydrateShops(shopIds *SetInts[shopID]) {
	start := now()
	ctx := context.Background()
	novelShopIds := NewSetInts[shopID]()
	shopIds.All(func(sid shopID) bool {
		assert(sid != 0)
		if !r.shopIdsToShopState.Has(sid) {
			novelShopIds.Add(sid)
		}
		return false
	})
	if sz := novelShopIds.Size(); sz > 0 {
		novelShopIds.All(func(shopId shopID) bool {
			shopState := &ShopState{}
			r.shopIdsToShopState.Set(shopId, shopState)
			return false
		})
		for _, novelShopIdsSubslice := range subslice(novelShopIds.Slice(), 256) {
			// Index: events(createdByShopId, shopSeq)
			const queryLatestShopSeq = `select createdByShopId, max(shopSeq) from events where createdByShopId = any($1) group by createdByShopId`
			rows, err := r.connPool.Query(ctx, queryLatestShopSeq, novelShopIdsSubslice)
			check(err)
			for rows.Next() {
				var shopID shopID
				var lastWrittenSeq *uint64
				err = rows.Scan(&shopID, &lastWrittenSeq)
				check(err)
				shopState := r.shopIdsToShopState.MustGet(shopID)
				if lastWrittenSeq != nil {
					shopState.lastWrittenSeq = *lastWrittenSeq
					shopState.lastUsedSeq = *lastWrittenSeq
				}
			}
			check(rows.Err())
			rows.Close()

			const queryLastRelayNonce = "select shopId, id, lastWrittenEventNonce from relayKeyCards where shopId = any($1)"
			rows, err = r.connPool.Query(ctx, queryLastRelayNonce, novelShopIdsSubslice)
			check(err)
			for rows.Next() {
				var shopID shopID
				var relayKCID keyCardID
				var relayNonce uint64
				err = rows.Scan(&shopID, &relayKCID, &relayNonce)
				check(err)
				assert(relayKCID != 0)
				shopState := r.shopIdsToShopState.MustGet(shopID)
				shopState.lastWrittenRelayEventNonce = relayNonce
				shopState.relayKeyCardID = relayKCID
			}
			check(rows.Err())
			rows.Close()
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

// readEvents from the database according to some
// `whereFragment` criteria, assumed to have a single `$1` arg for a
// slice of indexedIds.
// Does not change any in-memory caches; to be done by caller.
func (r *Relay) readEvents(whereFragment string, indexedIds []uint64) []EventInsert {
	// Index: events(field in whereFragment)
	// The indicies eventsOnEventTypeAnd* should correspond to the various Loaders defined in newDatabase.
	query := fmt.Sprintf(`select serverSeq, shopSeq, objectID, eventType, createdByKeyCardId, createdByShopId, createdAt, createdByNetworkSchemaVersion, encoded
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
			m         CachedMetadata
			eventType eventType
			createdAt time.Time
			encoded   []byte
		)
		err := rows.Scan(&m.serverSeq, &m.shopSeq, &m.objectID, &eventType, &m.createdByKeyCardID, &m.createdByShopID, &createdAt, &m.createdByNetworkVersion, &encoded)
		check(err)
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
	cm.shopSeq = shopSeqPair.lastUsedSeq + 1
	shopSeqPair.lastUsedSeq = cm.shopSeq

	insert := newEventInsert(evt, cm, abstract)
	r.queuedEventInserts = append(r.queuedEventInserts, insert)
	r.applyEvent(insert)
}

func (r *Relay) createRelayEvent(shopID shopID, event isShopEvent_Union) {
	shopState := r.shopIdsToShopState.MustGet(shopID)
	evt := &ShopEvent{
		Nonce:  shopState.nextRelayEventNonce(),
		ShopId: &shopState.shopTokenID,
		Timestamp: &timestamppb.Timestamp{
			Seconds: now().Unix(),
		},
		Union: event,
	}

	var sigEvt SignedEvent
	var err error
	sigEvt.Event, err = anypb.New(evt)
	check(err)

	sigEvt.Signature, err = r.ethereum.signEvent(sigEvt.Event.Value)
	check(err)

	meta := newMetadata(shopState.relayKeyCardID, shopID, currentRelayVersion)
	meta.writtenByRelay = true
	r.writeEvent(evt, meta, &sigEvt)
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

func (r *Relay) rollbackSyncTransaction() {
	assert(r.queuedEventInserts != nil)
	assert(r.syncTx != nil)
	ctx := context.Background()
	check(r.syncTx.Rollback(ctx))
	r.queuedEventInserts = nil
	r.syncTx = nil
}

var dbEventInsertColumns = []string{"eventType", "eventNonce", "createdByKeyCardId", "createdByShopId", "shopSeq", "createdAt", "createdByNetworkSchemaVersion", "serverSeq", "encoded", "signature", "objectID"}

func formInsert(ins *EventInsert) []interface{} {
	var (
		evtType eventType
		objID   *uint64 // used to stich together related events
	)
	switch tv := ins.evt.Union.(type) {
	case *ShopEvent_Manifest:
		evtType = eventTypeManifest
	case *ShopEvent_UpdateManifest:
		evtType = eventTypeUpdateManifest
	case *ShopEvent_Listing:
		evtType = eventTypeListing
		objID = &tv.Listing.Id
	case *ShopEvent_UpdateListing:
		evtType = eventTypeUpdateListing
		objID = &tv.UpdateListing.Id
	case *ShopEvent_Tag:
		evtType = eventTypeTag
		objID = &tv.Tag.Id
	case *ShopEvent_UpdateTag:
		evtType = eventTypeUpdateTag
		objID = &tv.UpdateTag.Id
	case *ShopEvent_ChangeInventory:
		evtType = eventTypeChangeInventory
	case *ShopEvent_CreateOrder:
		evtType = eventTypeCreateOrder
		objID = &tv.CreateOrder.Id
	case *ShopEvent_UpdateOrder:
		evtType = eventTypeUpdateOrder
		objID = &tv.UpdateOrder.Id
	case *ShopEvent_Account:
		evtType = eventTypeAccount
	default:
		panic(fmt.Errorf("formInsert.unrecognizeType eventType=%T", ins.evt.Union))
	}
	assert(evtType != eventTypeInvalid)
	return []interface{}{
		evtType,                     // eventType
		ins.evt.Nonce,               // eventNonce
		ins.createdByKeyCardID,      // createdByKeyCardId
		ins.createdByShopID,         // createdByShopId
		ins.shopSeq,                 // shopSeq
		now(),                       // createdAt
		ins.createdByNetworkVersion, // createdByNetworkSchemaVersion
		ins.serverSeq,               // serverSeq
		ins.pbany.Event.Value,       // encoded
		ins.pbany.Signature.Raw,     // signature
		objID,                       // objectID
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
	relayEvents := make(map[keyCardID]uint64)
	for i, ei := range r.queuedEventInserts {
		eventTuples[i] = formInsert(ei)
		if ei.writtenByRelay {
			last := relayEvents[ei.createdByKeyCardID]
			if last < ei.evt.Nonce {
				relayEvents[ei.createdByKeyCardID] = ei.evt.Nonce
			}
		}
	}
	assert(r.lastWrittenServerSeq < r.lastUsedServerSeq)

	insertedEventRows, conflictedEventRows := r.bulkInsert("events", dbEventInsertColumns, eventTuples)
	for _, row := range insertedEventRows {
		rowServerSeq := row[7].(uint64)
		assert(r.lastWrittenServerSeq < rowServerSeq)
		assert(rowServerSeq <= r.lastUsedServerSeq)
		r.lastWrittenServerSeq = rowServerSeq
		rowShopID := row[3].(shopID)
		rowShopSeq := row[4].(uint64)
		shopState := r.shopIdsToShopState.MustGet(rowShopID)
		assert(shopState.lastWrittenSeq < rowShopSeq)
		assert(rowShopSeq <= shopState.lastUsedSeq)
		shopState.lastWrittenSeq = rowShopSeq
	}
	assert(r.lastWrittenServerSeq <= r.lastUsedServerSeq)
	r.queuedEventInserts = nil
	log("relay.flushEvents.events insertedEntries=%d conflictedEntries=%d", len(insertedEventRows), len(conflictedEventRows))

	ctx := context.Background()
	if len(relayEvents) > 0 {
		const updateRelayNonce = `UPDATE relayKeyCards set lastWrittenEventNonce=$2, lastUsedAt=now() where id = $1`
		// TODO: there must be nicer way to do this but i'm on a train right now
		// preferably building tuples and sending a single query but here we are...
		for kcID, lastNonce := range relayEvents {
			assert(kcID != 0)
			res, err := r.syncTx.Exec(ctx, updateRelayNonce, kcID, lastNonce)
			check(err)
			aff := res.RowsAffected()
			assertWithMessage(aff == 1, fmt.Sprintf("keyCards affected not 1 but %d", aff))
		}
	}

	log("relay.flushEvents.finish took=%d", took(start))
}

// Loader is an interface for all loaders.
// Loaders represent the read-through cache layer.

type Loader interface {
	applyEvent(*EventInsert)
}

type fieldFn func(*ShopEvent, CachedMetadata) uint64

// ReductionLoader is a struct that represents a loader for a specific event type

type ReductionLoader[T CachedEvent] struct {
	db            *Relay
	fieldFn       fieldFn
	loaded        *MapInts[uint64, T]
	whereFragment string
}

func newReductionLoader[T CachedEvent](r *Relay, fn fieldFn, pgTypes []eventType, pgField string) *ReductionLoader[T] {
	sl := &ReductionLoader[T]{}
	sl.db = r
	sl.fieldFn = fn
	sl.loaded = NewMapInts[uint64, T]()
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
	if fieldID == 0 {
		return
	}
	v, has := sl.loaded.GetHas(fieldID)
	if has {
		v.update(e.evt, e.CachedMetadata)
	}
}

func (sl *ReductionLoader[T]) get(indexedID uint64) (T, bool) {
	var zero T
	_, known := sl.loaded.GetHas(indexedID)
	if !known {
		entries := sl.db.readEvents(sl.whereFragment, []uint64{indexedID})
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
	var shopID shopID
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
	} else if sessionState.shopID != 0 {
		logS(op.sessionID, "relay.challengeSolvedOp.alreadyAuthenticated")
		op.err = alreadyAuthenticatedError
		r.sendSessionOp(sessionState, op)
		return
	}

	var keyCardPublicKey []byte
	var shopID shopID

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
	logS(op.sessionID, "relay.challengeSolvedOp.ids keyCardId=%d shopId=%d", sessionState.keyCardID, shopID)

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

	sessionState.shopID = shopID
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
func (r *Relay) shopRootHash(_ shopID) []byte {
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
	sessionID := op.sessionID
	requestID := op.requestID.Raw
	sessionState := r.sessionIDsToSessionStates.Get(sessionID)
	if sessionState == nil {
		logSR("relay.eventWriteOp.drain", sessionID, requestID)
		return
	} else if sessionState.shopID == 0 {
		logSR("relay.eventWriteOp.notAuthenticated", sessionID, requestID)
		op.err = notAuthenticatedError
		r.sendSessionOp(sessionState, op)
		return
	}
	logSR("relay.eventWriteOp.process", sessionID, requestID)
	r.lastSeenAtTouch(sessionState)

	// check signature
	if err := op.im.Events[0].Verify(sessionState.keyCardPublicKey); err != nil {
		logSR("relay.eventWriteOp.verifyEventFailed err=%s", sessionID, requestID, err.Error())
		op.err = &Error{Code: ErrorCodes_INVALID, Message: "invalid signature"}
		r.sendSessionOp(sessionState, op)
		return
	}

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

	if uo := op.decodedShopEvt.GetUpdateOrder(); uo != nil {
		if p := uo.GetChoosePayment(); p != nil {
			err := r.processPaymentDetailsForOrder(sessionID, uo.Id, p)
			if err != nil {
				op.err = err
				r.sendSessionOp(sessionState, op)
				r.rollbackSyncTransaction()
				return
			}
		}
	}

	r.commitSyncTransaction()

	// compute resulting hash
	shopSeq := r.shopIdsToShopState.MustGet(sessionState.shopID)
	if shopSeq.lastUsedSeq >= 3 {
		hash := r.shopRootHash(sessionState.shopID)
		op.newShopHash = hash
	}
	r.sendSessionOp(sessionState, op)
}

func (r *Relay) checkShopEventWriteConsistency(union *ShopEvent, m CachedMetadata, sess *SessionState) *Error {
	manifest, shopExists := r.shopManifestsByShopID.get(uint64(m.createdByShopID))
	shopManifestExists := shopExists && len(manifest.shopTokenID) > 0

	switch tv := union.Union.(type) {

	case *ShopEvent_Manifest:
		if sess.keyCardOfAGuest {
			return notFoundError
		}
		if shopManifestExists {
			return &Error{Code: ErrorCodes_INVALID, Message: "shop already exists"}
		}

	case *ShopEvent_UpdateManifest:
		if !shopManifestExists {
			return notFoundError
		}
		if sess.keyCardOfAGuest {
			return notFoundError
		}
		if p := tv.UpdateManifest.AddPayee; p != nil {
			if _, has := manifest.payees[p.Name]; has {
				return &Error{Code: ErrorCodes_INVALID, Message: "payee nickname already taken"}
			}
			for name, payee := range manifest.payees {
				if bytes.Equal(payee.Address.Raw[:], p.Address.Raw) && payee.ChainId == p.ChainId {
					return &Error{Code: ErrorCodes_INVALID, Message: "conflicting payee: " + name}
				}
			}
		}
		if p := tv.UpdateManifest.RemovePayee; p != nil {
			if _, has := manifest.payees[p.Name]; !has {
				return notFoundError
			}
		}
		// this feels like a pre-op validation step but we dont have access to the relay there
		if adds := tv.UpdateManifest.AddAcceptedCurrencies; len(adds) > 0 {
			for _, add := range adds {
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
		}
		if base := tv.UpdateManifest.SetBaseCurrency; base != nil {
			if !bytes.Equal(ZeroAddress[:], base.Address.Raw) {
				err := r.ethereum.CheckValidERC20Metadata(base.ChainId, common.Address(base.Address.Raw))
				if err != nil {
					return err
				}
			}
		}
	case *ShopEvent_Listing:
		if !shopManifestExists || sess.keyCardOfAGuest {
			log("relay.checkEventWrite.createItem manifestExists=%v isGuest=%v", shopManifestExists, sess.keyCardOfAGuest)
			return notFoundError
		}
		evt := tv.Listing
		_, itemExists := r.itemsByItemID.get(evt.Id)
		if itemExists {
			return &Error{Code: ErrorCodes_INVALID, Message: "item already exists"}
		}

	case *ShopEvent_UpdateListing:
		if !shopManifestExists || sess.keyCardOfAGuest {
			log("relay.checkEventWrite.updateItem manifestExists=%v isGuest=%v", shopManifestExists, sess.keyCardOfAGuest)
			return notFoundError
		}
		evt := tv.UpdateListing
		item, itemExists := r.itemsByItemID.get(evt.Id)
		if !itemExists {
			return notFoundError
		}
		if item.createdByShopID != sess.shopID { // not allow to alter data from other shop
			return notFoundError
		}
		for _, opt := range evt.AddOptions {
			if _, has := item.options[opt.Id]; has {
				return &Error{Code: ErrorCodes_INVALID, Message: "option id already taken"}
			}
		}
		for _, opt := range evt.RemoveOptions {
			if _, has := item.options[opt]; !has {
				return &Error{Code: ErrorCodes_NOT_FOUND, Message: "option id not found"}
			}
		}
		for _, a := range evt.AddVariations {
			if _, has := item.options[a.OptionId]; !has {
				return notFoundError
			}
			// TODO: find a better mechanism to make variation IDs unique per item
			// so that we dont have to check all of them every time
			for _, vars := range item.options {
				if _, has := vars[a.Variation.Id]; has {
					return &Error{Code: ErrorCodes_INVALID, Message: "variation id already taken"}
				}
			}
		}
		for _, varid := range evt.RemoveVariations {
			var found bool
			for _, vars := range item.options {
				if _, has := vars[varid]; has {
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
		item, itemExists := r.itemsByItemID.get(itemID)
		if !itemExists {
			return notFoundError
		}
		if item.createdByShopID != sess.shopID { // not allow to alter data from other shops
			return notFoundError
		}

		// check wether variation is valid (all variations belong to different options)
		optUsed := make(map[uint64]struct{})
		for _, wantVarID := range evt.VariationIds {
			var found uint64
			// find option for variation
		lookForVar:
			for optID, opt := range item.options {
				for varID := range opt {
					if wantVarID == varID {
						found = optID
						break lookForVar
					}
				}
			}
			if found == 0 {
				return &Error{Code: ErrorCodes_NOT_FOUND, Message: "option not found"}
			}
			if _, has := optUsed[found]; has {
				return &Error{Code: ErrorCodes_INVALID, Message: "option used more then once"}
			}
			optUsed[found] = struct{}{}
		}

		shopStock, shopStockExists := r.stockByShopID.get(uint64(m.createdByShopID))
		if shopStockExists {
			items, has := shopStock.inventory.GetHas(newCombinedID(itemID, evt.VariationIds...))
			if has && items+change < 0 {
				return &Error{Code: ErrorCodes_OUT_OF_STOCK, Message: "not enough stock"}
			}
		}

	case *ShopEvent_Tag:
		if !shopManifestExists || sess.keyCardOfAGuest {
			return notFoundError
		}
		evt := tv.Tag
		_, tagExists := r.tagsByTagID.get(evt.Id)
		if tagExists {
			return &Error{Code: ErrorCodes_INVALID, Message: "tag already exists"}
		}

	case *ShopEvent_UpdateTag:
		if !shopManifestExists || sess.keyCardOfAGuest {
			return notFoundError
		}
		evt := tv.UpdateTag
		tag, tagExists := r.tagsByTagID.get(evt.Id)
		if !tagExists {
			return notFoundError
		}
		if tag.createdByShopID != sess.shopID { // not allow to alter data from other shops
			return notFoundError
		}
		for _, id := range evt.AddListingIds {
			item, itemExists := r.itemsByItemID.get(id)
			if !itemExists {
				return notFoundError
			}
			if item.createdByShopID != sess.shopID { // not allow to alter data from other shops
				return notFoundError
			}
		}
		for _, id := range evt.RemoveListingIds {
			item, itemExists := r.itemsByItemID.get(id)
			if !itemExists {
				return notFoundError
			}
			if item.createdByShopID != sess.shopID { // not allow to alter data from other shops
				return notFoundError
			}
		}
		if d := evt.Delete; d != nil && *d == false {
			return &Error{Code: ErrorCodes_INVALID, Message: "Can't undelete a tag"}
		}

	case *ShopEvent_CreateOrder:
		if !shopManifestExists {
			return notFoundError
		}
		evt := union.GetCreateOrder()
		_, orderExists := r.ordersByOrderID.get(evt.Id)
		if orderExists {
			return &Error{Code: ErrorCodes_INVALID, Message: "order already exists"}
		}

	case *ShopEvent_UpdateOrder:
		if !shopManifestExists {
			return notFoundError
		}
		evt := tv.UpdateOrder
		order, orderExists := r.ordersByOrderID.get(evt.Id)
		if !orderExists {
			return notFoundError
		}
		if order.createdByShopID != sess.shopID { // not allow to alter data from other shops
			return notFoundError
		}

		if sess.keyCardOfAGuest && order.createdByKeyCardID != sess.keyCardID {
			return notFoundError
		}

		switch act := evt.Action.(type) {
		case *UpdateOrder_ChangeItems_:
			ci := act.ChangeItems
			if order.order.State >= Order_STATE_COMMITED {
				return &Error{Code: ErrorCodes_INVALID, Message: "order already finalized"}
			}
			changes := NewMapInts[combinedID, int64]()
			for _, item := range ci.Adds {
				obj, itemExists := r.itemsByItemID.get(item.ListingId)
				if !itemExists {
					return notFoundError
				}
				if obj.createdByShopID != sess.shopID { // not allow to alter data from other shops
					return notFoundError
				}
				sid := newCombinedID(item.ListingId, item.VariationIds...)
				changes.Set(sid, int64(item.Quantity))
			}
			for _, item := range ci.Removes {
				obj, itemExists := r.itemsByItemID.get(item.ListingId)
				if !itemExists {
					return notFoundError
				}
				if obj.createdByShopID != sess.shopID { // not allow to alter data from other shops
					return notFoundError
				}
				sid := newCombinedID(item.ListingId, item.VariationIds...)
				changes.Set(sid, -int64(item.Quantity))
			}
			for _, stockID := range changes.Keys() {
				change := changes.Get(stockID)

				stock, has := r.stockByShopID.get(uint64(m.createdByShopID))
				if !has {
					return &Error{Code: ErrorCodes_INVALID, Message: "not enough stock"}
				}
				if change > 0 {
					inStock, has := stock.inventory.GetHas(stockID)
					if !has || int64(inStock) < change {
						return &Error{Code: ErrorCodes_INVALID, Message: "not enough stock"}
					}
				}
				inOrder := order.items.Get(stockID)
				if int64(inOrder)+change < 0 {
					return &Error{Code: ErrorCodes_INVALID, Message: "not enough items in order"}
				}
			}

		case *UpdateOrder_CommitItems_:
			// noop

		case *UpdateOrder_InvoiceAddress:
			// noop

		case *UpdateOrder_ShippingAddress:
			// noop

		case *UpdateOrder_Canceled_:
			if order.order.State < Order_STATE_COMMITED {
				return &Error{Code: ErrorCodes_INVALID, Message: "order is not finalized"}
			}

		case *UpdateOrder_ChoosePayment:
			if order.order.State >= Order_STATE_COMMITED {
				return &Error{Code: ErrorCodes_INVALID, Message: "order is already finalized"}
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

func (r *Relay) processPaymentDetailsForOrder(sessionID sessionID, orderID uint64, method *UpdateOrder_ChoosePaymentMethod) *Error {
	ctx := context.Background()
	sessionState := r.sessionIDsToSessionStates.Get(sessionID)

	start := now()
	logS(sessionID, "relay.commitOrderOp.process order=%d", orderID)

	ipfsClient, err := getIpfsClient(ctx, 0, nil)
	if err != nil {
		logS(sessionID, "relay.commitOrderOp.ipfsClientFailed error=%s", err)
		return &Error{Code: ErrorCodes_INVALID, Message: "internal error"}
	}

	// sum up order content
	order, has := r.ordersByOrderID.get(orderID)
	if !has {
		return notFoundError
	}
	// check ownership of the cart if it is a guest
	if sessionState.keyCardOfAGuest && order.createdByKeyCardID != sessionState.keyCardID {
		return notFoundError
	}
	shopID := order.createdByShopID
	shop, has := r.shopManifestsByShopID.get(uint64(shopID))
	if !has {
		return notFoundError
	}
	stock, has := r.stockByShopID.get(uint64(shopID))
	if !has {
		return notFoundError
	}

	// get all other orders that haven't been paid yet
	otherOrderRows, err := r.syncTx.Query(ctx, `select orderId from payments
where shopId = $1
  and orderId != $2
  and orderPayedAt is null
  and orderFinalizedAt >= now() - interval '1 day'`, sessionState.shopID, orderID)
	check(err)
	defer otherOrderRows.Close()

	otherOrderIds := NewMapInts[uint64, *CachedOrder]()
	for otherOrderRows.Next() {
		var otherOrderID uint64
		check(otherOrderRows.Scan(&otherOrderID))
		otherOrder, has := r.ordersByOrderID.get(otherOrderID)
		assert(has)
		otherOrderIds.Set(otherOrderID, otherOrder)
	}
	check(otherOrderRows.Err())

	// for convenience, sum up all items in the  other orders
	otherOrderItemQuantities := NewMapInts[combinedID, uint32]()
	otherOrderIds.All(func(_ uint64, order *CachedOrder) bool {
		if order.order.State == Order_STATE_CANCELED {
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

	// determain total price and create snapshot of items
	type savedItem struct {
		cid       combinedID
		versioned ipfsPath.ImmutablePath
	}
	var (
		bigTotal   = new(big.Int)
		invalidErr *Error

		orderHash [32]byte
		hasher    = sha3.NewLegacyKeccak256()

		listingSnapshots errgroup.Group
		savedCIDs        = make(chan savedItem)
		done             = make(chan struct{})
	)

	// worker to save an listing to ipfs an pin it
	// TODO: we are saving the hole listing each call, irrespective of variations, etc.
	// we know the variations from the order, so it's okay but we should be able to de-duplicate it
	mkSnapshot := func(cid combinedID, item *CachedItem) func() error {
		return func() error {
			data, err := proto.Marshal(item.value)
			if err != nil {
				return fmt.Errorf("mkSnapshot.encodeError item_id=%d err=%s", item.value.Id, err)
			}

			uploadHandle := ipfsFiles.NewReaderFile(bytes.NewReader(data))

			uploadedCid, err := ipfsClient.Unixfs().Add(ctx, uploadHandle)
			if err != nil {
				return fmt.Errorf("mkSnapshot.ipfsAddError item=%d err=%s", item.value.Id, err)
			}

			// TODO: wait with pinning until after the item was sold..?
			pinKey := fmt.Sprintf("shop-%d-item-%d-%d", shopID, item.value.Id, item.shopSeq)
			if !isDevEnv {
				_, err = pinataPin(uploadedCid, pinKey)
				if err != nil {
					return fmt.Errorf("mkSnapshot.pinataFail item=%d err=%s", item.value.Id, err)
				}
			}

			savedCIDs <- savedItem{cid, uploadedCid}

			log("relay.mkSnapshot item=%s bytes=%d path=%s", pinKey, len(data), uploadedCid)
			r.metric.counterAdd("listing_snapshot", 1)
			r.metric.counterAdd("listing_snapshotBytes", float64(len(data)))
			return nil
		}
	}

	// iterate over this order
	order.items.All(func(cid combinedID, quantity uint32) bool {
		item, has := r.itemsByItemID.get(cid.listingID)
		if !has {
			invalidErr = notFoundError
			return true
		}

		if item.createdByShopID != sessionState.shopID { // not allow to alter data from other shops
			invalidErr = notFoundError
			return true
		}

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

		listingSnapshots.Go(mkSnapshot(cid, item))

		// total += quantity * price
		bigQuant := big.NewInt(int64(quantity))

		bigPrice := new(big.Int)
		bigPrice.SetBytes(item.value.BasePrice.Raw)

		chosenVars := cid.Variations()
		found := 0
		for _, chosen := range chosenVars {
			// TODO: faster lookup of variations
			for _, availableVars := range item.options {
				for varID, variation := range availableVars {
					if varID == chosen {
						if diff := variation.PriceDiff; diff != nil {
							found++
							bigPriceDiff := new(big.Int)
							bigPriceDiff.SetBytes(diff.Raw)

							if variation.PriceDiffSign {
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

		bigQuant.Mul(bigQuant, bigPrice)

		bigTotal.Add(bigTotal, bigQuant)
		return false
	})
	if invalidErr != nil {
		return invalidErr
	}
	// worker to consume snapshot jobs
	var items []savedItem
	go func() {
		for it := range savedCIDs {
			items = append(items, it)
		}
		// create a sorting to make a deterministic order_hash
		slices.SortFunc(items, func(a, b savedItem) int {
			if a.cid.listingID != b.cid.listingID {
				if a.cid.listingID < b.cid.listingID {
					return -1
				}
				return 1
			}
			return strings.Compare(a.cid.variations, b.cid.variations)
		})

		for _, it := range items {
			h := it.cid.Hash()
			log("DEBUG/itemHash id=%v hash=%s ipfs=%s", it.cid, h.Hex(), it.versioned)
			hasher.Write(h.Bytes())
		}
		hs := hasher.Sum(nil)
		copy(orderHash[:], hs)
		close(done)
	}()
	err = listingSnapshots.Wait()
	if err != nil {
		logS(sessionID, "relay.commitOrderOp.itemSnapshots err=%s", err)
		return &Error{Code: ErrorCodes_INVALID, Message: "failed to snapshot items"}
	}
	close(savedCIDs) // savers are done
	<-done           // wait for consumer to create orderHash

	// create payment address for order content
	var (
		chosenCurrency = cachedShopCurrency{
			common.Address(method.Currency.Address.Raw),
			method.Currency.ChainId,
		}
	)
	if !chosenCurrency.Equal(shop.baseCurrency) {
		// convert base to chosen currency
		bigTotal, err = r.prices.Convert(shop.baseCurrency, chosenCurrency, bigTotal)
		if err != nil {
			logS(sessionID, "relay.commitOrderOp.priceConversion err=%s", err)
			return &Error{Code: ErrorCodes_INVALID, Message: "failed to establish conversion price"}
		}
	}

	bigShopTokenID := new(big.Int).SetBytes(shop.shopTokenID)

	// fallback for paymentAddr
	ownerAddr, err := r.ethereum.GetOwnerOfShop(bigShopTokenID)
	if err != nil {
		return &Error{Code: ErrorCodes_INVALID, Message: err.Error()}
	}

	if method.Payee.ChainId != chosenCurrency.ChainID {
		return &Error{Code: ErrorCodes_INVALID, Message: "payee and chosenCurrency chain_id mismatch"}
	}

	// ttl
	blockNo, err := r.ethereum.GetCurrentBlockNumber(chosenCurrency.ChainID)
	if err != nil {
		logS(sessionID, "relay.commitOrderOp.blockNumberFailed err=%s", err)
		return &Error{Code: ErrorCodes_INVALID, Message: "failed to get current block number"}
	}
	bigBlockNo := new(big.Int).SetInt64(int64(blockNo))

	block, err := r.ethereum.GetBlockByNumber(chosenCurrency.ChainID, bigBlockNo)
	if err != nil {
		logS(sessionID, "relay.commitOrderOp.blockByNumberFailed block=%d err=%s", blockNo, err)
		return &Error{Code: ErrorCodes_INVALID, Message: "failed to get block by number"}
	}

	var pr = PaymentRequest{}
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

	paymentId, paymentAddr, err := r.ethereum.GetPaymentIDAndAddress(chosenCurrency.ChainID, &pr, ownerAddr)
	if err != nil {
		return &Error{Code: ErrorCodes_INVALID, Message: err.Error()}
	}

	logS(sessionID, "relay.commitOrderOp.paymentRequest id=%x addr=%x total=%s currentBlock=%d order_hash=%x", paymentId, paymentAddr, bigTotal.String(), blockNo, orderHash)

	// mark order as finalized by creating the event and updating payments table
	var (
		fin PaymentDetails
		w   PaymentWaiter
	)
	fin.PaymentId = &Hash{Raw: paymentId}
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
				Id:     orderID,
				Action: &UpdateOrder_PaymentDetails{&fin},
			},
		})

	w.shopID = shopID
	w.orderID = order.order.Id
	w.orderFinalizedAt = now()
	w.purchaseAddr = paymentAddr
	w.chainID = chosenCurrency.ChainID
	w.lastBlockNo.SetInt64(int64(blockNo))
	w.coinsTotal.Set(bigTotal)
	w.coinsPayed.SetInt64(0)
	w.paymentId = paymentId

	var chosenIsErc20 = ZeroAddress.Cmp(chosenCurrency.Addr) != 0
	if chosenIsErc20 {
		w.erc20TokenAddr = &chosenCurrency.Addr
	}

	seqPair := r.shopIdsToShopState.MustGet(sessionState.shopID)
	const insertPaymentWaiterQuery = `insert into payments (shopSeqNo, shopId, orderId, orderFinalizedAt, purchaseAddr, lastBlockNo, coinsPayed, coinsTotal, erc20TokenAddr, paymentId, chainId)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`
	_, err = r.syncTx.Exec(ctx, insertPaymentWaiterQuery,
		seqPair.lastUsedSeq, w.shopID, w.orderID, w.orderFinalizedAt, w.purchaseAddr.Bytes(), w.lastBlockNo, w.coinsPayed, w.coinsTotal, w.erc20TokenAddr, w.paymentId, w.chainID)
	check(err)

	ctx = context.Background()
	if chosenIsErc20 {
		r.watcherContextERC20Cancel()
		r.watcherContextERC20, r.watcherContextERC20Cancel = context.WithCancel(ctx)
	} else {
		r.watcherContextEtherCancel()
		r.watcherContextEther, r.watcherContextEtherCancel = context.WithCancel(ctx)
	}

	logS(sessionID, "relay.commitOrderOp.finish took=%d", took(start))
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
		verifyOrderIds []uint64

		startSeqNo   = op.im.StartShopSeqNo
		subscription SubscriptionState

		shopTokenID = new(big.Int).SetBytes(op.im.ShopId.Raw)
	)

	err := r.connPool.QueryRow(ctx, `select id from shops where tokenId = $1`, shopTokenID.String()).Scan(&subscription.shopID)
	if err != nil {
		if err == pgx.ErrNoRows {
			op.err = notFoundError
			r.sendSessionOp(session, op)
			return
		}
		check(err)
	}

	subscription.lastStatusedSeq = startSeqNo
	subscription.lastBufferedSeq = startSeqNo
	subscription.lastPushedSeq = startSeqNo
	subscription.lastAckedSeq = startSeqNo
	subscription.lastAckedSeqFlushed = startSeqNo

	subscription.initialStatus = false
	subscription.nextPushIndex = 0

	// build WHERE fragment used for pushing events
	var wheres []string
	for _, filter := range op.im.Filters {
		// we only support queries for public content to other shops then the authenticated one
		if subscription.shopID != session.shopID &&
			(filter.ObjectType == ObjectType_OBJECT_TYPE_INVENTORY ||
				filter.ObjectType == ObjectType_OBJECT_TYPE_ORDER ||
				filter.ObjectType == ObjectType_OBJECT_TYPE_ACCOUNT) {
			logSR("relay.subscriptionRequestOp.notAllowed why=\"other shop\" filter=%s",
				sessionID, requestID, filter.ObjectType.String())
			op.err = &Error{Code: ErrorCodes_INVALID, Message: "not allowed"}
			r.sendSessionOp(session, op)
			return
		}

		// guests are only allowed to access their own orders
		if session.keyCardOfAGuest {
			switch filter.ObjectType {
			case ObjectType_OBJECT_TYPE_ORDER:
				// we only need to verify orders queried by guests
				if id := filter.GetObjectId(); id > 0 {
					verifyOrderIds = append(verifyOrderIds, id)
				}
			case ObjectType_OBJECT_TYPE_INVENTORY:
				logSR("relay.subscriptionRequestOp.notAllowed filter=%s",
					sessionID, requestID, filter.ObjectType.String())
				op.err = &Error{Code: ErrorCodes_INVALID, Message: "not allowed"}
				r.sendSessionOp(session, op)
				return
			}
		}

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
			if session.keyCardOfAGuest {
				where = where + fmt.Sprintf(" AND createdByKeyCardId=%d", session.keyCardID)
			}
		}
		if id := filter.ObjectId; id != nil && *id != 0 {
			where = "(" + where + fmt.Sprintf(" AND objectId = %d)", *filter.ObjectId)
		}
		wheres = append(wheres, where)
	}
	subscription.whereFragment = strings.Join(wheres, " OR ")

	if n := len(verifyOrderIds); n > 0 {
		// check that all orders belong to the same person
		var count int
		const checkQry = `select count(*) from events
where eventType="createOrder"
and createdByShopId = $1
and createdByKeyCardId = $2
and objectId = any($3)`
		err = r.connPool.QueryRow(ctx, checkQry, session.shopID, session.keyCardID, verifyOrderIds).Scan(&count)
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
	shopState := r.shopIdsToShopState.MustGet(subscription.shopID)

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
	} else if sessionState.shopID == 0 {
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

func (op *KeyCardEnrolledInternalOp) getSessionID() sessionID { panic("not implemented") }
func (op *KeyCardEnrolledInternalOp) setErr(_ *Error)         { panic("not implemented") }

func (op *KeyCardEnrolledInternalOp) process(r *Relay) {
	log("relay.keyCardEnrolledOp.start shopNFT=%s", op.shopNFT.String())
	start := now()

	r.beginSyncTransaction()

	dbCtx := context.Background()

	shopDBID := r.getOrCreateInternalShopID(op.shopNFT)
	r.hydrateShops(NewSetInts(shopDBID))

	const insertKeyCard = `insert into keyCards (shopId, cardPublicKey, userWalletAddr, isGuest, lastVersion,  lastAckedSeq, linkedAt, lastSeenAt)
		VALUES ($1, $2, $3, $4, 0, 0, now(), now() )`
	_, err := r.syncTx.Exec(dbCtx, insertKeyCard, shopDBID, op.keyCardPublicKey, op.userWallet.Bytes(), op.keyCardIsGuest)
	check(err)

	// emit new keycard event
	r.createRelayEvent(shopDBID,
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

func (op *OnchainActionInternalOp) getSessionID() sessionID { panic("not implemented") }
func (op *OnchainActionInternalOp) setErr(_ *Error)         { panic("not implemented") }

func (op *OnchainActionInternalOp) process(r *Relay) {
	assert(op.shopID != 0)
	assert(op.user.Cmp(ZeroAddress) != 0)
	log("db.onchainActionInternalOp.start shopID=%d user=%s", op.shopID, op.user)
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

func (op *PaymentFoundInternalOp) getSessionID() sessionID { panic("not implemented") }
func (op *PaymentFoundInternalOp) setErr(_ *Error)         { panic("not implemented") }

func (op *PaymentFoundInternalOp) process(r *Relay) {
	assert(op.shopID != 0)
	assert(op.orderID != 0)
	log("db.paymentFoundInternalOp.start shopID=%d orderID=%d", op.shopID, op.orderID)
	start := now()

	order, has := r.ordersByOrderID.get(op.orderID)
	assertWithMessage(has, fmt.Sprintf("order not found for orderId=%d", op.orderID))

	r.beginSyncTransaction()

	paid := &OrderPaid{}
	var txHash, blockHash *[]byte
	if t := op.txHash; t != nil {
		paid.TxHash = t
		txHash = &t.Raw
	}
	if b := op.blockHash; b != nil {
		paid.BlockHash = b
		blockHash = &b.Raw
	}

	const markOrderAsPayedQuery = `UPDATE payments SET
orderPayedAt = NOW(),
orderPayedTx = $1,
orderPayedBlock = $2
WHERE shopID = $3 and orderId = $4;`
	_, err := r.syncTx.Exec(context.Background(), markOrderAsPayedQuery, txHash, blockHash, op.shopID, op.orderID)
	check(err)

	r.hydrateShops(NewSetInts(op.shopID))

	// emit changeInventory events for each item
	order.items.All(func(cid combinedID, quantity uint32) bool {
		r.createRelayEvent(op.shopID, &ShopEvent_ChangeInventory{
			&ChangeInventory{
				Id:           cid.listingID,
				VariationIds: cid.Variations(),
				Diff:         -int32(quantity),
			},
		})
		return false
	})

	r.createRelayEvent(op.shopID,
		&ShopEvent_UpdateOrder{
			&UpdateOrder{
				Id: op.orderID,
				Action: &UpdateOrder_Paid{
					paid,
				},
			},
		},
	)

	r.commitSyncTransaction()
	log("db.paymentFoundInternalOp.finish orderID=%d took=%d", op.orderID, took(start))
	close(op.done)
}

func (op *EventLoopPingInternalOp) getSessionID() sessionID { panic("not implemented") }
func (op *EventLoopPingInternalOp) setErr(_ *Error)         { panic("not implemented") }

func (op *EventLoopPingInternalOp) process(r *Relay) {
	close(op.done)
}

// Database processing

func (r *Relay) debounceSessions() {
	// Process each session.
	// Only log if there is substantial activity because this is polling constantly and usually a no-op.
	start := now()

	r.sessionIDsToSessionStates.All(func(sessionID sessionID, sessionState *SessionState) bool {
		// Kick the session if we haven't received any recent messages from it, including ping responses.
		if time.Since(sessionState.lastSeenAt) > sessionKickTimeout {
			r.metric.counterAdd("sessions_kick", 1)
			logS(sessionID, "relay.debounceSessions.kick")
			op := &StopOp{sessionID: sessionID}
			r.sendSessionOp(sessionState, op)
			return false
		}

		for subID, subscription := range sessionState.subscriptions {
			r.pushOutShopLog(sessionID, sessionState, subID, subscription)
		}

		return false
	})

	// Since we're polling this loop constantly, only log if takes a non-trivial amount of time.
	debounceTook := took(start)
	if debounceTook > 0 {
		r.metric.counterAdd("relay_debounceSessions_took", float64(debounceTook))
		log("relay.debounceSessions.finish sessions=%d elapsed=%d", r.sessionIDsToSessionStates.Size(), debounceTook)
	}
}

func (r *Relay) pushOutShopLog(sessionID sessionID, session *SessionState, subID uint16, sub *SubscriptionState) {
	ctx := context.Background()

	// If the session is authenticated, we can get user info.
	shopState := r.shopIdsToShopState.MustGet(sub.shopID)
	r.assertCursors(sessionID, shopState, sub)

	// Calculate the new keyCard seq up to which the device has acked all pushes.
	// Slice the buffer to drop such entries as they have completed their lifecycle.
	// Do this all first to trim down the buffer before reading more, if possible.
	var (
		advancedFrom uint64
		advancedTo   uint64
		i            = 0
	)
	for ; i < len(sub.buffer); i++ {
		entryState := sub.buffer[i]
		if !entryState.acked {
			break
		}
		assert(entryState.seq > sub.lastAckedSeq)
		if i == 0 {
			advancedFrom = sub.lastAckedSeq
		}
		sub.lastAckedSeq = entryState.seq
		advancedTo = entryState.seq
	}
	if i != 0 {
		sub.buffer = sub.buffer[i:]
		sub.nextPushIndex -= i
		logS(sessionID, "relay.debounceSessions.advanceSeq reason=entries from=%d to=%d", advancedFrom, advancedTo)
		r.assertCursors(sessionID, shopState, sub)
	}

	// Check if a sync status is needed, and if so query and send it.
	// Use the boolean to ensure we always send an initial sync status for the session,
	// including if the user has no writes yet.
	// If everything for the device has been pushed, advance the buffered and pushed cursors too.
	if !sub.initialStatus || sub.lastStatusedSeq < shopState.lastWrittenSeq {
		syncStatusStart := now()
		op := &SyncStatusOp{
			sessionID:      sessionID,
			subscriptionID: subID,
		}
		// Index: events(createdByShopId, shopSeq)
		query := `select count(*) from events
			where createdByShopId = $1 and shopSeq > $2
			  and createdByKeyCardId != $3 and (` + sub.whereFragment + `)`
		err := r.connPool.QueryRow(ctx, query, sub.shopID, sub.lastPushedSeq, session.keyCardID).
			Scan(&op.unpushedEvents)
		if err != pgx.ErrNoRows {
			check(err)
		}
		r.sendSessionOp(session, op)
		sub.initialStatus = true
		sub.lastStatusedSeq = shopState.lastWrittenSeq
		if op.unpushedEvents == 0 {
			sub.lastBufferedSeq = sub.lastStatusedSeq
			sub.lastPushedSeq = sub.lastStatusedSeq
		}
		logS(sessionID, "relay.debounceSessions.syncStatus initialStatus=%t unpushedEvents=%d elapsed=%d", sub.initialStatus, op.unpushedEvents, took(syncStatusStart))
		r.assertCursors(sessionID, shopState, sub)
	}

	// Check if more buffering is needed, and if so fill buffer.
	writesNotBuffered := sub.lastBufferedSeq < shopState.lastWrittenSeq
	var readsAllowed int
	if len(sub.buffer) >= sessionBufferSizeRefill {
		readsAllowed = 0
	} else {
		readsAllowed = sessionBufferSizeMax - len(sub.buffer)
	}
	if writesNotBuffered && readsAllowed > 0 {
		readStart := now()
		reads := 0
		// Index: events(shopId, shopSeq)
		query := `select e.shopSeq, e.encoded, e.signature
			from events e
			where e.createdByShopId = $1
			    and e.shopSeq > $2
				and e.createdByKeyCardId != $3 and (` + sub.whereFragment + `) order by e.shopSeq asc limit $4`
		rows, err := r.connPool.Query(ctx, query, sub.shopID, sub.lastPushedSeq, session.keyCardID, readsAllowed)
		check(err)
		defer rows.Close()
		for rows.Next() {
			var (
				eventState         = &EventState{}
				encoded, signature []byte
			)
			err := rows.Scan(&eventState.seq, &encoded, &signature)
			check(err)
			reads++
			// log("relay.debounceSessions.debug event=%x", eventState.eventID)

			eventState.acked = false
			sub.buffer = append(sub.buffer, eventState)
			assert(eventState.seq > sub.lastBufferedSeq)
			sub.lastBufferedSeq = eventState.seq

			// re-create pb object from encoded database data
			eventState.encodedEvent.Event = &anypb.Any{
				// TODO: would prever to not craft this manually
				TypeUrl: shopEventTypeURL,
				Value:   encoded,
			}
			eventState.encodedEvent.Signature = &Signature{Raw: signature}
		}
		check(rows.Err())

		// If the read rows didn't use the full limit, that means we must be at the end
		// of this user's writes.
		if reads < readsAllowed {
			sub.lastBufferedSeq = shopState.lastWrittenSeq
		}

		logS(sessionID, "relay.debounceSessions.read shopId=%d reads=%d readsAllowed=%d bufferLen=%d lastWrittenSeq=%d, lastBufferedSeq=%d elapsed=%d", sub.shopID, reads, readsAllowed, len(sub.buffer), shopState.lastWrittenSeq, sub.lastBufferedSeq, took(readStart))
		r.metric.counterAdd("relay_events_read", float64(reads))
	}
	r.assertCursors(sessionID, shopState, sub)

	// Push any events as needed.
	const maxPushes = limitMaxOutRequests * limitMaxOutBatchSize
	pushes := 0
	var eventPushOp *SubscriptionPushOp
	pushOps := make([]SessionOp, 0)
	for ; sub.nextPushIndex < len(sub.buffer) && sub.nextPushIndex < maxPushes; sub.nextPushIndex++ {
		entryState := sub.buffer[sub.nextPushIndex]
		if eventPushOp != nil && len(eventPushOp.eventStates) == limitMaxOutBatchSize {
			eventPushOp = nil
		}
		if eventPushOp == nil {
			eventPushOp = &SubscriptionPushOp{
				sessionID:      sessionID,
				subscriptionID: subID,
				eventStates:    make([]*EventState, 0),
			}
			pushOps = append(pushOps, eventPushOp)
		}
		eventPushOp.eventStates = append(eventPushOp.eventStates, entryState)
		sub.lastPushedSeq = entryState.seq
		pushes++
	}
	for _, pushOp := range pushOps {
		r.sendSessionOp(session, pushOp)
	}
	if pushes > 0 {
		logS(sessionID, "relay.debounce.push pushes=%d ops=%d", pushes, len(pushOps))
	}
	r.assertCursors(sessionID, shopState, sub)

	// If there are no buffered events at this point, it's safe to advance the acked pointer.
	if len(sub.buffer) == 0 && sub.lastAckedSeq < sub.lastPushedSeq {
		logS(sessionID, "relay.debounceSessions.advanceSeq reason=emptyBuffer from=%d to=%d", sub.lastAckedSeq, sub.lastPushedSeq)
		sub.lastAckedSeq = sub.lastPushedSeq
	}
	r.assertCursors(sessionID, shopState, sub)

	// logS(sessionID, "relay.debounce.cursors lastWrittenSeq=%d lastStatusedshopSeq=%d lastBufferedshopSeq=%d lastPushedshopSeq=%d lastAckedSeq=%d", userState.lastWrittenSeq, sessionState.lastStatusedshopSeq, sessionState.lastBufferedshopSeq, sessionState.lastPushedshopSeq, sessionState.lastAckedSeq)
}

func (r *Relay) memoryStats() {
	start := now()
	debug("relay.memoryStats.start")

	// Shared between old and sharing worlds.
	sessionCount := r.sessionIDsToSessionStates.Size()
	sessionVersionCounts := make(map[uint]uint64)
	r.sessionIDsToSessionStates.All(func(sessionID sessionID, sessionState *SessionState) bool {
		sessionVersionCount := sessionVersionCounts[sessionState.version]
		sessionVersionCounts[sessionState.version] = sessionVersionCount + 1
		return false
	})
	r.metric.gaugeSet("sessions_active", float64(sessionCount))
	for version, versionCount := range sessionVersionCounts {
		// TODO: vector?
		r.metric.gaugeSet(fmt.Sprintf("sessions_active_version_%d", version), float64(versionCount))
	}
	r.metric.gaugeSet("relay_cached_shops", float64(r.shopIdsToShopState.Size()))

	r.metric.gaugeSet("relay_ops_queued", float64(len(r.ops)))

	// r.metric.emit("relay_cached_items", uint64(r.itemsByItemID.loaded.Size()))
	// r.metric.emit("relay_cached_orders", uint64(r.ordersByOrderID.loaded.Size()))

	// Go runtime memory information
	var runtimeMemory runtime.MemStats
	runtime.ReadMemStats(&runtimeMemory)
	r.metric.gaugeSet("go_runtime_heapalloc", float64(runtimeMemory.HeapAlloc))
	r.metric.gaugeSet("go_runtime_inuse", float64(runtimeMemory.HeapInuse))
	r.metric.gaugeSet("go_runtime_gcpauses", float64(runtimeMemory.PauseTotalNs))

	memoryStatsTook := took(start)
	r.metric.gaugeSet("relay_memoryStats_took", float64(memoryStatsTook))
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

		case <-tickStatsTimer.C:
			tickType, tickSelected = timeTick(ttTickStats)
			for tt, e := range tickTypeToTooks {
				if e.Milliseconds() > 0 {
					r.metric.gaugeSet(fmt.Sprintf("relay_run_tick_%s_took", tt.String()), float64(e.Milliseconds()))
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

func (m *Metric) gaugeSet(name string, value float64) {
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

	gauge.Set(value)
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
					r.metric.counterAdd("blob_pinata_error", 1)
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
			// assuming the enrollment is directly on the relay, without a website involved
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

		op := &KeyCardEnrolledInternalOp{
			shopNFT:          shopTokenID,
			keyCardIsGuest:   isGuest,
			keyCardPublicKey: keyCardPublicKey,
			userWallet:       userWallet,
			done:             make(chan struct{}),
		}
		r.opsInternal <- op
		<-op.done

		w.WriteHeader(http.StatusCreated)
		err = json.NewEncoder(w).Encode(map[string]any{"success": true})
		if err != nil {
			log("relay.enrollKeyCard.responseFailure err=%s", err)
			// returning an error would mean sending error code
			// we already sent one so we cant
			return 0, nil
		}

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
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		var res int
		err := r.connPool.QueryRow(ctx, `select 1`).Scan(&res)
		if err != nil {
			log("relay.health.dbs.fail err=%s", err)
			w.WriteHeader(500)
			r.metric.httpStatusCodes.WithLabelValues("500", req.URL.Path).Inc()
			_, _ = fmt.Fprintln(w, "database unavailable")
			return
		}
		// log("relay.health.dbs.pass")

		wait, op := NewEventLoopPing()
		select {
		case r.opsInternal <- op:
			// pass
		default:
			log("relay.health.evtLoop.txFail")
			w.WriteHeader(500)
			r.metric.httpStatusCodes.WithLabelValues("500", req.URL.Path).Inc()
			_, _ = fmt.Fprintln(w, "event loop unavailable")
			return
		}
		// log("relay.health.evtLoop.txPass")

		select {
		case <-time.After(5 * time.Second):
			log("relay.health.evtLoop.rxTimeout")
			w.WriteHeader(500)
			r.metric.httpStatusCodes.WithLabelValues("500", req.URL.Path).Inc()
			_, _ = fmt.Fprintln(w, "event loop unavailable")
			return
		case <-wait:
		}

		_, _ = fmt.Fprintln(w, "health OK")
		r.metric.httpStatusCodes.WithLabelValues("200", req.URL.Path).Inc()
		r.metric.httpResponseTimes.WithLabelValues("200", req.URL.Path).Set(tookF(start))
		log("relay.health.pass took=%d", took(start))
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
		uptime := float64(time.Since(start).Milliseconds())
		log("relay.emitUptime uptime=%v", uptime)
		metric.gaugeSet("server_uptime", uptime)
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

	delay := repeat.FullJitterBackoff(250 * time.Millisecond)
	delay.MaxDelay = ethereumBlockInterval

	// onchain accounts only need to happen on the chain where the shop registry contract is hosted
	go func() {
		chain_id := r.ethereum.registryChainID
		geth, has := r.ethereum.chains[chain_id]
		assert(has)

		countError := repeat.FnOnError(repeat.FnES(func(err error) {
			log("watcher.error name=onchain-accounts chainId=%d err=%s", chain_id, err)
			r.metric.counterAdd("relay_watchError_error", 1)
		}))

		err := repeat.Repeat(
			repeat.Fn(func() error {
				return r.subscribeAccountEvents(geth)
			}),
			repeat.WithDelay(delay.Set()),
			countError,
		)
		panic(err) // TODO: panic reporting
	}()

	for _, geth := range r.ethereum.chains {
		for _, w := range fns {
			go func(w watcher, c *ethClient) {
				log("watcher.spawned name=%s chainId=%d", w.name, c.chainID)

				ticker := NewReusableTimer(ethereumBlockInterval / 2)
				countError := repeat.FnOnError(repeat.FnES(func(err error) {
					log("watcher.error name=%s chainId=%d err=%s", w.name, c.chainID, err)
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
				err := repeat.Repeat(
					repeat.Fn(func() error { return w.fn(c) }),
					waitForNextBlock,
					countError,
					repeat.WithDelay(delay.Set()),
				)
				panic(err) // TODO: panic reporting
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

func debugObject(eventType string) {

	pbData, err := io.ReadAll(os.Stdin)
	check(err)

	switch strings.ToLower(eventType) {
	case "listing":
		var lis Listing
		err = proto.Unmarshal(pbData, &lis)
		check(err)
		spew.Dump(&lis)
	default:
		fmt.Fprintln(os.Stderr, "unhandled event type:"+eventType)
		os.Exit(1)
	}
}

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
	} else if cmd == "debug-obj" && len(cmdArgs) == 1 {
		debugObject(cmdArgs[0])
	} else {
		usage()
	}
}
