// SPDX-FileCopyrightText: 2024 - 2025 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/gobwas/ws/wsutil"
	"google.golang.org/protobuf/proto"

	"github.com/masslbs/go-pgmmr"
	cbor "github.com/masslbs/network-schema/go/cbor"
	pb "github.com/masslbs/network-schema/go/pb"
)

// Session represents a connection to a client
type Session struct {
	id                sessionID
	version           uint
	conn              net.Conn
	messages          chan *pb.Envelope
	lastRequestID     int64
	activeInRequests  *MapInts[int64, time.Time]
	activeOutRequests *MapInts[int64, responseHandler]
	activePushes      *MapInts[int64, SessionOp]
	ops               chan SessionOp
	databaseOps       chan RelayOp
	validator         *validator.Validate
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
		messages:    make(chan *pb.Envelope, limitMaxInRequests*2),
		ops:         make(chan SessionOp, (limitMaxInRequests+limitMaxOutRequests)*2),
		databaseOps: databaseOps,
		validator:   cbor.DefaultValidator(),
		metric:      metric,
		stopping:    false,
	}
}

func (sess *Session) nextRequestID() *pb.RequestId {
	next := sess.lastRequestID + 1
	reqID := &pb.RequestId{Raw: next}
	sess.lastRequestID = next
	return reqID
}

// Starts a dedicated session reader goroutine. We need this to get messages
// on a channel to enable multi-way select in the main session go-routine.
// Note that the expected way to end this goroutine is Close'ing the conn
// so that a subsequent read errors.
func (sess *Session) readerRun() {
	logS(sess.id, "session.reader.start")
	defer sentryRecover()

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

func (sess *Session) readerReadMessage() (*pb.Envelope, error) {
	bytes, err := wsutil.ReadClientBinary(sess.conn)
	if err != nil {
		logS(sess.id, "session.reader.readMessage.readError %+v", err)
		return nil, err
	}

	if n := len(bytes); n > limitMaxMessageSize {
		logS(sess.id, "session.reader.readMessage.tooLarge %d", n)
		return nil, fmt.Errorf("message too large")

	}

	var envl pb.Envelope
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
	typeName := strings.TrimPrefix(fmt.Sprintf("%T", envl.Message), "*pb.Envelope_")
	sess.metric.counterAdd("sessions_messages_read_type_"+typeName, 1)

	return &envl, nil
}

func (sess *Session) writeResponse(reqID *pb.RequestId, resp *pb.Envelope_GenericResponse) {
	envl := &pb.Envelope{
		RequestId: reqID,
		Message:   &pb.Envelope_Response{Response: resp},
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
	typeName := strings.TrimPrefix(fmt.Sprintf("%T", envl.Message), "*pb.Envelope_")
	sess.metric.counterAdd("sessions_messages_response_type_"+typeName, 1)
}

func (sess *Session) writeRequest(reqID *pb.RequestId, msg pb.IsEnvelope_Message) {
	envl := &pb.Envelope{
		RequestId: reqID,
		Message:   msg,
	}
	requestID := reqID.Raw

	// Note that this requestId is outbound.
	assert(!sess.activeOutRequests.Has(requestID))
	var handler responseHandler
	switch tv := msg.(type) {
	case *pb.Envelope_PingRequest:
		handler = handlePingResponse
	case *pb.Envelope_SyncStatusRequest:
		handler = handleSyncStatusResponse
	// case *pb.Envelope_SubscriptionPushRequest:
	// 	handler = handleSubscriptionPushResponse
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
	typeName := strings.TrimPrefix(fmt.Sprintf("%T", envl.Message), "*pb.Envelope_")
	sess.metric.counterAdd("sessions_messages_request_type_"+typeName, 1)
}

type networkMessage interface {
	handle(sess *Session, reqID *pb.RequestId)
}

type networkRequest interface {
	networkMessage
	validate(uint) *pb.Error
}

// Sadly we can't attach methods to the generated pb.Envelope_Message types.
// So we need to define our own types that wrap the generated types and add
// our methods.

type AuthenticateRequestHandler struct {
	*pb.AuthenticateRequest
}

func (im *AuthenticateRequestHandler) validate(version uint) *pb.Error {
	if version < 4 {
		return minimumVersionError
	}
	return validatePublicKey(im.PublicKey)
}

func (im *AuthenticateRequestHandler) handle(sess *Session, reqID *pb.RequestId) {
	op := &AuthenticateOp{
		requestID: reqID,
		sessionID: sess.id,
		im:        im.AuthenticateRequest,
	}
	sess.sendDatabaseOp(op)
}

type ChallengeSolvedRequestHandler struct {
	*pb.ChallengeSolvedRequest
}

func (im *ChallengeSolvedRequestHandler) validate(version uint) *pb.Error {
	if version < 4 {
		return minimumVersionError
	}
	return validateSignature(im.Signature)
}

func (im *ChallengeSolvedRequestHandler) handle(sess *Session, reqID *pb.RequestId) {
	op := &ChallengeSolvedOp{
		requestID: reqID,
		sessionID: sess.id,
		im:        im.ChallengeSolvedRequest,
	}
	sess.sendDatabaseOp(op)
}

type GetBlobUploadUrlRequestHandler struct {
	*pb.GetBlobUploadURLRequest
}

func (im *GetBlobUploadUrlRequestHandler) validate(version uint) *pb.Error {
	if version < 4 {
		return minimumVersionError
	}
	return nil // req id is checked seperatly
}

func (im *GetBlobUploadUrlRequestHandler) handle(sess *Session, reqID *pb.RequestId) {
	op := &GetBlobUploadURLOp{
		requestID: reqID,
		sessionID: sess.id,
		im:        im.GetBlobUploadURLRequest,
	}
	sess.sendDatabaseOp(op)
}

type WriteRequestHandler struct {
	*pb.EventWriteRequest

	validator *validator.Validate

	decodedPatchSet *cbor.SignedPatchSet
}

var bigZero = big.NewInt(0)

func (im *WriteRequestHandler) validate(version uint) *pb.Error {
	if version < 4 {
		return minimumVersionError
	}
	var decodedPatchSet cbor.SignedPatchSet
	if cborErr := cbor.Unmarshal(im.PatchSet, &decodedPatchSet); cborErr != nil {
		log("eventWriteRequest.validate: cbor unmarshal failed: %s", cborErr.Error())
		return &pb.Error{Code: pb.ErrorCodes_INVALID, Message: "invalid CBOR encoding"}
	}
	if valErr := im.validator.Struct(decodedPatchSet); valErr != nil {
		log("eventWriteRequest.validate: validator.Struct failed: %s", valErr.Error())
		return &pb.Error{Code: pb.ErrorCodes_INVALID, Message: "unable to validate patch set"}
	}
	if decodedPatchSet.Header.Timestamp.IsZero() {
		return &pb.Error{Code: pb.ErrorCodes_INVALID, Message: "timestamp can't be unset"}
	}
	if decodedPatchSet.Header.ShopID.Cmp(bigZero) == 0 {
		return &pb.Error{Code: pb.ErrorCodes_INVALID, Message: "missing shopID on shopEvent"}
	}

	// verify RootHash
	computedRoot, tree, err := cbor.RootHash(decodedPatchSet.Patches)
	if err != nil {
		return &pb.Error{Code: pb.ErrorCodes_INVALID, Message: "unable to compute root hash"}
	}
	if !bytes.Equal(computedRoot[:], decodedPatchSet.Header.RootHash[:]) {
		return &pb.Error{Code: pb.ErrorCodes_INVALID, Message: "invalid root hash"}
	}

	// compute proofs for all patches
	proofs := make([]*pgmmr.Proof, len(decodedPatchSet.Patches))
	for i := 0; i < len(decodedPatchSet.Patches); i++ {
		proofs[i], err = tree.MakeProof(uint64(i))
		if err != nil {
			return &pb.Error{Code: pb.ErrorCodes_INVALID, Message: "unable to make proof"}
		}
	}

	im.decodedPatchSet = &decodedPatchSet
	return nil
}

func (im *WriteRequestHandler) handle(sess *Session, reqID *pb.RequestId) {
	op := &EventWriteOp{
		requestID: reqID,
		sessionID: sess.id,
		im:        im.EventWriteRequest,
		decoded:   im.decodedPatchSet,
	}
	sess.sendDatabaseOp(op)
}

func isRequest(e *pb.Envelope, v *validator.Validate) (networkRequest, bool) {
	switch tv := e.Message.(type) {

	case *pb.Envelope_Response:
		return nil, false

	case *pb.Envelope_AuthRequest:
		return &AuthenticateRequestHandler{tv.AuthRequest}, true
	case *pb.Envelope_ChallengeSolutionRequest:
		return &ChallengeSolvedRequestHandler{tv.ChallengeSolutionRequest}, true
	case *pb.Envelope_GetBlobUploadUrlRequest:
		return &GetBlobUploadUrlRequestHandler{tv.GetBlobUploadUrlRequest}, true
	case *pb.Envelope_EventWriteRequest:
		return &WriteRequestHandler{
			EventWriteRequest: tv.EventWriteRequest,
			validator:         v,
		}, true
	/*
		case *pb.Envelope_SubscriptionRequest:
			return tv.SubscriptionRequest, true
		case *pb.Envelope_SubscriptionCancelRequest:
			return tv.SubscriptionCancelRequest, true
	*/
	default:
		panic(fmt.Sprintf("Envelope.isRequest: unhandeled type: %T", tv))
	}
}

// App/Client Sessions
type responseHandler func(*Session, *pb.RequestId, *pb.Envelope_GenericResponse)

func (sess *Session) handleMessage(im *pb.Envelope) {
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

	if irm, isReq := isRequest(im, sess.validator); isReq {
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

		irm.handle(sess, im.RequestId)
		return
	}

	// Responses must correspond to server-originating request IDs.
	// If the client makes this error we can't coherently respond to them.
	handlerFn, has := sess.activeOutRequests.GetHas(requestID.Raw)
	if !has {
		logS(sess.id, "session.handleMessage.unknownRequestIdError requestId=%s requestType=%T", requestID, im)
		op := &StopOp{sessionID: sess.id}
		sess.sendDatabaseOp(op)
		return
	}

	resp, ok := im.Message.(*pb.Envelope_Response)
	if !ok {
		logS(sess.id, "session.handleMessage.unexpectedResponse requestId=%s requestType=%T", requestID, im)
		op := &StopOp{sessionID: sess.id}
		sess.sendDatabaseOp(op)
		return
	}

	handlerFn(sess, requestID, resp.Response)

	// Note that this outbound requestId has been responded to.
	sess.activeOutRequests.Delete(requestID.Raw)
}

func newGenericResponse(err *pb.Error) *pb.Envelope_GenericResponse {
	r := &pb.Envelope_GenericResponse{}
	if err != nil {
		r.Response = &pb.Envelope_GenericResponse_Error{Error: err}
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

func (sess *Session) heartbeat() {
	logS(sess.id, "session.heartbeat")
	sess.writeRequest(sess.nextRequestID(), &pb.Envelope_PingRequest{PingRequest: &pb.PingRequest{}})
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
