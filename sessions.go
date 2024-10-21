// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/gobwas/ws/wsutil"
	"google.golang.org/protobuf/proto"
)

// Session represents a connection to a client
type Session struct {
	id                sessionID
	version           uint
	conn              net.Conn
	messages          chan *Envelope
	lastRequestID     int64
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

func (sess *Session) nextRequestID() *RequestId {
	next := sess.lastRequestID + 1
	reqID := &RequestId{Raw: next}
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

func (sess *Session) heartbeat() {
	logS(sess.id, "session.heartbeat")
	sess.writeRequest(sess.nextRequestID(), &Envelope_PingRequest{&PingRequest{}})
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
