// Generated from /nix/store/r14cbryys0jdmf9msi39arssgc13851p-source/network-schema/envelope.proto at version v3 (5ac728e84c6ed53e4aea4c58dee94ad539169b0b)

// SPDX-FileCopyrightText: 2023 - 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-License-Identifier: MIT

// This file defines the transport protocol between relays and clients.
// It's main purpose is transfer of events of the higher application levels.
// It is orthogonal to the shop registry and other smart contracts.
//
// Messages must be prefixed with their acompanying encoding number
// as a single byte. encoding.txt defines the number for each message.
//
// Furthermore, we expect only one message per write/binary frame.
// This means no buffering of multiple messages into a single write.
// The protocol offers repeated fields where approriate for higher throughput.
// A suggested transport is WebSocket over HTTPS but the protocol is
// agnostic, as long as it can handle binary data and keeps the framing intact.
// This design, specifically the push from the relay to client, assumes
// the transport does not offer backpressure. No further pushes are sent
// until they are acknowledged by the client.
//
// For upgrades there exists a VERSION file in the root of the repository.
// The VERSION is a single unsigned integer, incremented for each change.
// The client and relay must agree on the VERSION before starting the protocol.
// In the case of WebSocket, the VERSION can be compared via the URL.
// The relay must close the connection if the VERSION isn't supported.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.1
// 	protoc        v4.24.4
// source: envelope.proto

package main

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Envelope is how client and server exchange requests and responses.
type Envelope struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RequestId *RequestId `protobuf:"bytes,1,opt,name=request_id,json=requestId,proto3" json:"request_id,omitempty"`
	// Types that are assignable to Message:
	//
	//	*Envelope_Response
	//	*Envelope_EventWriteRequest
	//	*Envelope_SubscriptionRequest
	//	*Envelope_SubscriptionPushRequest
	//	*Envelope_SyncStatusRequest
	//	*Envelope_PingRequest
	//	*Envelope_GetBlobUploadUrlRequest
	//	*Envelope_AuthRequest
	//	*Envelope_ChallengeSolutionRequest
	Message isEnvelope_Message `protobuf_oneof:"message"`
}

func (x *Envelope) Reset() {
	*x = Envelope{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envelope_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Envelope) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Envelope) ProtoMessage() {}

func (x *Envelope) ProtoReflect() protoreflect.Message {
	mi := &file_envelope_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Envelope.ProtoReflect.Descriptor instead.
func (*Envelope) Descriptor() ([]byte, []int) {
	return file_envelope_proto_rawDescGZIP(), []int{0}
}

func (x *Envelope) GetRequestId() *RequestId {
	if x != nil {
		return x.RequestId
	}
	return nil
}

func (m *Envelope) GetMessage() isEnvelope_Message {
	if m != nil {
		return m.Message
	}
	return nil
}

func (x *Envelope) GetResponse() *Envelope_GenericResponse {
	if x, ok := x.GetMessage().(*Envelope_Response); ok {
		return x.Response
	}
	return nil
}

func (x *Envelope) GetEventWriteRequest() *EventWriteRequest {
	if x, ok := x.GetMessage().(*Envelope_EventWriteRequest); ok {
		return x.EventWriteRequest
	}
	return nil
}

func (x *Envelope) GetSubscriptionRequest() *SubscriptionRequest {
	if x, ok := x.GetMessage().(*Envelope_SubscriptionRequest); ok {
		return x.SubscriptionRequest
	}
	return nil
}

func (x *Envelope) GetSubscriptionPushRequest() *SubscriptionPushRequest {
	if x, ok := x.GetMessage().(*Envelope_SubscriptionPushRequest); ok {
		return x.SubscriptionPushRequest
	}
	return nil
}

func (x *Envelope) GetSyncStatusRequest() *SyncStatusRequest {
	if x, ok := x.GetMessage().(*Envelope_SyncStatusRequest); ok {
		return x.SyncStatusRequest
	}
	return nil
}

func (x *Envelope) GetPingRequest() *PingRequest {
	if x, ok := x.GetMessage().(*Envelope_PingRequest); ok {
		return x.PingRequest
	}
	return nil
}

func (x *Envelope) GetGetBlobUploadUrlRequest() *GetBlobUploadURLRequest {
	if x, ok := x.GetMessage().(*Envelope_GetBlobUploadUrlRequest); ok {
		return x.GetBlobUploadUrlRequest
	}
	return nil
}

func (x *Envelope) GetAuthRequest() *AuthenticateRequest {
	if x, ok := x.GetMessage().(*Envelope_AuthRequest); ok {
		return x.AuthRequest
	}
	return nil
}

func (x *Envelope) GetChallengeSolutionRequest() *ChallengeSolvedRequest {
	if x, ok := x.GetMessage().(*Envelope_ChallengeSolutionRequest); ok {
		return x.ChallengeSolutionRequest
	}
	return nil
}

type isEnvelope_Message interface {
	isEnvelope_Message()
}

type Envelope_Response struct {
	Response *Envelope_GenericResponse `protobuf:"bytes,2,opt,name=response,proto3,oneof"`
}

type Envelope_EventWriteRequest struct {
	// write operation
	EventWriteRequest *EventWriteRequest `protobuf:"bytes,3,opt,name=event_write_request,json=eventWriteRequest,proto3,oneof"`
}

type Envelope_SubscriptionRequest struct {
	// subscriptions
	SubscriptionRequest *SubscriptionRequest `protobuf:"bytes,4,opt,name=subscription_request,json=subscriptionRequest,proto3,oneof"`
}

type Envelope_SubscriptionPushRequest struct {
	SubscriptionPushRequest *SubscriptionPushRequest `protobuf:"bytes,5,opt,name=subscription_push_request,json=subscriptionPushRequest,proto3,oneof"`
}

type Envelope_SyncStatusRequest struct {
	// sync state information
	SyncStatusRequest *SyncStatusRequest `protobuf:"bytes,6,opt,name=sync_status_request,json=syncStatusRequest,proto3,oneof"`
}

type Envelope_PingRequest struct {
	PingRequest *PingRequest `protobuf:"bytes,7,opt,name=ping_request,json=pingRequest,proto3,oneof"`
}

type Envelope_GetBlobUploadUrlRequest struct {
	// shop requests
	GetBlobUploadUrlRequest *GetBlobUploadURLRequest `protobuf:"bytes,8,opt,name=get_blob_upload_url_request,json=getBlobUploadUrlRequest,proto3,oneof"`
}

type Envelope_AuthRequest struct {
	// authentification messages
	AuthRequest *AuthenticateRequest `protobuf:"bytes,9,opt,name=auth_request,json=authRequest,proto3,oneof"`
}

type Envelope_ChallengeSolutionRequest struct {
	ChallengeSolutionRequest *ChallengeSolvedRequest `protobuf:"bytes,10,opt,name=challenge_solution_request,json=challengeSolutionRequest,proto3,oneof"`
}

func (*Envelope_Response) isEnvelope_Message() {}

func (*Envelope_EventWriteRequest) isEnvelope_Message() {}

func (*Envelope_SubscriptionRequest) isEnvelope_Message() {}

func (*Envelope_SubscriptionPushRequest) isEnvelope_Message() {}

func (*Envelope_SyncStatusRequest) isEnvelope_Message() {}

func (*Envelope_PingRequest) isEnvelope_Message() {}

func (*Envelope_GetBlobUploadUrlRequest) isEnvelope_Message() {}

func (*Envelope_AuthRequest) isEnvelope_Message() {}

func (*Envelope_ChallengeSolutionRequest) isEnvelope_Message() {}

type Envelope_GenericResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Response:
	//
	//	*Envelope_GenericResponse_Error
	//	*Envelope_GenericResponse_Payload
	Response isEnvelope_GenericResponse_Response `protobuf_oneof:"response"`
}

func (x *Envelope_GenericResponse) Reset() {
	*x = Envelope_GenericResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envelope_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Envelope_GenericResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Envelope_GenericResponse) ProtoMessage() {}

func (x *Envelope_GenericResponse) ProtoReflect() protoreflect.Message {
	mi := &file_envelope_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Envelope_GenericResponse.ProtoReflect.Descriptor instead.
func (*Envelope_GenericResponse) Descriptor() ([]byte, []int) {
	return file_envelope_proto_rawDescGZIP(), []int{0, 0}
}

func (m *Envelope_GenericResponse) GetResponse() isEnvelope_GenericResponse_Response {
	if m != nil {
		return m.Response
	}
	return nil
}

func (x *Envelope_GenericResponse) GetError() *Error {
	if x, ok := x.GetResponse().(*Envelope_GenericResponse_Error); ok {
		return x.Error
	}
	return nil
}

func (x *Envelope_GenericResponse) GetPayload() []byte {
	if x, ok := x.GetResponse().(*Envelope_GenericResponse_Payload); ok {
		return x.Payload
	}
	return nil
}

type isEnvelope_GenericResponse_Response interface {
	isEnvelope_GenericResponse_Response()
}

type Envelope_GenericResponse_Error struct {
	Error *Error `protobuf:"bytes,1,opt,name=error,proto3,oneof"`
}

type Envelope_GenericResponse_Payload struct {
	Payload []byte `protobuf:"bytes,2,opt,name=payload,proto3,oneof"`
}

func (*Envelope_GenericResponse_Error) isEnvelope_GenericResponse_Response() {}

func (*Envelope_GenericResponse_Payload) isEnvelope_GenericResponse_Response() {}

var File_envelope_proto protoreflect.FileDescriptor

var file_envelope_proto_rawDesc = []byte{
	0x0a, 0x0e, 0x65, 0x6e, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x0b, 0x6d, 0x61, 0x72, 0x6b, 0x65, 0x74, 0x2e, 0x6d, 0x61, 0x73, 0x73, 0x1a, 0x14, 0x61,
	0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x10, 0x62, 0x61, 0x73, 0x65, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x0b, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x13, 0x73, 0x68, 0x6f, 0x70, 0x5f, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x12, 0x73, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69,
	0x70, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x0f, 0x74, 0x72, 0x61,
	0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xa8, 0x07, 0x0a,
	0x08, 0x45, 0x6e, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x65, 0x12, 0x35, 0x0a, 0x0a, 0x72, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x16, 0x2e,
	0x6d, 0x61, 0x72, 0x6b, 0x65, 0x74, 0x2e, 0x6d, 0x61, 0x73, 0x73, 0x2e, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x49, 0x64, 0x52, 0x09, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x49, 0x64,
	0x12, 0x43, 0x0a, 0x08, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x25, 0x2e, 0x6d, 0x61, 0x72, 0x6b, 0x65, 0x74, 0x2e, 0x6d, 0x61, 0x73, 0x73,
	0x2e, 0x45, 0x6e, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x65, 0x2e, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x69,
	0x63, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x48, 0x00, 0x52, 0x08, 0x72, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x50, 0x0a, 0x13, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x5f, 0x77,
	0x72, 0x69, 0x74, 0x65, 0x5f, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x1e, 0x2e, 0x6d, 0x61, 0x72, 0x6b, 0x65, 0x74, 0x2e, 0x6d, 0x61, 0x73, 0x73,
	0x2e, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x57, 0x72, 0x69, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x48, 0x00, 0x52, 0x11, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x57, 0x72, 0x69, 0x74, 0x65,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x55, 0x0a, 0x14, 0x73, 0x75, 0x62, 0x73, 0x63,
	0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x6d, 0x61, 0x72, 0x6b, 0x65, 0x74, 0x2e, 0x6d,
	0x61, 0x73, 0x73, 0x2e, 0x53, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x48, 0x00, 0x52, 0x13, 0x73, 0x75, 0x62, 0x73, 0x63,
	0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x62,
	0x0a, 0x19, 0x73, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x70,
	0x75, 0x73, 0x68, 0x5f, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x18, 0x05, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x24, 0x2e, 0x6d, 0x61, 0x72, 0x6b, 0x65, 0x74, 0x2e, 0x6d, 0x61, 0x73, 0x73, 0x2e,
	0x53, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x50, 0x75, 0x73, 0x68,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x48, 0x00, 0x52, 0x17, 0x73, 0x75, 0x62, 0x73, 0x63,
	0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x50, 0x75, 0x73, 0x68, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x12, 0x50, 0x0a, 0x13, 0x73, 0x79, 0x6e, 0x63, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x75,
	0x73, 0x5f, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1e, 0x2e, 0x6d, 0x61, 0x72, 0x6b, 0x65, 0x74, 0x2e, 0x6d, 0x61, 0x73, 0x73, 0x2e, 0x53, 0x79,
	0x6e, 0x63, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x48,
	0x00, 0x52, 0x11, 0x73, 0x79, 0x6e, 0x63, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x3d, 0x0a, 0x0c, 0x70, 0x69, 0x6e, 0x67, 0x5f, 0x72, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x6d, 0x61, 0x72,
	0x6b, 0x65, 0x74, 0x2e, 0x6d, 0x61, 0x73, 0x73, 0x2e, 0x50, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x48, 0x00, 0x52, 0x0b, 0x70, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x12, 0x64, 0x0a, 0x1b, 0x67, 0x65, 0x74, 0x5f, 0x62, 0x6c, 0x6f, 0x62, 0x5f,
	0x75, 0x70, 0x6c, 0x6f, 0x61, 0x64, 0x5f, 0x75, 0x72, 0x6c, 0x5f, 0x72, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x24, 0x2e, 0x6d, 0x61, 0x72, 0x6b, 0x65,
	0x74, 0x2e, 0x6d, 0x61, 0x73, 0x73, 0x2e, 0x47, 0x65, 0x74, 0x42, 0x6c, 0x6f, 0x62, 0x55, 0x70,
	0x6c, 0x6f, 0x61, 0x64, 0x55, 0x52, 0x4c, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x48, 0x00,
	0x52, 0x17, 0x67, 0x65, 0x74, 0x42, 0x6c, 0x6f, 0x62, 0x55, 0x70, 0x6c, 0x6f, 0x61, 0x64, 0x55,
	0x72, 0x6c, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x45, 0x0a, 0x0c, 0x61, 0x75, 0x74,
	0x68, 0x5f, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x20, 0x2e, 0x6d, 0x61, 0x72, 0x6b, 0x65, 0x74, 0x2e, 0x6d, 0x61, 0x73, 0x73, 0x2e, 0x41, 0x75,
	0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x48, 0x00, 0x52, 0x0b, 0x61, 0x75, 0x74, 0x68, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x12, 0x63, 0x0a, 0x1a, 0x63, 0x68, 0x61, 0x6c, 0x6c, 0x65, 0x6e, 0x67, 0x65, 0x5f, 0x73, 0x6f,
	0x6c, 0x75, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x18, 0x0a,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x23, 0x2e, 0x6d, 0x61, 0x72, 0x6b, 0x65, 0x74, 0x2e, 0x6d, 0x61,
	0x73, 0x73, 0x2e, 0x43, 0x68, 0x61, 0x6c, 0x6c, 0x65, 0x6e, 0x67, 0x65, 0x53, 0x6f, 0x6c, 0x76,
	0x65, 0x64, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x48, 0x00, 0x52, 0x18, 0x63, 0x68, 0x61,
	0x6c, 0x6c, 0x65, 0x6e, 0x67, 0x65, 0x53, 0x6f, 0x6c, 0x75, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x65, 0x0a, 0x0f, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x69, 0x63,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x2a, 0x0a, 0x05, 0x65, 0x72, 0x72, 0x6f,
	0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x6d, 0x61, 0x72, 0x6b, 0x65, 0x74,
	0x2e, 0x6d, 0x61, 0x73, 0x73, 0x2e, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x48, 0x00, 0x52, 0x05, 0x65,
	0x72, 0x72, 0x6f, 0x72, 0x12, 0x1a, 0x0a, 0x07, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0c, 0x48, 0x00, 0x52, 0x07, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
	0x42, 0x0a, 0x0a, 0x08, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x42, 0x09, 0x0a, 0x07,
	0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_envelope_proto_rawDescOnce sync.Once
	file_envelope_proto_rawDescData = file_envelope_proto_rawDesc
)

func file_envelope_proto_rawDescGZIP() []byte {
	file_envelope_proto_rawDescOnce.Do(func() {
		file_envelope_proto_rawDescData = protoimpl.X.CompressGZIP(file_envelope_proto_rawDescData)
	})
	return file_envelope_proto_rawDescData
}

var file_envelope_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_envelope_proto_goTypes = []interface{}{
	(*Envelope)(nil),                 // 0: market.mass.Envelope
	(*Envelope_GenericResponse)(nil), // 1: market.mass.Envelope.GenericResponse
	(*RequestId)(nil),                // 2: market.mass.RequestId
	(*EventWriteRequest)(nil),        // 3: market.mass.EventWriteRequest
	(*SubscriptionRequest)(nil),      // 4: market.mass.SubscriptionRequest
	(*SubscriptionPushRequest)(nil),  // 5: market.mass.SubscriptionPushRequest
	(*SyncStatusRequest)(nil),        // 6: market.mass.SyncStatusRequest
	(*PingRequest)(nil),              // 7: market.mass.PingRequest
	(*GetBlobUploadURLRequest)(nil),  // 8: market.mass.GetBlobUploadURLRequest
	(*AuthenticateRequest)(nil),      // 9: market.mass.AuthenticateRequest
	(*ChallengeSolvedRequest)(nil),   // 10: market.mass.ChallengeSolvedRequest
	(*Error)(nil),                    // 11: market.mass.Error
}
var file_envelope_proto_depIdxs = []int32{
	2,  // 0: market.mass.Envelope.request_id:type_name -> market.mass.RequestId
	1,  // 1: market.mass.Envelope.response:type_name -> market.mass.Envelope.GenericResponse
	3,  // 2: market.mass.Envelope.event_write_request:type_name -> market.mass.EventWriteRequest
	4,  // 3: market.mass.Envelope.subscription_request:type_name -> market.mass.SubscriptionRequest
	5,  // 4: market.mass.Envelope.subscription_push_request:type_name -> market.mass.SubscriptionPushRequest
	6,  // 5: market.mass.Envelope.sync_status_request:type_name -> market.mass.SyncStatusRequest
	7,  // 6: market.mass.Envelope.ping_request:type_name -> market.mass.PingRequest
	8,  // 7: market.mass.Envelope.get_blob_upload_url_request:type_name -> market.mass.GetBlobUploadURLRequest
	9,  // 8: market.mass.Envelope.auth_request:type_name -> market.mass.AuthenticateRequest
	10, // 9: market.mass.Envelope.challenge_solution_request:type_name -> market.mass.ChallengeSolvedRequest
	11, // 10: market.mass.Envelope.GenericResponse.error:type_name -> market.mass.Error
	11, // [11:11] is the sub-list for method output_type
	11, // [11:11] is the sub-list for method input_type
	11, // [11:11] is the sub-list for extension type_name
	11, // [11:11] is the sub-list for extension extendee
	0,  // [0:11] is the sub-list for field type_name
}

func init() { file_envelope_proto_init() }
func file_envelope_proto_init() {
	if File_envelope_proto != nil {
		return
	}
	file_authentication_proto_init()
	file_base_types_proto_init()
	file_error_proto_init()
	file_shop_requests_proto_init()
	file_subscription_proto_init()
	file_transport_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_envelope_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Envelope); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_envelope_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Envelope_GenericResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_envelope_proto_msgTypes[0].OneofWrappers = []interface{}{
		(*Envelope_Response)(nil),
		(*Envelope_EventWriteRequest)(nil),
		(*Envelope_SubscriptionRequest)(nil),
		(*Envelope_SubscriptionPushRequest)(nil),
		(*Envelope_SyncStatusRequest)(nil),
		(*Envelope_PingRequest)(nil),
		(*Envelope_GetBlobUploadUrlRequest)(nil),
		(*Envelope_AuthRequest)(nil),
		(*Envelope_ChallengeSolutionRequest)(nil),
	}
	file_envelope_proto_msgTypes[1].OneofWrappers = []interface{}{
		(*Envelope_GenericResponse_Error)(nil),
		(*Envelope_GenericResponse_Payload)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_envelope_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_envelope_proto_goTypes,
		DependencyIndexes: file_envelope_proto_depIdxs,
		MessageInfos:      file_envelope_proto_msgTypes,
	}.Build()
	File_envelope_proto = out.File
	file_envelope_proto_rawDesc = nil
	file_envelope_proto_goTypes = nil
	file_envelope_proto_depIdxs = nil
}
