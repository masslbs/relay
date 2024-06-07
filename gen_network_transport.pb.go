// Generated from /nix/store/vcify823rvb5cvgwq0dwvcrblp5nxp4n-source/network-schema/transport.proto at version v2 (acc60bbe41693018700efca8dfe97ceeabb9fca3)

// SPDX-FileCopyrightText: 2023 - 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-License-Identifier: MIT

// This file defines the transport protocol between relays and clients.
// It's main purpose is transfer of events of the higher application levels.
// It is orthogonal to the store registry and other smart contracts.
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
//
// As of this version, the protocol is grouped into 4 areas:
// 1) the transport (this file)
// 2) authentication for establishing access rights
// 3) store specific requets
// 4) store events
//

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v4.24.4
// source: transport.proto

package main

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	anypb "google.golang.org/protobuf/types/known/anypb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Used by the Client to write a single event to the store.
type EventWriteRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RequestId []byte     `protobuf:"bytes,1,opt,name=request_id,json=requestId,proto3" json:"request_id,omitempty"`
	Event     *anypb.Any `protobuf:"bytes,2,opt,name=event,proto3" json:"event,omitempty"`
}

func (x *EventWriteRequest) Reset() {
	*x = EventWriteRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transport_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EventWriteRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EventWriteRequest) ProtoMessage() {}

func (x *EventWriteRequest) ProtoReflect() protoreflect.Message {
	mi := &file_transport_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EventWriteRequest.ProtoReflect.Descriptor instead.
func (*EventWriteRequest) Descriptor() ([]byte, []int) {
	return file_transport_proto_rawDescGZIP(), []int{0}
}

func (x *EventWriteRequest) GetRequestId() []byte {
	if x != nil {
		return x.RequestId
	}
	return nil
}

func (x *EventWriteRequest) GetEvent() *anypb.Any {
	if x != nil {
		return x.Event
	}
	return nil
}

// Might return an error if the event or its signature is invalid.
// If no error is returned,
// the new_store_hash is the hash of the store with the new event applied.
// The event_sequence_no is the index of the event in the stores log.
type EventWriteResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RequestId       []byte `protobuf:"bytes,1,opt,name=request_id,json=requestId,proto3" json:"request_id,omitempty"`
	Error           *Error `protobuf:"bytes,2,opt,name=error,proto3" json:"error,omitempty"`
	NewStoreHash    []byte `protobuf:"bytes,3,opt,name=new_store_hash,json=newStoreHash,proto3" json:"new_store_hash,omitempty"`
	EventSequenceNo uint64 `protobuf:"varint,4,opt,name=event_sequence_no,json=eventSequenceNo,proto3" json:"event_sequence_no,omitempty"`
}

func (x *EventWriteResponse) Reset() {
	*x = EventWriteResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transport_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EventWriteResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EventWriteResponse) ProtoMessage() {}

func (x *EventWriteResponse) ProtoReflect() protoreflect.Message {
	mi := &file_transport_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EventWriteResponse.ProtoReflect.Descriptor instead.
func (*EventWriteResponse) Descriptor() ([]byte, []int) {
	return file_transport_proto_rawDescGZIP(), []int{1}
}

func (x *EventWriteResponse) GetRequestId() []byte {
	if x != nil {
		return x.RequestId
	}
	return nil
}

func (x *EventWriteResponse) GetError() *Error {
	if x != nil {
		return x.Error
	}
	return nil
}

func (x *EventWriteResponse) GetNewStoreHash() []byte {
	if x != nil {
		return x.NewStoreHash
	}
	return nil
}

func (x *EventWriteResponse) GetEventSequenceNo() uint64 {
	if x != nil {
		return x.EventSequenceNo
	}
	return 0
}

// Used by the relay to push events to the client.
// Will not sent more events until the client has acknowledged the last batch.
type EventPushRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RequestId []byte       `protobuf:"bytes,1,opt,name=request_id,json=requestId,proto3" json:"request_id,omitempty"`
	Events    []*anypb.Any `protobuf:"bytes,2,rep,name=events,proto3" json:"events,omitempty"`
}

func (x *EventPushRequest) Reset() {
	*x = EventPushRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transport_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EventPushRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EventPushRequest) ProtoMessage() {}

func (x *EventPushRequest) ProtoReflect() protoreflect.Message {
	mi := &file_transport_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EventPushRequest.ProtoReflect.Descriptor instead.
func (*EventPushRequest) Descriptor() ([]byte, []int) {
	return file_transport_proto_rawDescGZIP(), []int{2}
}

func (x *EventPushRequest) GetRequestId() []byte {
	if x != nil {
		return x.RequestId
	}
	return nil
}

func (x *EventPushRequest) GetEvents() []*anypb.Any {
	if x != nil {
		return x.Events
	}
	return nil
}

type EventPushResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RequestId []byte `protobuf:"bytes,1,opt,name=request_id,json=requestId,proto3" json:"request_id,omitempty"`
	Error     *Error `protobuf:"bytes,2,opt,name=error,proto3" json:"error,omitempty"`
}

func (x *EventPushResponse) Reset() {
	*x = EventPushResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transport_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EventPushResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EventPushResponse) ProtoMessage() {}

func (x *EventPushResponse) ProtoReflect() protoreflect.Message {
	mi := &file_transport_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EventPushResponse.ProtoReflect.Descriptor instead.
func (*EventPushResponse) Descriptor() ([]byte, []int) {
	return file_transport_proto_rawDescGZIP(), []int{3}
}

func (x *EventPushResponse) GetRequestId() []byte {
	if x != nil {
		return x.RequestId
	}
	return nil
}

func (x *EventPushResponse) GetError() *Error {
	if x != nil {
		return x.Error
	}
	return nil
}

// Sent by the relay to signal the number of unpushed events.
type SyncStatusRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RequestId      []byte `protobuf:"bytes,1,opt,name=request_id,json=requestId,proto3" json:"request_id,omitempty"`
	UnpushedEvents uint64 `protobuf:"varint,2,opt,name=unpushed_events,json=unpushedEvents,proto3" json:"unpushed_events,omitempty"`
}

func (x *SyncStatusRequest) Reset() {
	*x = SyncStatusRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transport_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SyncStatusRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SyncStatusRequest) ProtoMessage() {}

func (x *SyncStatusRequest) ProtoReflect() protoreflect.Message {
	mi := &file_transport_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SyncStatusRequest.ProtoReflect.Descriptor instead.
func (*SyncStatusRequest) Descriptor() ([]byte, []int) {
	return file_transport_proto_rawDescGZIP(), []int{4}
}

func (x *SyncStatusRequest) GetRequestId() []byte {
	if x != nil {
		return x.RequestId
	}
	return nil
}

func (x *SyncStatusRequest) GetUnpushedEvents() uint64 {
	if x != nil {
		return x.UnpushedEvents
	}
	return 0
}

type SyncStatusResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RequestId []byte `protobuf:"bytes,1,opt,name=request_id,json=requestId,proto3" json:"request_id,omitempty"`
	Error     *Error `protobuf:"bytes,2,opt,name=error,proto3" json:"error,omitempty"`
}

func (x *SyncStatusResponse) Reset() {
	*x = SyncStatusResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transport_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SyncStatusResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SyncStatusResponse) ProtoMessage() {}

func (x *SyncStatusResponse) ProtoReflect() protoreflect.Message {
	mi := &file_transport_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SyncStatusResponse.ProtoReflect.Descriptor instead.
func (*SyncStatusResponse) Descriptor() ([]byte, []int) {
	return file_transport_proto_rawDescGZIP(), []int{5}
}

func (x *SyncStatusResponse) GetRequestId() []byte {
	if x != nil {
		return x.RequestId
	}
	return nil
}

func (x *SyncStatusResponse) GetError() *Error {
	if x != nil {
		return x.Error
	}
	return nil
}

// Sent by the relay to check for the clients liveness.
// The client needs to respond with a PingResponse.
// The relay will close the connection if the client doesn't respond 3 times.
type PingRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// 16 bytes, chosen by the sender but should be random.
	// Used to match the response to the request.
	RequestId []byte `protobuf:"bytes,1,opt,name=request_id,json=requestId,proto3" json:"request_id,omitempty"`
}

func (x *PingRequest) Reset() {
	*x = PingRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transport_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PingRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PingRequest) ProtoMessage() {}

func (x *PingRequest) ProtoReflect() protoreflect.Message {
	mi := &file_transport_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PingRequest.ProtoReflect.Descriptor instead.
func (*PingRequest) Descriptor() ([]byte, []int) {
	return file_transport_proto_rawDescGZIP(), []int{6}
}

func (x *PingRequest) GetRequestId() []byte {
	if x != nil {
		return x.RequestId
	}
	return nil
}

type PingResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RequestId []byte `protobuf:"bytes,1,opt,name=request_id,json=requestId,proto3" json:"request_id,omitempty"`
	Error     *Error `protobuf:"bytes,2,opt,name=error,proto3" json:"error,omitempty"`
}

func (x *PingResponse) Reset() {
	*x = PingResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_transport_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PingResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PingResponse) ProtoMessage() {}

func (x *PingResponse) ProtoReflect() protoreflect.Message {
	mi := &file_transport_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PingResponse.ProtoReflect.Descriptor instead.
func (*PingResponse) Descriptor() ([]byte, []int) {
	return file_transport_proto_rawDescGZIP(), []int{7}
}

func (x *PingResponse) GetRequestId() []byte {
	if x != nil {
		return x.RequestId
	}
	return nil
}

func (x *PingResponse) GetError() *Error {
	if x != nil {
		return x.Error
	}
	return nil
}

var File_transport_proto protoreflect.FileDescriptor

var file_transport_proto_rawDesc = []byte{
	0x0a, 0x0f, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x0b, 0x6d, 0x61, 0x72, 0x6b, 0x65, 0x74, 0x2e, 0x6d, 0x61, 0x73, 0x73, 0x1a, 0x19,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f,
	0x61, 0x6e, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x0b, 0x65, 0x72, 0x72, 0x6f, 0x72,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x5e, 0x0a, 0x11, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x57,
	0x72, 0x69, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1d, 0x0a, 0x0a, 0x72,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x09, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x49, 0x64, 0x12, 0x2a, 0x0a, 0x05, 0x65, 0x76,
	0x65, 0x6e, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x41, 0x6e, 0x79, 0x52,
	0x05, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x22, 0xaf, 0x01, 0x0a, 0x12, 0x45, 0x76, 0x65, 0x6e, 0x74,
	0x57, 0x72, 0x69, 0x74, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x1d, 0x0a,
	0x0a, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x09, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x49, 0x64, 0x12, 0x28, 0x0a, 0x05,
	0x65, 0x72, 0x72, 0x6f, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x6d, 0x61,
	0x72, 0x6b, 0x65, 0x74, 0x2e, 0x6d, 0x61, 0x73, 0x73, 0x2e, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x52,
	0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x12, 0x24, 0x0a, 0x0e, 0x6e, 0x65, 0x77, 0x5f, 0x73, 0x74,
	0x6f, 0x72, 0x65, 0x5f, 0x68, 0x61, 0x73, 0x68, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0c,
	0x6e, 0x65, 0x77, 0x53, 0x74, 0x6f, 0x72, 0x65, 0x48, 0x61, 0x73, 0x68, 0x12, 0x2a, 0x0a, 0x11,
	0x65, 0x76, 0x65, 0x6e, 0x74, 0x5f, 0x73, 0x65, 0x71, 0x75, 0x65, 0x6e, 0x63, 0x65, 0x5f, 0x6e,
	0x6f, 0x18, 0x04, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0f, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x53, 0x65,
	0x71, 0x75, 0x65, 0x6e, 0x63, 0x65, 0x4e, 0x6f, 0x22, 0x5f, 0x0a, 0x10, 0x45, 0x76, 0x65, 0x6e,
	0x74, 0x50, 0x75, 0x73, 0x68, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1d, 0x0a, 0x0a,
	0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x09, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x49, 0x64, 0x12, 0x2c, 0x0a, 0x06, 0x65,
	0x76, 0x65, 0x6e, 0x74, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x41, 0x6e,
	0x79, 0x52, 0x06, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x73, 0x22, 0x5c, 0x0a, 0x11, 0x45, 0x76, 0x65,
	0x6e, 0x74, 0x50, 0x75, 0x73, 0x68, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x1d,
	0x0a, 0x0a, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x09, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x49, 0x64, 0x12, 0x28, 0x0a,
	0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x6d,
	0x61, 0x72, 0x6b, 0x65, 0x74, 0x2e, 0x6d, 0x61, 0x73, 0x73, 0x2e, 0x45, 0x72, 0x72, 0x6f, 0x72,
	0x52, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x22, 0x5b, 0x0a, 0x11, 0x53, 0x79, 0x6e, 0x63, 0x53,
	0x74, 0x61, 0x74, 0x75, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1d, 0x0a, 0x0a,
	0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x09, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x49, 0x64, 0x12, 0x27, 0x0a, 0x0f, 0x75,
	0x6e, 0x70, 0x75, 0x73, 0x68, 0x65, 0x64, 0x5f, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x73, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x04, 0x52, 0x0e, 0x75, 0x6e, 0x70, 0x75, 0x73, 0x68, 0x65, 0x64, 0x45, 0x76,
	0x65, 0x6e, 0x74, 0x73, 0x22, 0x5d, 0x0a, 0x12, 0x53, 0x79, 0x6e, 0x63, 0x53, 0x74, 0x61, 0x74,
	0x75, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x72, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09,
	0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x49, 0x64, 0x12, 0x28, 0x0a, 0x05, 0x65, 0x72, 0x72,
	0x6f, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x6d, 0x61, 0x72, 0x6b, 0x65,
	0x74, 0x2e, 0x6d, 0x61, 0x73, 0x73, 0x2e, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x52, 0x05, 0x65, 0x72,
	0x72, 0x6f, 0x72, 0x22, 0x2c, 0x0a, 0x0b, 0x50, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x12, 0x1d, 0x0a, 0x0a, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x69, 0x64,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x49,
	0x64, 0x22, 0x57, 0x0a, 0x0c, 0x50, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x69, 0x64, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x49, 0x64,
	0x12, 0x28, 0x0a, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x12, 0x2e, 0x6d, 0x61, 0x72, 0x6b, 0x65, 0x74, 0x2e, 0x6d, 0x61, 0x73, 0x73, 0x2e, 0x45, 0x72,
	0x72, 0x6f, 0x72, 0x52, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_transport_proto_rawDescOnce sync.Once
	file_transport_proto_rawDescData = file_transport_proto_rawDesc
)

func file_transport_proto_rawDescGZIP() []byte {
	file_transport_proto_rawDescOnce.Do(func() {
		file_transport_proto_rawDescData = protoimpl.X.CompressGZIP(file_transport_proto_rawDescData)
	})
	return file_transport_proto_rawDescData
}

var file_transport_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_transport_proto_goTypes = []interface{}{
	(*EventWriteRequest)(nil),  // 0: market.mass.EventWriteRequest
	(*EventWriteResponse)(nil), // 1: market.mass.EventWriteResponse
	(*EventPushRequest)(nil),   // 2: market.mass.EventPushRequest
	(*EventPushResponse)(nil),  // 3: market.mass.EventPushResponse
	(*SyncStatusRequest)(nil),  // 4: market.mass.SyncStatusRequest
	(*SyncStatusResponse)(nil), // 5: market.mass.SyncStatusResponse
	(*PingRequest)(nil),        // 6: market.mass.PingRequest
	(*PingResponse)(nil),       // 7: market.mass.PingResponse
	(*anypb.Any)(nil),          // 8: google.protobuf.Any
	(*Error)(nil),              // 9: market.mass.Error
}
var file_transport_proto_depIdxs = []int32{
	8, // 0: market.mass.EventWriteRequest.event:type_name -> google.protobuf.Any
	9, // 1: market.mass.EventWriteResponse.error:type_name -> market.mass.Error
	8, // 2: market.mass.EventPushRequest.events:type_name -> google.protobuf.Any
	9, // 3: market.mass.EventPushResponse.error:type_name -> market.mass.Error
	9, // 4: market.mass.SyncStatusResponse.error:type_name -> market.mass.Error
	9, // 5: market.mass.PingResponse.error:type_name -> market.mass.Error
	6, // [6:6] is the sub-list for method output_type
	6, // [6:6] is the sub-list for method input_type
	6, // [6:6] is the sub-list for extension type_name
	6, // [6:6] is the sub-list for extension extendee
	0, // [0:6] is the sub-list for field type_name
}

func init() { file_transport_proto_init() }
func file_transport_proto_init() {
	if File_transport_proto != nil {
		return
	}
	file_error_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_transport_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EventWriteRequest); i {
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
		file_transport_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EventWriteResponse); i {
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
		file_transport_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EventPushRequest); i {
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
		file_transport_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EventPushResponse); i {
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
		file_transport_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SyncStatusRequest); i {
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
		file_transport_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SyncStatusResponse); i {
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
		file_transport_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PingRequest); i {
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
		file_transport_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PingResponse); i {
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
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_transport_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_transport_proto_goTypes,
		DependencyIndexes: file_transport_proto_depIdxs,
		MessageInfos:      file_transport_proto_msgTypes,
	}.Build()
	File_transport_proto = out.File
	file_transport_proto_rawDesc = nil
	file_transport_proto_goTypes = nil
	file_transport_proto_depIdxs = nil
}
