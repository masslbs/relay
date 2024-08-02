// Generated from /nix/store/r14cbryys0jdmf9msi39arssgc13851p-source/network-schema/subscription.proto at version v3 (5ac728e84c6ed53e4aea4c58dee94ad539169b0b)

// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-License-Identifier: MIT

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.1
// 	protoc        v4.24.4
// source: subscription.proto

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

// The types of objects that events effect
type ObjectType int32

const (
	ObjectType_OBJECT_TYPE_UNSPECIFIED ObjectType = 0 // invalid
	ObjectType_OBJECT_TYPE_LISTING     ObjectType = 1
	ObjectType_OBJECT_TYPE_TAG         ObjectType = 2
	ObjectType_OBJECT_TYPE_ORDER       ObjectType = 3
	// accounts refer to keycards enrollments and customer accounts
	ObjectType_OBJECT_TYPE_ACCOUNT  ObjectType = 4
	ObjectType_OBJECT_TYPE_MANIFEST ObjectType = 5
	// inventory is seperated since you must first authenticate to get the events
	ObjectType_OBJECT_TYPE_INVENTORY ObjectType = 6
)

// Enum value maps for ObjectType.
var (
	ObjectType_name = map[int32]string{
		0: "OBJECT_TYPE_UNSPECIFIED",
		1: "OBJECT_TYPE_LISTING",
		2: "OBJECT_TYPE_TAG",
		3: "OBJECT_TYPE_ORDER",
		4: "OBJECT_TYPE_ACCOUNT",
		5: "OBJECT_TYPE_MANIFEST",
		6: "OBJECT_TYPE_INVENTORY",
	}
	ObjectType_value = map[string]int32{
		"OBJECT_TYPE_UNSPECIFIED": 0,
		"OBJECT_TYPE_LISTING":     1,
		"OBJECT_TYPE_TAG":         2,
		"OBJECT_TYPE_ORDER":       3,
		"OBJECT_TYPE_ACCOUNT":     4,
		"OBJECT_TYPE_MANIFEST":    5,
		"OBJECT_TYPE_INVENTORY":   6,
	}
)

func (x ObjectType) Enum() *ObjectType {
	p := new(ObjectType)
	*p = x
	return p
}

func (x ObjectType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ObjectType) Descriptor() protoreflect.EnumDescriptor {
	return file_subscription_proto_enumTypes[0].Descriptor()
}

func (ObjectType) Type() protoreflect.EnumType {
	return &file_subscription_proto_enumTypes[0]
}

func (x ObjectType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ObjectType.Descriptor instead.
func (ObjectType) EnumDescriptor() ([]byte, []int) {
	return file_subscription_proto_rawDescGZIP(), []int{0}
}

// Used by the client to subscribe to a subset of event from the store
//
// reponse via GenericResponse
// which notifies the client wether the subscription was succseful
type SubscriptionRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The relay will send events from the shop log starting from this
	// sequence number.
	// what happens if this no longer exists?
	StartShopSeqNo uint64 `protobuf:"varint,1,opt,name=start_shop_seq_no,json=startShopSeqNo,proto3" json:"start_shop_seq_no,omitempty"`
	// The id of the shop that is being subscribed to. If an objectType
	// is not specified then the relay will return all the events for
	// the shop given the currently level of authentication.
	ShopId *Uint256 `protobuf:"bytes,2,opt,name=shop_id,json=shopId,proto3" json:"shop_id,omitempty"`
	// Filter can be applyed to return only a subset of events
	Filters []*SubscriptionRequest_Filter `protobuf:"bytes,3,rep,name=filters,proto3" json:"filters,omitempty"`
}

func (x *SubscriptionRequest) Reset() {
	*x = SubscriptionRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_subscription_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SubscriptionRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SubscriptionRequest) ProtoMessage() {}

func (x *SubscriptionRequest) ProtoReflect() protoreflect.Message {
	mi := &file_subscription_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SubscriptionRequest.ProtoReflect.Descriptor instead.
func (*SubscriptionRequest) Descriptor() ([]byte, []int) {
	return file_subscription_proto_rawDescGZIP(), []int{0}
}

func (x *SubscriptionRequest) GetStartShopSeqNo() uint64 {
	if x != nil {
		return x.StartShopSeqNo
	}
	return 0
}

func (x *SubscriptionRequest) GetShopId() *Uint256 {
	if x != nil {
		return x.ShopId
	}
	return nil
}

func (x *SubscriptionRequest) GetFilters() []*SubscriptionRequest_Filter {
	if x != nil {
		return x.Filters
	}
	return nil
}

// Used by the relay to push events to the client.
// Will not sent more events until the client has acknowledged the last batch.
//
// Client sends a GenericResponse without an error to acknowledge recepetion.
// To close a subscription, respond with ERROR_CODES_CLOSE_SUBSCRIPTION
type SubscriptionPushRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Events []*SignedEvent `protobuf:"bytes,1,rep,name=events,proto3" json:"events,omitempty"`
}

func (x *SubscriptionPushRequest) Reset() {
	*x = SubscriptionPushRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_subscription_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SubscriptionPushRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SubscriptionPushRequest) ProtoMessage() {}

func (x *SubscriptionPushRequest) ProtoReflect() protoreflect.Message {
	mi := &file_subscription_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SubscriptionPushRequest.ProtoReflect.Descriptor instead.
func (*SubscriptionPushRequest) Descriptor() ([]byte, []int) {
	return file_subscription_proto_rawDescGZIP(), []int{1}
}

func (x *SubscriptionPushRequest) GetEvents() []*SignedEvent {
	if x != nil {
		return x.Events
	}
	return nil
}

type SubscriptionRequest_Filter struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Which object that is being subscribed to. Subscribing to an object
	// will return a  stream of events
	// that modify that object type. For example subscribing to LISTING
	// will return a stream of all the events
	// that modify listings in the store.
	ObjectType ObjectType `protobuf:"varint,3,opt,name=object_type,json=objectType,proto3,enum=market.mass.ObjectType" json:"object_type,omitempty"`
	// Optional subscribe to only events that modify a single item.
	// We assume object_id is only unique for a given object_type, so
	// object_type is required.
	ObjectId []byte `protobuf:"bytes,4,opt,name=object_id,json=objectId,proto3,oneof" json:"object_id,omitempty"`
}

func (x *SubscriptionRequest_Filter) Reset() {
	*x = SubscriptionRequest_Filter{}
	if protoimpl.UnsafeEnabled {
		mi := &file_subscription_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SubscriptionRequest_Filter) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SubscriptionRequest_Filter) ProtoMessage() {}

func (x *SubscriptionRequest_Filter) ProtoReflect() protoreflect.Message {
	mi := &file_subscription_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SubscriptionRequest_Filter.ProtoReflect.Descriptor instead.
func (*SubscriptionRequest_Filter) Descriptor() ([]byte, []int) {
	return file_subscription_proto_rawDescGZIP(), []int{0, 0}
}

func (x *SubscriptionRequest_Filter) GetObjectType() ObjectType {
	if x != nil {
		return x.ObjectType
	}
	return ObjectType_OBJECT_TYPE_UNSPECIFIED
}

func (x *SubscriptionRequest_Filter) GetObjectId() []byte {
	if x != nil {
		return x.ObjectId
	}
	return nil
}

var File_subscription_proto protoreflect.FileDescriptor

var file_subscription_proto_rawDesc = []byte{
	0x0a, 0x12, 0x73, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0b, 0x6d, 0x61, 0x72, 0x6b, 0x65, 0x74, 0x2e, 0x6d, 0x61, 0x73,
	0x73, 0x1a, 0x10, 0x62, 0x61, 0x73, 0x65, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x0f, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0xa6, 0x02, 0x0a, 0x13, 0x53, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69,
	0x70, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x29, 0x0a, 0x11,
	0x73, 0x74, 0x61, 0x72, 0x74, 0x5f, 0x73, 0x68, 0x6f, 0x70, 0x5f, 0x73, 0x65, 0x71, 0x5f, 0x6e,
	0x6f, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0e, 0x73, 0x74, 0x61, 0x72, 0x74, 0x53, 0x68,
	0x6f, 0x70, 0x53, 0x65, 0x71, 0x4e, 0x6f, 0x12, 0x2d, 0x0a, 0x07, 0x73, 0x68, 0x6f, 0x70, 0x5f,
	0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x6d, 0x61, 0x72, 0x6b, 0x65,
	0x74, 0x2e, 0x6d, 0x61, 0x73, 0x73, 0x2e, 0x55, 0x69, 0x6e, 0x74, 0x32, 0x35, 0x36, 0x52, 0x06,
	0x73, 0x68, 0x6f, 0x70, 0x49, 0x64, 0x12, 0x41, 0x0a, 0x07, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72,
	0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x27, 0x2e, 0x6d, 0x61, 0x72, 0x6b, 0x65, 0x74,
	0x2e, 0x6d, 0x61, 0x73, 0x73, 0x2e, 0x53, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69,
	0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x2e, 0x46, 0x69, 0x6c, 0x74, 0x65, 0x72,
	0x52, 0x07, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x1a, 0x72, 0x0a, 0x06, 0x46, 0x69, 0x6c,
	0x74, 0x65, 0x72, 0x12, 0x38, 0x0a, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x74, 0x79,
	0x70, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x17, 0x2e, 0x6d, 0x61, 0x72, 0x6b, 0x65,
	0x74, 0x2e, 0x6d, 0x61, 0x73, 0x73, 0x2e, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x54, 0x79, 0x70,
	0x65, 0x52, 0x0a, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x54, 0x79, 0x70, 0x65, 0x12, 0x20, 0x0a,
	0x09, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c,
	0x48, 0x00, 0x52, 0x08, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x49, 0x64, 0x88, 0x01, 0x01, 0x42,
	0x0c, 0x0a, 0x0a, 0x5f, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x69, 0x64, 0x22, 0x4b, 0x0a,
	0x17, 0x53, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x50, 0x75, 0x73,
	0x68, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x30, 0x0a, 0x06, 0x65, 0x76, 0x65, 0x6e,
	0x74, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x6d, 0x61, 0x72, 0x6b, 0x65,
	0x74, 0x2e, 0x6d, 0x61, 0x73, 0x73, 0x2e, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x45, 0x76, 0x65,
	0x6e, 0x74, 0x52, 0x06, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x73, 0x2a, 0xbc, 0x01, 0x0a, 0x0a, 0x4f,
	0x62, 0x6a, 0x65, 0x63, 0x74, 0x54, 0x79, 0x70, 0x65, 0x12, 0x1b, 0x0a, 0x17, 0x4f, 0x42, 0x4a,
	0x45, 0x43, 0x54, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49,
	0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x17, 0x0a, 0x13, 0x4f, 0x42, 0x4a, 0x45, 0x43, 0x54,
	0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x4c, 0x49, 0x53, 0x54, 0x49, 0x4e, 0x47, 0x10, 0x01, 0x12,
	0x13, 0x0a, 0x0f, 0x4f, 0x42, 0x4a, 0x45, 0x43, 0x54, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x54,
	0x41, 0x47, 0x10, 0x02, 0x12, 0x15, 0x0a, 0x11, 0x4f, 0x42, 0x4a, 0x45, 0x43, 0x54, 0x5f, 0x54,
	0x59, 0x50, 0x45, 0x5f, 0x4f, 0x52, 0x44, 0x45, 0x52, 0x10, 0x03, 0x12, 0x17, 0x0a, 0x13, 0x4f,
	0x42, 0x4a, 0x45, 0x43, 0x54, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x41, 0x43, 0x43, 0x4f, 0x55,
	0x4e, 0x54, 0x10, 0x04, 0x12, 0x18, 0x0a, 0x14, 0x4f, 0x42, 0x4a, 0x45, 0x43, 0x54, 0x5f, 0x54,
	0x59, 0x50, 0x45, 0x5f, 0x4d, 0x41, 0x4e, 0x49, 0x46, 0x45, 0x53, 0x54, 0x10, 0x05, 0x12, 0x19,
	0x0a, 0x15, 0x4f, 0x42, 0x4a, 0x45, 0x43, 0x54, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x5f, 0x49, 0x4e,
	0x56, 0x45, 0x4e, 0x54, 0x4f, 0x52, 0x59, 0x10, 0x06, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_subscription_proto_rawDescOnce sync.Once
	file_subscription_proto_rawDescData = file_subscription_proto_rawDesc
)

func file_subscription_proto_rawDescGZIP() []byte {
	file_subscription_proto_rawDescOnce.Do(func() {
		file_subscription_proto_rawDescData = protoimpl.X.CompressGZIP(file_subscription_proto_rawDescData)
	})
	return file_subscription_proto_rawDescData
}

var file_subscription_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_subscription_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_subscription_proto_goTypes = []interface{}{
	(ObjectType)(0),                    // 0: market.mass.ObjectType
	(*SubscriptionRequest)(nil),        // 1: market.mass.SubscriptionRequest
	(*SubscriptionPushRequest)(nil),    // 2: market.mass.SubscriptionPushRequest
	(*SubscriptionRequest_Filter)(nil), // 3: market.mass.SubscriptionRequest.Filter
	(*Uint256)(nil),                    // 4: market.mass.Uint256
	(*SignedEvent)(nil),                // 5: market.mass.SignedEvent
}
var file_subscription_proto_depIdxs = []int32{
	4, // 0: market.mass.SubscriptionRequest.shop_id:type_name -> market.mass.Uint256
	3, // 1: market.mass.SubscriptionRequest.filters:type_name -> market.mass.SubscriptionRequest.Filter
	5, // 2: market.mass.SubscriptionPushRequest.events:type_name -> market.mass.SignedEvent
	0, // 3: market.mass.SubscriptionRequest.Filter.object_type:type_name -> market.mass.ObjectType
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_subscription_proto_init() }
func file_subscription_proto_init() {
	if File_subscription_proto != nil {
		return
	}
	file_base_types_proto_init()
	file_transport_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_subscription_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SubscriptionRequest); i {
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
		file_subscription_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SubscriptionPushRequest); i {
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
		file_subscription_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SubscriptionRequest_Filter); i {
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
	file_subscription_proto_msgTypes[2].OneofWrappers = []interface{}{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_subscription_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_subscription_proto_goTypes,
		DependencyIndexes: file_subscription_proto_depIdxs,
		EnumInfos:         file_subscription_proto_enumTypes,
		MessageInfos:      file_subscription_proto_msgTypes,
	}.Build()
	File_subscription_proto = out.File
	file_subscription_proto_rawDesc = nil
	file_subscription_proto_goTypes = nil
	file_subscription_proto_depIdxs = nil
}
