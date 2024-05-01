// Generated from /nix/store/xkcj22890a0jhkflmc0lzdw89bhkmd8d-source/network-schema/store_requests.proto at version v2 (b16798f77d65153596d1932a06753cccae4bbc1e)

// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-License-Identifier: MIT

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v4.24.4
// source: store_requests.proto

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

// Initiate check out of a cart
type CommitItemsToOrderRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RequestId []byte `protobuf:"bytes,1,opt,name=request_id,json=requestId,proto3" json:"request_id,omitempty"`
	OrderId   []byte `protobuf:"bytes,2,opt,name=order_id,json=orderId,proto3" json:"order_id,omitempty"`
	Erc20Addr []byte `protobuf:"bytes,3,opt,name=erc20_addr,json=erc20Addr,proto3" json:"erc20_addr,omitempty"` // emtpy/unset means vanilla ETH
}

func (x *CommitItemsToOrderRequest) Reset() {
	*x = CommitItemsToOrderRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_store_requests_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CommitItemsToOrderRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CommitItemsToOrderRequest) ProtoMessage() {}

func (x *CommitItemsToOrderRequest) ProtoReflect() protoreflect.Message {
	mi := &file_store_requests_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CommitItemsToOrderRequest.ProtoReflect.Descriptor instead.
func (*CommitItemsToOrderRequest) Descriptor() ([]byte, []int) {
	return file_store_requests_proto_rawDescGZIP(), []int{0}
}

func (x *CommitItemsToOrderRequest) GetRequestId() []byte {
	if x != nil {
		return x.RequestId
	}
	return nil
}

func (x *CommitItemsToOrderRequest) GetOrderId() []byte {
	if x != nil {
		return x.OrderId
	}
	return nil
}

func (x *CommitItemsToOrderRequest) GetErc20Addr() []byte {
	if x != nil {
		return x.Erc20Addr
	}
	return nil
}

// Returns an error if the cart is already finalized.
// No error blocks further changes to a cart and starts the payment process.
type CommitItemsToOrderResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RequestId        []byte `protobuf:"bytes,1,opt,name=request_id,json=requestId,proto3" json:"request_id,omitempty"`
	Error            *Error `protobuf:"bytes,2,opt,name=error,proto3" json:"error,omitempty"`
	OrderFinalizedId []byte `protobuf:"bytes,3,opt,name=order_finalized_id,json=orderFinalizedId,proto3" json:"order_finalized_id,omitempty"`
}

func (x *CommitItemsToOrderResponse) Reset() {
	*x = CommitItemsToOrderResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_store_requests_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CommitItemsToOrderResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CommitItemsToOrderResponse) ProtoMessage() {}

func (x *CommitItemsToOrderResponse) ProtoReflect() protoreflect.Message {
	mi := &file_store_requests_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CommitItemsToOrderResponse.ProtoReflect.Descriptor instead.
func (*CommitItemsToOrderResponse) Descriptor() ([]byte, []int) {
	return file_store_requests_proto_rawDescGZIP(), []int{1}
}

func (x *CommitItemsToOrderResponse) GetRequestId() []byte {
	if x != nil {
		return x.RequestId
	}
	return nil
}

func (x *CommitItemsToOrderResponse) GetError() *Error {
	if x != nil {
		return x.Error
	}
	return nil
}

func (x *CommitItemsToOrderResponse) GetOrderFinalizedId() []byte {
	if x != nil {
		return x.OrderFinalizedId
	}
	return nil
}

// Get an URL to upload a blob to.
// This exists for future-proofing the protocol
// and reduce stress on the websocket connection.
type GetBlobUploadURLRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RequestId []byte `protobuf:"bytes,1,opt,name=request_id,json=requestId,proto3" json:"request_id,omitempty"`
}

func (x *GetBlobUploadURLRequest) Reset() {
	*x = GetBlobUploadURLRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_store_requests_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetBlobUploadURLRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetBlobUploadURLRequest) ProtoMessage() {}

func (x *GetBlobUploadURLRequest) ProtoReflect() protoreflect.Message {
	mi := &file_store_requests_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetBlobUploadURLRequest.ProtoReflect.Descriptor instead.
func (*GetBlobUploadURLRequest) Descriptor() ([]byte, []int) {
	return file_store_requests_proto_rawDescGZIP(), []int{2}
}

func (x *GetBlobUploadURLRequest) GetRequestId() []byte {
	if x != nil {
		return x.RequestId
	}
	return nil
}

// Returns a single-use URL to upload a blob to.
// The HTTP response will contain the blob's IPFS path.
type GetBlobUploadURLResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RequestId []byte `protobuf:"bytes,1,opt,name=request_id,json=requestId,proto3" json:"request_id,omitempty"`
	Error     *Error `protobuf:"bytes,2,opt,name=error,proto3" json:"error,omitempty"`
	Url       string `protobuf:"bytes,3,opt,name=url,proto3" json:"url,omitempty"`
}

func (x *GetBlobUploadURLResponse) Reset() {
	*x = GetBlobUploadURLResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_store_requests_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetBlobUploadURLResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetBlobUploadURLResponse) ProtoMessage() {}

func (x *GetBlobUploadURLResponse) ProtoReflect() protoreflect.Message {
	mi := &file_store_requests_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetBlobUploadURLResponse.ProtoReflect.Descriptor instead.
func (*GetBlobUploadURLResponse) Descriptor() ([]byte, []int) {
	return file_store_requests_proto_rawDescGZIP(), []int{3}
}

func (x *GetBlobUploadURLResponse) GetRequestId() []byte {
	if x != nil {
		return x.RequestId
	}
	return nil
}

func (x *GetBlobUploadURLResponse) GetError() *Error {
	if x != nil {
		return x.Error
	}
	return nil
}

func (x *GetBlobUploadURLResponse) GetUrl() string {
	if x != nil {
		return x.Url
	}
	return ""
}

var File_store_requests_proto protoreflect.FileDescriptor

var file_store_requests_proto_rawDesc = []byte{
	0x0a, 0x14, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x5f, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x73,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0b, 0x6d, 0x61, 0x72, 0x6b, 0x65, 0x74, 0x2e, 0x6d,
	0x61, 0x73, 0x73, 0x1a, 0x0b, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x22, 0x74, 0x0a, 0x19, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x49, 0x74, 0x65, 0x6d, 0x73, 0x54,
	0x6f, 0x4f, 0x72, 0x64, 0x65, 0x72, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1d, 0x0a,
	0x0a, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x09, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x49, 0x64, 0x12, 0x19, 0x0a, 0x08,
	0x6f, 0x72, 0x64, 0x65, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07,
	0x6f, 0x72, 0x64, 0x65, 0x72, 0x49, 0x64, 0x12, 0x1d, 0x0a, 0x0a, 0x65, 0x72, 0x63, 0x32, 0x30,
	0x5f, 0x61, 0x64, 0x64, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x65, 0x72, 0x63,
	0x32, 0x30, 0x41, 0x64, 0x64, 0x72, 0x22, 0x93, 0x01, 0x0a, 0x1a, 0x43, 0x6f, 0x6d, 0x6d, 0x69,
	0x74, 0x49, 0x74, 0x65, 0x6d, 0x73, 0x54, 0x6f, 0x4f, 0x72, 0x64, 0x65, 0x72, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x72, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x49, 0x64, 0x12, 0x28, 0x0a, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x6d, 0x61, 0x72, 0x6b, 0x65, 0x74, 0x2e, 0x6d, 0x61, 0x73,
	0x73, 0x2e, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x52, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x12, 0x2c,
	0x0a, 0x12, 0x6f, 0x72, 0x64, 0x65, 0x72, 0x5f, 0x66, 0x69, 0x6e, 0x61, 0x6c, 0x69, 0x7a, 0x65,
	0x64, 0x5f, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x10, 0x6f, 0x72, 0x64, 0x65,
	0x72, 0x46, 0x69, 0x6e, 0x61, 0x6c, 0x69, 0x7a, 0x65, 0x64, 0x49, 0x64, 0x22, 0x38, 0x0a, 0x17,
	0x47, 0x65, 0x74, 0x42, 0x6c, 0x6f, 0x62, 0x55, 0x70, 0x6c, 0x6f, 0x61, 0x64, 0x55, 0x52, 0x4c,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1d, 0x0a, 0x0a, 0x72, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x72, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x49, 0x64, 0x22, 0x75, 0x0a, 0x18, 0x47, 0x65, 0x74, 0x42, 0x6c, 0x6f,
	0x62, 0x55, 0x70, 0x6c, 0x6f, 0x61, 0x64, 0x55, 0x52, 0x4c, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x69, 0x64,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x49,
	0x64, 0x12, 0x28, 0x0a, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x12, 0x2e, 0x6d, 0x61, 0x72, 0x6b, 0x65, 0x74, 0x2e, 0x6d, 0x61, 0x73, 0x73, 0x2e, 0x45,
	0x72, 0x72, 0x6f, 0x72, 0x52, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x12, 0x10, 0x0a, 0x03, 0x75,
	0x72, 0x6c, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x75, 0x72, 0x6c, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_store_requests_proto_rawDescOnce sync.Once
	file_store_requests_proto_rawDescData = file_store_requests_proto_rawDesc
)

func file_store_requests_proto_rawDescGZIP() []byte {
	file_store_requests_proto_rawDescOnce.Do(func() {
		file_store_requests_proto_rawDescData = protoimpl.X.CompressGZIP(file_store_requests_proto_rawDescData)
	})
	return file_store_requests_proto_rawDescData
}

var file_store_requests_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_store_requests_proto_goTypes = []interface{}{
	(*CommitItemsToOrderRequest)(nil),  // 0: market.mass.CommitItemsToOrderRequest
	(*CommitItemsToOrderResponse)(nil), // 1: market.mass.CommitItemsToOrderResponse
	(*GetBlobUploadURLRequest)(nil),    // 2: market.mass.GetBlobUploadURLRequest
	(*GetBlobUploadURLResponse)(nil),   // 3: market.mass.GetBlobUploadURLResponse
	(*Error)(nil),                      // 4: market.mass.Error
}
var file_store_requests_proto_depIdxs = []int32{
	4, // 0: market.mass.CommitItemsToOrderResponse.error:type_name -> market.mass.Error
	4, // 1: market.mass.GetBlobUploadURLResponse.error:type_name -> market.mass.Error
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_store_requests_proto_init() }
func file_store_requests_proto_init() {
	if File_store_requests_proto != nil {
		return
	}
	file_error_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_store_requests_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CommitItemsToOrderRequest); i {
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
		file_store_requests_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CommitItemsToOrderResponse); i {
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
		file_store_requests_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetBlobUploadURLRequest); i {
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
		file_store_requests_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetBlobUploadURLResponse); i {
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
			RawDescriptor: file_store_requests_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_store_requests_proto_goTypes,
		DependencyIndexes: file_store_requests_proto_depIdxs,
		MessageInfos:      file_store_requests_proto_msgTypes,
	}.Build()
	File_store_requests_proto = out.File
	file_store_requests_proto_rawDesc = nil
	file_store_requests_proto_goTypes = nil
	file_store_requests_proto_depIdxs = nil
}
