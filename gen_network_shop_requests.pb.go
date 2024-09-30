// Generated from /nix/store/48d398y3dfpbayxh96vgyhqlq5jirh9z-source/network-schema/shop_requests.proto at version v3 (6147809bbce291ee5ed436e8cc9f0ef8858e6ec3)

// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-License-Identifier: MIT

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.1
// 	protoc        v4.24.4
// source: shop_requests.proto

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

// Get an URL to upload a blob to.
// This exists for future-proofing the protocol
// and reduce stress on the websocket connection.
// GenericResponse returns a single-use URL to upload a blob to.
// The HTTP response will contain the blob's IPFS path.
type GetBlobUploadURLRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *GetBlobUploadURLRequest) Reset() {
	*x = GetBlobUploadURLRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_shop_requests_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetBlobUploadURLRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetBlobUploadURLRequest) ProtoMessage() {}

func (x *GetBlobUploadURLRequest) ProtoReflect() protoreflect.Message {
	mi := &file_shop_requests_proto_msgTypes[0]
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
	return file_shop_requests_proto_rawDescGZIP(), []int{0}
}

var File_shop_requests_proto protoreflect.FileDescriptor

var file_shop_requests_proto_rawDesc = []byte{
	0x0a, 0x13, 0x73, 0x68, 0x6f, 0x70, 0x5f, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x73, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0b, 0x6d, 0x61, 0x72, 0x6b, 0x65, 0x74, 0x2e, 0x6d, 0x61,
	0x73, 0x73, 0x22, 0x19, 0x0a, 0x17, 0x47, 0x65, 0x74, 0x42, 0x6c, 0x6f, 0x62, 0x55, 0x70, 0x6c,
	0x6f, 0x61, 0x64, 0x55, 0x52, 0x4c, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_shop_requests_proto_rawDescOnce sync.Once
	file_shop_requests_proto_rawDescData = file_shop_requests_proto_rawDesc
)

func file_shop_requests_proto_rawDescGZIP() []byte {
	file_shop_requests_proto_rawDescOnce.Do(func() {
		file_shop_requests_proto_rawDescData = protoimpl.X.CompressGZIP(file_shop_requests_proto_rawDescData)
	})
	return file_shop_requests_proto_rawDescData
}

var file_shop_requests_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_shop_requests_proto_goTypes = []interface{}{
	(*GetBlobUploadURLRequest)(nil), // 0: market.mass.GetBlobUploadURLRequest
}
var file_shop_requests_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_shop_requests_proto_init() }
func file_shop_requests_proto_init() {
	if File_shop_requests_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_shop_requests_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
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
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_shop_requests_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_shop_requests_proto_goTypes,
		DependencyIndexes: file_shop_requests_proto_depIdxs,
		MessageInfos:      file_shop_requests_proto_msgTypes,
	}.Build()
	File_shop_requests_proto = out.File
	file_shop_requests_proto_rawDesc = nil
	file_shop_requests_proto_goTypes = nil
	file_shop_requests_proto_depIdxs = nil
}
