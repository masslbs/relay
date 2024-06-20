// Generated from /nix/store/psdz2f6ch6ck8ykizjpad501c4rhd3m8-source/network-schema/error.proto at version v2 (7add0e4a0f4842870b3fb38386705a946292d017)

// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-License-Identifier: MIT

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        v4.24.4
// source: error.proto

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

type ErrorCodes int32

const (
	ErrorCodes_UNSPECIFIED                  ErrorCodes = 0
	ErrorCodes_NOT_FOUND                    ErrorCodes = 1
	ErrorCodes_INVALID                      ErrorCodes = 2
	ErrorCodes_NOT_AUTHENTICATED            ErrorCodes = 3
	ErrorCodes_ALREADY_AUTHENTICATED        ErrorCodes = 4
	ErrorCodes_ALREADY_CONNECTED            ErrorCodes = 5
	ErrorCodes_TOO_MANY_CONCURRENT_REQUESTS ErrorCodes = 6
	ErrorCodes_UNLINKED_KEYCARD             ErrorCodes = 7
	ErrorCodes_MINUMUM_VERSION_NOT_REACHED  ErrorCodes = 8
	ErrorCodes_OUT_OF_STOCK                 ErrorCodes = 9
	ErrorCodes_SIMULATED                    ErrorCodes = 10 // use to signal randmom/simulated errors
)

// Enum value maps for ErrorCodes.
var (
	ErrorCodes_name = map[int32]string{
		0:  "ERROR_CODES_UNSPECIFIED",
		1:  "ERROR_CODES_NOT_FOUND",
		2:  "ERROR_CODES_INVALID",
		3:  "ERROR_CODES_NOT_AUTHENTICATED",
		4:  "ERROR_CODES_ALREADY_AUTHENTICATED",
		5:  "ERROR_CODES_ALREADY_CONNECTED",
		6:  "ERROR_CODES_TOO_MANY_CONCURRENT_REQUESTS",
		7:  "ERROR_CODES_UNLINKED_KEYCARD",
		8:  "ERROR_CODES_MINUMUM_VERSION_NOT_REACHED",
		9:  "ERROR_CODES_OUT_OF_STOCK",
		10: "ERROR_CODES_SIMULATED",
	}
	ErrorCodes_value = map[string]int32{
		"ERROR_CODES_UNSPECIFIED":                  0,
		"ERROR_CODES_NOT_FOUND":                    1,
		"ERROR_CODES_INVALID":                      2,
		"ERROR_CODES_NOT_AUTHENTICATED":            3,
		"ERROR_CODES_ALREADY_AUTHENTICATED":        4,
		"ERROR_CODES_ALREADY_CONNECTED":            5,
		"ERROR_CODES_TOO_MANY_CONCURRENT_REQUESTS": 6,
		"ERROR_CODES_UNLINKED_KEYCARD":             7,
		"ERROR_CODES_MINUMUM_VERSION_NOT_REACHED":  8,
		"ERROR_CODES_OUT_OF_STOCK":                 9,
		"ERROR_CODES_SIMULATED":                    10,
	}
)

func (x ErrorCodes) Enum() *ErrorCodes {
	p := new(ErrorCodes)
	*p = x
	return p
}

func (x ErrorCodes) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ErrorCodes) Descriptor() protoreflect.EnumDescriptor {
	return file_error_proto_enumTypes[0].Descriptor()
}

func (ErrorCodes) Type() protoreflect.EnumType {
	return &file_error_proto_enumTypes[0]
}

func (x ErrorCodes) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ErrorCodes.Descriptor instead.
func (ErrorCodes) EnumDescriptor() ([]byte, []int) {
	return file_error_proto_rawDescGZIP(), []int{0}
}

type Error struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Code    ErrorCodes `protobuf:"varint,1,opt,name=code,proto3,enum=market.mass.ErrorCodes" json:"code,omitempty"`
	Message string     `protobuf:"bytes,2,opt,name=message,proto3" json:"message,omitempty"`
}

func (x *Error) Reset() {
	*x = Error{}
	if protoimpl.UnsafeEnabled {
		mi := &file_error_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Error) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Error) ProtoMessage() {}

func (x *Error) ProtoReflect() protoreflect.Message {
	mi := &file_error_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Error.ProtoReflect.Descriptor instead.
func (*Error) Descriptor() ([]byte, []int) {
	return file_error_proto_rawDescGZIP(), []int{0}
}

func (x *Error) GetCode() ErrorCodes {
	if x != nil {
		return x.Code
	}
	return ErrorCodes_UNSPECIFIED
}

func (x *Error) GetMessage() string {
	if x != nil {
		return x.Message
	}
	return ""
}

var File_error_proto protoreflect.FileDescriptor

var file_error_proto_rawDesc = []byte{
	0x0a, 0x0b, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0b, 0x6d,
	0x61, 0x72, 0x6b, 0x65, 0x74, 0x2e, 0x6d, 0x61, 0x73, 0x73, 0x22, 0x4e, 0x0a, 0x05, 0x45, 0x72,
	0x72, 0x6f, 0x72, 0x12, 0x2b, 0x0a, 0x04, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0e, 0x32, 0x17, 0x2e, 0x6d, 0x61, 0x72, 0x6b, 0x65, 0x74, 0x2e, 0x6d, 0x61, 0x73, 0x73, 0x2e,
	0x45, 0x72, 0x72, 0x6f, 0x72, 0x43, 0x6f, 0x64, 0x65, 0x73, 0x52, 0x04, 0x63, 0x6f, 0x64, 0x65,
	0x12, 0x18, 0x0a, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2a, 0x80, 0x03, 0x0a, 0x0a, 0x45,
	0x72, 0x72, 0x6f, 0x72, 0x43, 0x6f, 0x64, 0x65, 0x73, 0x12, 0x1b, 0x0a, 0x17, 0x45, 0x52, 0x52,
	0x4f, 0x52, 0x5f, 0x43, 0x4f, 0x44, 0x45, 0x53, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49,
	0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x12, 0x19, 0x0a, 0x15, 0x45, 0x52, 0x52, 0x4f, 0x52, 0x5f,
	0x43, 0x4f, 0x44, 0x45, 0x53, 0x5f, 0x4e, 0x4f, 0x54, 0x5f, 0x46, 0x4f, 0x55, 0x4e, 0x44, 0x10,
	0x01, 0x12, 0x17, 0x0a, 0x13, 0x45, 0x52, 0x52, 0x4f, 0x52, 0x5f, 0x43, 0x4f, 0x44, 0x45, 0x53,
	0x5f, 0x49, 0x4e, 0x56, 0x41, 0x4c, 0x49, 0x44, 0x10, 0x02, 0x12, 0x21, 0x0a, 0x1d, 0x45, 0x52,
	0x52, 0x4f, 0x52, 0x5f, 0x43, 0x4f, 0x44, 0x45, 0x53, 0x5f, 0x4e, 0x4f, 0x54, 0x5f, 0x41, 0x55,
	0x54, 0x48, 0x45, 0x4e, 0x54, 0x49, 0x43, 0x41, 0x54, 0x45, 0x44, 0x10, 0x03, 0x12, 0x25, 0x0a,
	0x21, 0x45, 0x52, 0x52, 0x4f, 0x52, 0x5f, 0x43, 0x4f, 0x44, 0x45, 0x53, 0x5f, 0x41, 0x4c, 0x52,
	0x45, 0x41, 0x44, 0x59, 0x5f, 0x41, 0x55, 0x54, 0x48, 0x45, 0x4e, 0x54, 0x49, 0x43, 0x41, 0x54,
	0x45, 0x44, 0x10, 0x04, 0x12, 0x21, 0x0a, 0x1d, 0x45, 0x52, 0x52, 0x4f, 0x52, 0x5f, 0x43, 0x4f,
	0x44, 0x45, 0x53, 0x5f, 0x41, 0x4c, 0x52, 0x45, 0x41, 0x44, 0x59, 0x5f, 0x43, 0x4f, 0x4e, 0x4e,
	0x45, 0x43, 0x54, 0x45, 0x44, 0x10, 0x05, 0x12, 0x2c, 0x0a, 0x28, 0x45, 0x52, 0x52, 0x4f, 0x52,
	0x5f, 0x43, 0x4f, 0x44, 0x45, 0x53, 0x5f, 0x54, 0x4f, 0x4f, 0x5f, 0x4d, 0x41, 0x4e, 0x59, 0x5f,
	0x43, 0x4f, 0x4e, 0x43, 0x55, 0x52, 0x52, 0x45, 0x4e, 0x54, 0x5f, 0x52, 0x45, 0x51, 0x55, 0x45,
	0x53, 0x54, 0x53, 0x10, 0x06, 0x12, 0x20, 0x0a, 0x1c, 0x45, 0x52, 0x52, 0x4f, 0x52, 0x5f, 0x43,
	0x4f, 0x44, 0x45, 0x53, 0x5f, 0x55, 0x4e, 0x4c, 0x49, 0x4e, 0x4b, 0x45, 0x44, 0x5f, 0x4b, 0x45,
	0x59, 0x43, 0x41, 0x52, 0x44, 0x10, 0x07, 0x12, 0x2b, 0x0a, 0x27, 0x45, 0x52, 0x52, 0x4f, 0x52,
	0x5f, 0x43, 0x4f, 0x44, 0x45, 0x53, 0x5f, 0x4d, 0x49, 0x4e, 0x55, 0x4d, 0x55, 0x4d, 0x5f, 0x56,
	0x45, 0x52, 0x53, 0x49, 0x4f, 0x4e, 0x5f, 0x4e, 0x4f, 0x54, 0x5f, 0x52, 0x45, 0x41, 0x43, 0x48,
	0x45, 0x44, 0x10, 0x08, 0x12, 0x1c, 0x0a, 0x18, 0x45, 0x52, 0x52, 0x4f, 0x52, 0x5f, 0x43, 0x4f,
	0x44, 0x45, 0x53, 0x5f, 0x4f, 0x55, 0x54, 0x5f, 0x4f, 0x46, 0x5f, 0x53, 0x54, 0x4f, 0x43, 0x4b,
	0x10, 0x09, 0x12, 0x19, 0x0a, 0x15, 0x45, 0x52, 0x52, 0x4f, 0x52, 0x5f, 0x43, 0x4f, 0x44, 0x45,
	0x53, 0x5f, 0x53, 0x49, 0x4d, 0x55, 0x4c, 0x41, 0x54, 0x45, 0x44, 0x10, 0x0a, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_error_proto_rawDescOnce sync.Once
	file_error_proto_rawDescData = file_error_proto_rawDesc
)

func file_error_proto_rawDescGZIP() []byte {
	file_error_proto_rawDescOnce.Do(func() {
		file_error_proto_rawDescData = protoimpl.X.CompressGZIP(file_error_proto_rawDescData)
	})
	return file_error_proto_rawDescData
}

var file_error_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_error_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_error_proto_goTypes = []interface{}{
	(ErrorCodes)(0), // 0: market.mass.ErrorCodes
	(*Error)(nil),   // 1: market.mass.Error
}
var file_error_proto_depIdxs = []int32{
	0, // 0: market.mass.Error.code:type_name -> market.mass.ErrorCodes
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_error_proto_init() }
func file_error_proto_init() {
	if File_error_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_error_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Error); i {
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
			RawDescriptor: file_error_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_error_proto_goTypes,
		DependencyIndexes: file_error_proto_depIdxs,
		EnumInfos:         file_error_proto_enumTypes,
		MessageInfos:      file_error_proto_msgTypes,
	}.Build()
	File_error_proto = out.File
	file_error_proto_rawDesc = nil
	file_error_proto_goTypes = nil
	file_error_proto_depIdxs = nil
}
