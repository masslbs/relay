// Generated from /nix/store/48d398y3dfpbayxh96vgyhqlq5jirh9z-source/network-schema/authentication.proto at version v3 (6147809bbce291ee5ed436e8cc9f0ef8858e6ec3)

// SPDX-FileCopyrightText: 2024 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-License-Identifier: MIT

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.1
// 	protoc        v4.24.4
// source: authentication.proto

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

// Initiates the challenge/response protocol.
// reponse via GenericResponse
// Returns an error if the public key is not an enrolled KeyCard.
// or a challenge to be signed by the KeyCard.
type AuthenticateRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PublicKey *PublicKey `protobuf:"bytes,2,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"` // of their keyCard
}

func (x *AuthenticateRequest) Reset() {
	*x = AuthenticateRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_authentication_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AuthenticateRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuthenticateRequest) ProtoMessage() {}

func (x *AuthenticateRequest) ProtoReflect() protoreflect.Message {
	mi := &file_authentication_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AuthenticateRequest.ProtoReflect.Descriptor instead.
func (*AuthenticateRequest) Descriptor() ([]byte, []int) {
	return file_authentication_proto_rawDescGZIP(), []int{0}
}

func (x *AuthenticateRequest) GetPublicKey() *PublicKey {
	if x != nil {
		return x.PublicKey
	}
	return nil
}

// Completes authentication by supplying the signature over the challenge.
// Responded with GnericResponse. // No error means the user is authenticated.
type ChallengeSolvedRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Signature *Signature `protobuf:"bytes,2,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (x *ChallengeSolvedRequest) Reset() {
	*x = ChallengeSolvedRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_authentication_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ChallengeSolvedRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ChallengeSolvedRequest) ProtoMessage() {}

func (x *ChallengeSolvedRequest) ProtoReflect() protoreflect.Message {
	mi := &file_authentication_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ChallengeSolvedRequest.ProtoReflect.Descriptor instead.
func (*ChallengeSolvedRequest) Descriptor() ([]byte, []int) {
	return file_authentication_proto_rawDescGZIP(), []int{1}
}

func (x *ChallengeSolvedRequest) GetSignature() *Signature {
	if x != nil {
		return x.Signature
	}
	return nil
}

var File_authentication_proto protoreflect.FileDescriptor

var file_authentication_proto_rawDesc = []byte{
	0x0a, 0x14, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0b, 0x6d, 0x61, 0x72, 0x6b, 0x65, 0x74, 0x2e, 0x6d,
	0x61, 0x73, 0x73, 0x1a, 0x10, 0x62, 0x61, 0x73, 0x65, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x4c, 0x0a, 0x13, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74,
	0x69, 0x63, 0x61, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x35, 0x0a, 0x0a,
	0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x16, 0x2e, 0x6d, 0x61, 0x72, 0x6b, 0x65, 0x74, 0x2e, 0x6d, 0x61, 0x73, 0x73, 0x2e, 0x50,
	0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x52, 0x09, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
	0x4b, 0x65, 0x79, 0x22, 0x4e, 0x0a, 0x16, 0x43, 0x68, 0x61, 0x6c, 0x6c, 0x65, 0x6e, 0x67, 0x65,
	0x53, 0x6f, 0x6c, 0x76, 0x65, 0x64, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x34, 0x0a,
	0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x16, 0x2e, 0x6d, 0x61, 0x72, 0x6b, 0x65, 0x74, 0x2e, 0x6d, 0x61, 0x73, 0x73, 0x2e, 0x53,
	0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74,
	0x75, 0x72, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_authentication_proto_rawDescOnce sync.Once
	file_authentication_proto_rawDescData = file_authentication_proto_rawDesc
)

func file_authentication_proto_rawDescGZIP() []byte {
	file_authentication_proto_rawDescOnce.Do(func() {
		file_authentication_proto_rawDescData = protoimpl.X.CompressGZIP(file_authentication_proto_rawDescData)
	})
	return file_authentication_proto_rawDescData
}

var file_authentication_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_authentication_proto_goTypes = []interface{}{
	(*AuthenticateRequest)(nil),    // 0: market.mass.AuthenticateRequest
	(*ChallengeSolvedRequest)(nil), // 1: market.mass.ChallengeSolvedRequest
	(*PublicKey)(nil),              // 2: market.mass.PublicKey
	(*Signature)(nil),              // 3: market.mass.Signature
}
var file_authentication_proto_depIdxs = []int32{
	2, // 0: market.mass.AuthenticateRequest.public_key:type_name -> market.mass.PublicKey
	3, // 1: market.mass.ChallengeSolvedRequest.signature:type_name -> market.mass.Signature
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_authentication_proto_init() }
func file_authentication_proto_init() {
	if File_authentication_proto != nil {
		return
	}
	file_base_types_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_authentication_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AuthenticateRequest); i {
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
		file_authentication_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ChallengeSolvedRequest); i {
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
			RawDescriptor: file_authentication_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_authentication_proto_goTypes,
		DependencyIndexes: file_authentication_proto_depIdxs,
		MessageInfos:      file_authentication_proto_msgTypes,
	}.Build()
	File_authentication_proto = out.File
	file_authentication_proto_rawDesc = nil
	file_authentication_proto_goTypes = nil
	file_authentication_proto_depIdxs = nil
}
