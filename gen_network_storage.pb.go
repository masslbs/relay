// Generated from /nix/store/71rh2ghi6lii0mrz8mbw6b6fwal8v5yn-source/network-schema/storage.proto at version v3 (9d18c2fd2a1a0367d1ab833ad0d759a4b65c0047)

// SPDX-FileCopyrightText: 2024 - 2025 Mass Labs
//
// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-License-Identifier: MIT

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.35.1
// 	protoc        v5.28.3
// source: storage.proto

package main

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Order can be used to represent current state of an order.
// This is not transmitted over the event stream directly.
type Order struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id    *ObjectId      `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Items []*OrderedItem `protobuf:"bytes,2,rep,name=items,proto3" json:"items,omitempty"`
	// can be used for note keeping like delivery statuses and tracking codes
	ShippingStatus string                 `protobuf:"bytes,3,opt,name=shipping_status,json=shippingStatus,proto3" json:"shipping_status,omitempty"`
	CanceledAt     *timestamppb.Timestamp `protobuf:"bytes,4,opt,name=canceled_at,json=canceledAt,proto3,oneof" json:"canceled_at,omitempty"`
	CommitedAt     *timestamppb.Timestamp `protobuf:"bytes,5,opt,name=commited_at,json=commitedAt,proto3,oneof" json:"commited_at,omitempty"`
	InvoiceAddress *AddressDetails        `protobuf:"bytes,6,opt,name=invoice_address,json=invoiceAddress,proto3,oneof" json:"invoice_address,omitempty"`
	// no shipping addr assumes invoice addr
	ShippingAddress  *AddressDetails        `protobuf:"bytes,7,opt,name=shipping_address,json=shippingAddress,proto3,oneof" json:"shipping_address,omitempty"`
	AddressUpdatedAt *timestamppb.Timestamp `protobuf:"bytes,8,opt,name=address_updated_at,json=addressUpdatedAt,proto3,oneof" json:"address_updated_at,omitempty"`
	// mandatory if state was commited
	ChosenPayee             *Payee                 `protobuf:"bytes,9,opt,name=chosen_payee,json=chosenPayee,proto3,oneof" json:"chosen_payee,omitempty"`
	ChosenCurrency          *ShopCurrency          `protobuf:"bytes,10,opt,name=chosen_currency,json=chosenCurrency,proto3,oneof" json:"chosen_currency,omitempty"`
	PaymentDetails          *PaymentDetails        `protobuf:"bytes,11,opt,name=payment_details,json=paymentDetails,proto3,oneof" json:"payment_details,omitempty"`
	PaymentDetailsCreatedAt *timestamppb.Timestamp `protobuf:"bytes,12,opt,name=payment_details_created_at,json=paymentDetailsCreatedAt,proto3,oneof" json:"payment_details_created_at,omitempty"`
	PaymentTransactions     []*OrderTransaction    `protobuf:"bytes,13,rep,name=payment_transactions,json=paymentTransactions,proto3" json:"payment_transactions,omitempty"`
}

func (x *Order) Reset() {
	*x = Order{}
	mi := &file_storage_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Order) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Order) ProtoMessage() {}

func (x *Order) ProtoReflect() protoreflect.Message {
	mi := &file_storage_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Order.ProtoReflect.Descriptor instead.
func (*Order) Descriptor() ([]byte, []int) {
	return file_storage_proto_rawDescGZIP(), []int{0}
}

func (x *Order) GetId() *ObjectId {
	if x != nil {
		return x.Id
	}
	return nil
}

func (x *Order) GetItems() []*OrderedItem {
	if x != nil {
		return x.Items
	}
	return nil
}

func (x *Order) GetShippingStatus() string {
	if x != nil {
		return x.ShippingStatus
	}
	return ""
}

func (x *Order) GetCanceledAt() *timestamppb.Timestamp {
	if x != nil {
		return x.CanceledAt
	}
	return nil
}

func (x *Order) GetCommitedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.CommitedAt
	}
	return nil
}

func (x *Order) GetInvoiceAddress() *AddressDetails {
	if x != nil {
		return x.InvoiceAddress
	}
	return nil
}

func (x *Order) GetShippingAddress() *AddressDetails {
	if x != nil {
		return x.ShippingAddress
	}
	return nil
}

func (x *Order) GetAddressUpdatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.AddressUpdatedAt
	}
	return nil
}

func (x *Order) GetChosenPayee() *Payee {
	if x != nil {
		return x.ChosenPayee
	}
	return nil
}

func (x *Order) GetChosenCurrency() *ShopCurrency {
	if x != nil {
		return x.ChosenCurrency
	}
	return nil
}

func (x *Order) GetPaymentDetails() *PaymentDetails {
	if x != nil {
		return x.PaymentDetails
	}
	return nil
}

func (x *Order) GetPaymentDetailsCreatedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.PaymentDetailsCreatedAt
	}
	return nil
}

func (x *Order) GetPaymentTransactions() []*OrderTransaction {
	if x != nil {
		return x.PaymentTransactions
	}
	return nil
}

var File_storage_proto protoreflect.FileDescriptor

var file_storage_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x0b, 0x6d, 0x61, 0x72, 0x6b, 0x65, 0x74, 0x2e, 0x6d, 0x61, 0x73, 0x73, 0x1a, 0x10, 0x62, 0x61,
	0x73, 0x65, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f,
	0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0xaa, 0x08, 0x0a, 0x05, 0x4f, 0x72, 0x64, 0x65, 0x72, 0x12, 0x25, 0x0a, 0x02, 0x69, 0x64, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x15, 0x2e, 0x6d, 0x61, 0x72, 0x6b, 0x65, 0x74, 0x2e, 0x6d,
	0x61, 0x73, 0x73, 0x2e, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x49, 0x64, 0x52, 0x02, 0x69, 0x64,
	0x12, 0x2e, 0x0a, 0x05, 0x69, 0x74, 0x65, 0x6d, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32,
	0x18, 0x2e, 0x6d, 0x61, 0x72, 0x6b, 0x65, 0x74, 0x2e, 0x6d, 0x61, 0x73, 0x73, 0x2e, 0x4f, 0x72,
	0x64, 0x65, 0x72, 0x65, 0x64, 0x49, 0x74, 0x65, 0x6d, 0x52, 0x05, 0x69, 0x74, 0x65, 0x6d, 0x73,
	0x12, 0x27, 0x0a, 0x0f, 0x73, 0x68, 0x69, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x5f, 0x73, 0x74, 0x61,
	0x74, 0x75, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e, 0x73, 0x68, 0x69, 0x70, 0x70,
	0x69, 0x6e, 0x67, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x40, 0x0a, 0x0b, 0x63, 0x61, 0x6e,
	0x63, 0x65, 0x6c, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x48, 0x00, 0x52, 0x0a, 0x63, 0x61,
	0x6e, 0x63, 0x65, 0x6c, 0x65, 0x64, 0x41, 0x74, 0x88, 0x01, 0x01, 0x12, 0x40, 0x0a, 0x0b, 0x63,
	0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x48, 0x01, 0x52, 0x0a,
	0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x65, 0x64, 0x41, 0x74, 0x88, 0x01, 0x01, 0x12, 0x49, 0x0a,
	0x0f, 0x69, 0x6e, 0x76, 0x6f, 0x69, 0x63, 0x65, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73,
	0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1b, 0x2e, 0x6d, 0x61, 0x72, 0x6b, 0x65, 0x74, 0x2e,
	0x6d, 0x61, 0x73, 0x73, 0x2e, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x44, 0x65, 0x74, 0x61,
	0x69, 0x6c, 0x73, 0x48, 0x02, 0x52, 0x0e, 0x69, 0x6e, 0x76, 0x6f, 0x69, 0x63, 0x65, 0x41, 0x64,
	0x64, 0x72, 0x65, 0x73, 0x73, 0x88, 0x01, 0x01, 0x12, 0x4b, 0x0a, 0x10, 0x73, 0x68, 0x69, 0x70,
	0x70, 0x69, 0x6e, 0x67, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x07, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x1b, 0x2e, 0x6d, 0x61, 0x72, 0x6b, 0x65, 0x74, 0x2e, 0x6d, 0x61, 0x73, 0x73,
	0x2e, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x48,
	0x03, 0x52, 0x0f, 0x73, 0x68, 0x69, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x41, 0x64, 0x64, 0x72, 0x65,
	0x73, 0x73, 0x88, 0x01, 0x01, 0x12, 0x4d, 0x0a, 0x12, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73,
	0x5f, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18, 0x08, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x48, 0x04, 0x52,
	0x10, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x64, 0x41,
	0x74, 0x88, 0x01, 0x01, 0x12, 0x3a, 0x0a, 0x0c, 0x63, 0x68, 0x6f, 0x73, 0x65, 0x6e, 0x5f, 0x70,
	0x61, 0x79, 0x65, 0x65, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x6d, 0x61, 0x72,
	0x6b, 0x65, 0x74, 0x2e, 0x6d, 0x61, 0x73, 0x73, 0x2e, 0x50, 0x61, 0x79, 0x65, 0x65, 0x48, 0x05,
	0x52, 0x0b, 0x63, 0x68, 0x6f, 0x73, 0x65, 0x6e, 0x50, 0x61, 0x79, 0x65, 0x65, 0x88, 0x01, 0x01,
	0x12, 0x47, 0x0a, 0x0f, 0x63, 0x68, 0x6f, 0x73, 0x65, 0x6e, 0x5f, 0x63, 0x75, 0x72, 0x72, 0x65,
	0x6e, 0x63, 0x79, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x6d, 0x61, 0x72, 0x6b,
	0x65, 0x74, 0x2e, 0x6d, 0x61, 0x73, 0x73, 0x2e, 0x53, 0x68, 0x6f, 0x70, 0x43, 0x75, 0x72, 0x72,
	0x65, 0x6e, 0x63, 0x79, 0x48, 0x06, 0x52, 0x0e, 0x63, 0x68, 0x6f, 0x73, 0x65, 0x6e, 0x43, 0x75,
	0x72, 0x72, 0x65, 0x6e, 0x63, 0x79, 0x88, 0x01, 0x01, 0x12, 0x49, 0x0a, 0x0f, 0x70, 0x61, 0x79,
	0x6d, 0x65, 0x6e, 0x74, 0x5f, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x18, 0x0b, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x1b, 0x2e, 0x6d, 0x61, 0x72, 0x6b, 0x65, 0x74, 0x2e, 0x6d, 0x61, 0x73, 0x73,
	0x2e, 0x50, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x48,
	0x07, 0x52, 0x0e, 0x70, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c,
	0x73, 0x88, 0x01, 0x01, 0x12, 0x5c, 0x0a, 0x1a, 0x70, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x5f,
	0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x5f, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f,
	0x61, 0x74, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73,
	0x74, 0x61, 0x6d, 0x70, 0x48, 0x08, 0x52, 0x17, 0x70, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x44,
	0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x41, 0x74, 0x88,
	0x01, 0x01, 0x12, 0x50, 0x0a, 0x14, 0x70, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x5f, 0x74, 0x72,
	0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x0d, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x1d, 0x2e, 0x6d, 0x61, 0x72, 0x6b, 0x65, 0x74, 0x2e, 0x6d, 0x61, 0x73, 0x73, 0x2e, 0x4f,
	0x72, 0x64, 0x65, 0x72, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x52,
	0x13, 0x70, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74,
	0x69, 0x6f, 0x6e, 0x73, 0x42, 0x0e, 0x0a, 0x0c, 0x5f, 0x63, 0x61, 0x6e, 0x63, 0x65, 0x6c, 0x65,
	0x64, 0x5f, 0x61, 0x74, 0x42, 0x0e, 0x0a, 0x0c, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x65,
	0x64, 0x5f, 0x61, 0x74, 0x42, 0x12, 0x0a, 0x10, 0x5f, 0x69, 0x6e, 0x76, 0x6f, 0x69, 0x63, 0x65,
	0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x42, 0x13, 0x0a, 0x11, 0x5f, 0x73, 0x68, 0x69,
	0x70, 0x70, 0x69, 0x6e, 0x67, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x42, 0x15, 0x0a,
	0x13, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x5f, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65,
	0x64, 0x5f, 0x61, 0x74, 0x42, 0x0f, 0x0a, 0x0d, 0x5f, 0x63, 0x68, 0x6f, 0x73, 0x65, 0x6e, 0x5f,
	0x70, 0x61, 0x79, 0x65, 0x65, 0x42, 0x12, 0x0a, 0x10, 0x5f, 0x63, 0x68, 0x6f, 0x73, 0x65, 0x6e,
	0x5f, 0x63, 0x75, 0x72, 0x72, 0x65, 0x6e, 0x63, 0x79, 0x42, 0x12, 0x0a, 0x10, 0x5f, 0x70, 0x61,
	0x79, 0x6d, 0x65, 0x6e, 0x74, 0x5f, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x42, 0x1d, 0x0a,
	0x1b, 0x5f, 0x70, 0x61, 0x79, 0x6d, 0x65, 0x6e, 0x74, 0x5f, 0x64, 0x65, 0x74, 0x61, 0x69, 0x6c,
	0x73, 0x5f, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_storage_proto_rawDescOnce sync.Once
	file_storage_proto_rawDescData = file_storage_proto_rawDesc
)

func file_storage_proto_rawDescGZIP() []byte {
	file_storage_proto_rawDescOnce.Do(func() {
		file_storage_proto_rawDescData = protoimpl.X.CompressGZIP(file_storage_proto_rawDescData)
	})
	return file_storage_proto_rawDescData
}

var file_storage_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_storage_proto_goTypes = []any{
	(*Order)(nil),                 // 0: market.mass.Order
	(*ObjectId)(nil),              // 1: market.mass.ObjectId
	(*OrderedItem)(nil),           // 2: market.mass.OrderedItem
	(*timestamppb.Timestamp)(nil), // 3: google.protobuf.Timestamp
	(*AddressDetails)(nil),        // 4: market.mass.AddressDetails
	(*Payee)(nil),                 // 5: market.mass.Payee
	(*ShopCurrency)(nil),          // 6: market.mass.ShopCurrency
	(*PaymentDetails)(nil),        // 7: market.mass.PaymentDetails
	(*OrderTransaction)(nil),      // 8: market.mass.OrderTransaction
}
var file_storage_proto_depIdxs = []int32{
	1,  // 0: market.mass.Order.id:type_name -> market.mass.ObjectId
	2,  // 1: market.mass.Order.items:type_name -> market.mass.OrderedItem
	3,  // 2: market.mass.Order.canceled_at:type_name -> google.protobuf.Timestamp
	3,  // 3: market.mass.Order.commited_at:type_name -> google.protobuf.Timestamp
	4,  // 4: market.mass.Order.invoice_address:type_name -> market.mass.AddressDetails
	4,  // 5: market.mass.Order.shipping_address:type_name -> market.mass.AddressDetails
	3,  // 6: market.mass.Order.address_updated_at:type_name -> google.protobuf.Timestamp
	5,  // 7: market.mass.Order.chosen_payee:type_name -> market.mass.Payee
	6,  // 8: market.mass.Order.chosen_currency:type_name -> market.mass.ShopCurrency
	7,  // 9: market.mass.Order.payment_details:type_name -> market.mass.PaymentDetails
	3,  // 10: market.mass.Order.payment_details_created_at:type_name -> google.protobuf.Timestamp
	8,  // 11: market.mass.Order.payment_transactions:type_name -> market.mass.OrderTransaction
	12, // [12:12] is the sub-list for method output_type
	12, // [12:12] is the sub-list for method input_type
	12, // [12:12] is the sub-list for extension type_name
	12, // [12:12] is the sub-list for extension extendee
	0,  // [0:12] is the sub-list for field type_name
}

func init() { file_storage_proto_init() }
func file_storage_proto_init() {
	if File_storage_proto != nil {
		return
	}
	file_base_types_proto_init()
	file_storage_proto_msgTypes[0].OneofWrappers = []any{}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_storage_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_storage_proto_goTypes,
		DependencyIndexes: file_storage_proto_depIdxs,
		MessageInfos:      file_storage_proto_msgTypes,
	}.Build()
	File_storage_proto = out.File
	file_storage_proto_rawDesc = nil
	file_storage_proto_goTypes = nil
	file_storage_proto_depIdxs = nil
}
