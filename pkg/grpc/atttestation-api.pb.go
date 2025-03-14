// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.5
// 	protoc        v5.28.3
// source: pkg/grpc/atttestation-api.proto

package grpc

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type EnsureVinVcRequest struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// The token Id of the VC to ensure.
	TokenId uint32 `protobuf:"varint,1,opt,name=token_id,json=tokenId,proto3" json:"token_id,omitempty"`
	// If true, the VC will be created even if it already exists.
	Force bool `protobuf:"varint,2,opt,name=force,proto3" json:"force,omitempty"`
	// The recorded at time of the VIN VC must be before this time.
	Before        *timestamppb.Timestamp `protobuf:"bytes,3,opt,name=before,proto3" json:"before,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *EnsureVinVcRequest) Reset() {
	*x = EnsureVinVcRequest{}
	mi := &file_pkg_grpc_atttestation_api_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *EnsureVinVcRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EnsureVinVcRequest) ProtoMessage() {}

func (x *EnsureVinVcRequest) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_grpc_atttestation_api_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EnsureVinVcRequest.ProtoReflect.Descriptor instead.
func (*EnsureVinVcRequest) Descriptor() ([]byte, []int) {
	return file_pkg_grpc_atttestation_api_proto_rawDescGZIP(), []int{0}
}

func (x *EnsureVinVcRequest) GetTokenId() uint32 {
	if x != nil {
		return x.TokenId
	}
	return 0
}

func (x *EnsureVinVcRequest) GetForce() bool {
	if x != nil {
		return x.Force
	}
	return false
}

func (x *EnsureVinVcRequest) GetBefore() *timestamppb.Timestamp {
	if x != nil {
		return x.Before
	}
	return nil
}

type EnsureVinVcResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	RawVc         string                 `protobuf:"bytes,1,opt,name=raw_vc,json=rawVc,proto3" json:"raw_vc,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *EnsureVinVcResponse) Reset() {
	*x = EnsureVinVcResponse{}
	mi := &file_pkg_grpc_atttestation_api_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *EnsureVinVcResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EnsureVinVcResponse) ProtoMessage() {}

func (x *EnsureVinVcResponse) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_grpc_atttestation_api_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EnsureVinVcResponse.ProtoReflect.Descriptor instead.
func (*EnsureVinVcResponse) Descriptor() ([]byte, []int) {
	return file_pkg_grpc_atttestation_api_proto_rawDescGZIP(), []int{1}
}

func (x *EnsureVinVcResponse) GetRawVc() string {
	if x != nil {
		return x.RawVc
	}
	return ""
}

type GetLatestVinVcRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	TokenId       uint32                 `protobuf:"varint,1,opt,name=token_id,json=tokenId,proto3" json:"token_id,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *GetLatestVinVcRequest) Reset() {
	*x = GetLatestVinVcRequest{}
	mi := &file_pkg_grpc_atttestation_api_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetLatestVinVcRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetLatestVinVcRequest) ProtoMessage() {}

func (x *GetLatestVinVcRequest) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_grpc_atttestation_api_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetLatestVinVcRequest.ProtoReflect.Descriptor instead.
func (*GetLatestVinVcRequest) Descriptor() ([]byte, []int) {
	return file_pkg_grpc_atttestation_api_proto_rawDescGZIP(), []int{2}
}

func (x *GetLatestVinVcRequest) GetTokenId() uint32 {
	if x != nil {
		return x.TokenId
	}
	return 0
}

type GetLatestVinVcResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	RawVc         string                 `protobuf:"bytes,1,opt,name=raw_vc,json=rawVc,proto3" json:"raw_vc,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *GetLatestVinVcResponse) Reset() {
	*x = GetLatestVinVcResponse{}
	mi := &file_pkg_grpc_atttestation_api_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetLatestVinVcResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetLatestVinVcResponse) ProtoMessage() {}

func (x *GetLatestVinVcResponse) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_grpc_atttestation_api_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetLatestVinVcResponse.ProtoReflect.Descriptor instead.
func (*GetLatestVinVcResponse) Descriptor() ([]byte, []int) {
	return file_pkg_grpc_atttestation_api_proto_rawDescGZIP(), []int{3}
}

func (x *GetLatestVinVcResponse) GetRawVc() string {
	if x != nil {
		return x.RawVc
	}
	return ""
}

type TestVinVcCreationRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	TokenId       uint32                 `protobuf:"varint,1,opt,name=token_id,json=tokenId,proto3" json:"token_id,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *TestVinVcCreationRequest) Reset() {
	*x = TestVinVcCreationRequest{}
	mi := &file_pkg_grpc_atttestation_api_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *TestVinVcCreationRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TestVinVcCreationRequest) ProtoMessage() {}

func (x *TestVinVcCreationRequest) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_grpc_atttestation_api_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TestVinVcCreationRequest.ProtoReflect.Descriptor instead.
func (*TestVinVcCreationRequest) Descriptor() ([]byte, []int) {
	return file_pkg_grpc_atttestation_api_proto_rawDescGZIP(), []int{4}
}

func (x *TestVinVcCreationRequest) GetTokenId() uint32 {
	if x != nil {
		return x.TokenId
	}
	return 0
}

type TestVinVcCreationResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	RawVc         string                 `protobuf:"bytes,1,opt,name=raw_vc,json=rawVc,proto3" json:"raw_vc,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *TestVinVcCreationResponse) Reset() {
	*x = TestVinVcCreationResponse{}
	mi := &file_pkg_grpc_atttestation_api_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *TestVinVcCreationResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TestVinVcCreationResponse) ProtoMessage() {}

func (x *TestVinVcCreationResponse) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_grpc_atttestation_api_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TestVinVcCreationResponse.ProtoReflect.Descriptor instead.
func (*TestVinVcCreationResponse) Descriptor() ([]byte, []int) {
	return file_pkg_grpc_atttestation_api_proto_rawDescGZIP(), []int{5}
}

func (x *TestVinVcCreationResponse) GetRawVc() string {
	if x != nil {
		return x.RawVc
	}
	return ""
}

type ManualVinVcCreationRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	TokenId       uint32                 `protobuf:"varint,1,opt,name=token_id,json=tokenId,proto3" json:"token_id,omitempty"`
	Vin           string                 `protobuf:"bytes,2,opt,name=vin,proto3" json:"vin,omitempty"`
	CountryCode   string                 `protobuf:"bytes,3,opt,name=country_code,json=countryCode,proto3" json:"country_code,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ManualVinVcCreationRequest) Reset() {
	*x = ManualVinVcCreationRequest{}
	mi := &file_pkg_grpc_atttestation_api_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ManualVinVcCreationRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ManualVinVcCreationRequest) ProtoMessage() {}

func (x *ManualVinVcCreationRequest) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_grpc_atttestation_api_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ManualVinVcCreationRequest.ProtoReflect.Descriptor instead.
func (*ManualVinVcCreationRequest) Descriptor() ([]byte, []int) {
	return file_pkg_grpc_atttestation_api_proto_rawDescGZIP(), []int{6}
}

func (x *ManualVinVcCreationRequest) GetTokenId() uint32 {
	if x != nil {
		return x.TokenId
	}
	return 0
}

func (x *ManualVinVcCreationRequest) GetVin() string {
	if x != nil {
		return x.Vin
	}
	return ""
}

func (x *ManualVinVcCreationRequest) GetCountryCode() string {
	if x != nil {
		return x.CountryCode
	}
	return ""
}

type ManualVinVcCreationResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	RawVc         string                 `protobuf:"bytes,1,opt,name=raw_vc,json=rawVc,proto3" json:"raw_vc,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ManualVinVcCreationResponse) Reset() {
	*x = ManualVinVcCreationResponse{}
	mi := &file_pkg_grpc_atttestation_api_proto_msgTypes[7]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ManualVinVcCreationResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ManualVinVcCreationResponse) ProtoMessage() {}

func (x *ManualVinVcCreationResponse) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_grpc_atttestation_api_proto_msgTypes[7]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ManualVinVcCreationResponse.ProtoReflect.Descriptor instead.
func (*ManualVinVcCreationResponse) Descriptor() ([]byte, []int) {
	return file_pkg_grpc_atttestation_api_proto_rawDescGZIP(), []int{7}
}

func (x *ManualVinVcCreationResponse) GetRawVc() string {
	if x != nil {
		return x.RawVc
	}
	return ""
}

var File_pkg_grpc_atttestation_api_proto protoreflect.FileDescriptor

var file_pkg_grpc_atttestation_api_proto_rawDesc = string([]byte{
	0x0a, 0x1f, 0x70, 0x6b, 0x67, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x2f, 0x61, 0x74, 0x74, 0x74, 0x65,
	0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x61, 0x70, 0x69, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x04, 0x67, 0x72, 0x70, 0x63, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61,
	0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x79, 0x0a, 0x12, 0x45, 0x6e, 0x73, 0x75,
	0x72, 0x65, 0x56, 0x69, 0x6e, 0x56, 0x63, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x19,
	0x0a, 0x08, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x07, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x49, 0x64, 0x12, 0x14, 0x0a, 0x05, 0x66, 0x6f, 0x72,
	0x63, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x05, 0x66, 0x6f, 0x72, 0x63, 0x65, 0x12,
	0x32, 0x0a, 0x06, 0x62, 0x65, 0x66, 0x6f, 0x72, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x06, 0x62, 0x65, 0x66,
	0x6f, 0x72, 0x65, 0x22, 0x2c, 0x0a, 0x13, 0x45, 0x6e, 0x73, 0x75, 0x72, 0x65, 0x56, 0x69, 0x6e,
	0x56, 0x63, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x15, 0x0a, 0x06, 0x72, 0x61,
	0x77, 0x5f, 0x76, 0x63, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x72, 0x61, 0x77, 0x56,
	0x63, 0x22, 0x32, 0x0a, 0x15, 0x47, 0x65, 0x74, 0x4c, 0x61, 0x74, 0x65, 0x73, 0x74, 0x56, 0x69,
	0x6e, 0x56, 0x63, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x19, 0x0a, 0x08, 0x74, 0x6f,
	0x6b, 0x65, 0x6e, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x74, 0x6f,
	0x6b, 0x65, 0x6e, 0x49, 0x64, 0x22, 0x2f, 0x0a, 0x16, 0x47, 0x65, 0x74, 0x4c, 0x61, 0x74, 0x65,
	0x73, 0x74, 0x56, 0x69, 0x6e, 0x56, 0x63, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12,
	0x15, 0x0a, 0x06, 0x72, 0x61, 0x77, 0x5f, 0x76, 0x63, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x05, 0x72, 0x61, 0x77, 0x56, 0x63, 0x22, 0x35, 0x0a, 0x18, 0x54, 0x65, 0x73, 0x74, 0x56, 0x69,
	0x6e, 0x56, 0x63, 0x43, 0x72, 0x65, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x12, 0x19, 0x0a, 0x08, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x5f, 0x69, 0x64, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x49, 0x64, 0x22, 0x32, 0x0a,
	0x19, 0x54, 0x65, 0x73, 0x74, 0x56, 0x69, 0x6e, 0x56, 0x63, 0x43, 0x72, 0x65, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x15, 0x0a, 0x06, 0x72, 0x61,
	0x77, 0x5f, 0x76, 0x63, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x72, 0x61, 0x77, 0x56,
	0x63, 0x22, 0x6c, 0x0a, 0x1a, 0x4d, 0x61, 0x6e, 0x75, 0x61, 0x6c, 0x56, 0x69, 0x6e, 0x56, 0x63,
	0x43, 0x72, 0x65, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12,
	0x19, 0x0a, 0x08, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x07, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x49, 0x64, 0x12, 0x10, 0x0a, 0x03, 0x76, 0x69,
	0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x76, 0x69, 0x6e, 0x12, 0x21, 0x0a, 0x0c,
	0x63, 0x6f, 0x75, 0x6e, 0x74, 0x72, 0x79, 0x5f, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x0b, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x72, 0x79, 0x43, 0x6f, 0x64, 0x65, 0x22,
	0x34, 0x0a, 0x1b, 0x4d, 0x61, 0x6e, 0x75, 0x61, 0x6c, 0x56, 0x69, 0x6e, 0x56, 0x63, 0x43, 0x72,
	0x65, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x15,
	0x0a, 0x06, 0x72, 0x61, 0x77, 0x5f, 0x76, 0x63, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05,
	0x72, 0x61, 0x77, 0x56, 0x63, 0x32, 0xd7, 0x02, 0x0a, 0x12, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x42, 0x0a, 0x0b,
	0x45, 0x6e, 0x73, 0x75, 0x72, 0x65, 0x56, 0x69, 0x6e, 0x56, 0x63, 0x12, 0x18, 0x2e, 0x67, 0x72,
	0x70, 0x63, 0x2e, 0x45, 0x6e, 0x73, 0x75, 0x72, 0x65, 0x56, 0x69, 0x6e, 0x56, 0x63, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x19, 0x2e, 0x67, 0x72, 0x70, 0x63, 0x2e, 0x45, 0x6e, 0x73,
	0x75, 0x72, 0x65, 0x56, 0x69, 0x6e, 0x56, 0x63, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x4b, 0x0a, 0x0e, 0x47, 0x65, 0x74, 0x56, 0x69, 0x6e, 0x56, 0x63, 0x4c, 0x61, 0x74, 0x65,
	0x73, 0x74, 0x12, 0x1b, 0x2e, 0x67, 0x72, 0x70, 0x63, 0x2e, 0x47, 0x65, 0x74, 0x4c, 0x61, 0x74,
	0x65, 0x73, 0x74, 0x56, 0x69, 0x6e, 0x56, 0x63, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a,
	0x1c, 0x2e, 0x67, 0x72, 0x70, 0x63, 0x2e, 0x47, 0x65, 0x74, 0x4c, 0x61, 0x74, 0x65, 0x73, 0x74,
	0x56, 0x69, 0x6e, 0x56, 0x63, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x54, 0x0a,
	0x11, 0x54, 0x65, 0x73, 0x74, 0x56, 0x69, 0x6e, 0x56, 0x63, 0x43, 0x72, 0x65, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x12, 0x1e, 0x2e, 0x67, 0x72, 0x70, 0x63, 0x2e, 0x54, 0x65, 0x73, 0x74, 0x56, 0x69,
	0x6e, 0x56, 0x63, 0x43, 0x72, 0x65, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x1a, 0x1f, 0x2e, 0x67, 0x72, 0x70, 0x63, 0x2e, 0x54, 0x65, 0x73, 0x74, 0x56, 0x69,
	0x6e, 0x56, 0x63, 0x43, 0x72, 0x65, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x12, 0x5a, 0x0a, 0x13, 0x4d, 0x61, 0x6e, 0x75, 0x61, 0x6c, 0x56, 0x69, 0x6e,
	0x56, 0x63, 0x43, 0x72, 0x65, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x20, 0x2e, 0x67, 0x72, 0x70,
	0x63, 0x2e, 0x4d, 0x61, 0x6e, 0x75, 0x61, 0x6c, 0x56, 0x69, 0x6e, 0x56, 0x63, 0x43, 0x72, 0x65,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x21, 0x2e, 0x67,
	0x72, 0x70, 0x63, 0x2e, 0x4d, 0x61, 0x6e, 0x75, 0x61, 0x6c, 0x56, 0x69, 0x6e, 0x56, 0x63, 0x43,
	0x72, 0x65, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x42,
	0x32, 0x5a, 0x30, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x44, 0x49,
	0x4d, 0x4f, 0x2d, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2f, 0x61, 0x74, 0x74, 0x65, 0x73,
	0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x61, 0x70, 0x69, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x67,
	0x72, 0x70, 0x63, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
})

var (
	file_pkg_grpc_atttestation_api_proto_rawDescOnce sync.Once
	file_pkg_grpc_atttestation_api_proto_rawDescData []byte
)

func file_pkg_grpc_atttestation_api_proto_rawDescGZIP() []byte {
	file_pkg_grpc_atttestation_api_proto_rawDescOnce.Do(func() {
		file_pkg_grpc_atttestation_api_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_pkg_grpc_atttestation_api_proto_rawDesc), len(file_pkg_grpc_atttestation_api_proto_rawDesc)))
	})
	return file_pkg_grpc_atttestation_api_proto_rawDescData
}

var file_pkg_grpc_atttestation_api_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_pkg_grpc_atttestation_api_proto_goTypes = []any{
	(*EnsureVinVcRequest)(nil),          // 0: grpc.EnsureVinVcRequest
	(*EnsureVinVcResponse)(nil),         // 1: grpc.EnsureVinVcResponse
	(*GetLatestVinVcRequest)(nil),       // 2: grpc.GetLatestVinVcRequest
	(*GetLatestVinVcResponse)(nil),      // 3: grpc.GetLatestVinVcResponse
	(*TestVinVcCreationRequest)(nil),    // 4: grpc.TestVinVcCreationRequest
	(*TestVinVcCreationResponse)(nil),   // 5: grpc.TestVinVcCreationResponse
	(*ManualVinVcCreationRequest)(nil),  // 6: grpc.ManualVinVcCreationRequest
	(*ManualVinVcCreationResponse)(nil), // 7: grpc.ManualVinVcCreationResponse
	(*timestamppb.Timestamp)(nil),       // 8: google.protobuf.Timestamp
}
var file_pkg_grpc_atttestation_api_proto_depIdxs = []int32{
	8, // 0: grpc.EnsureVinVcRequest.before:type_name -> google.protobuf.Timestamp
	0, // 1: grpc.AttestationService.EnsureVinVc:input_type -> grpc.EnsureVinVcRequest
	2, // 2: grpc.AttestationService.GetVinVcLatest:input_type -> grpc.GetLatestVinVcRequest
	4, // 3: grpc.AttestationService.TestVinVcCreation:input_type -> grpc.TestVinVcCreationRequest
	6, // 4: grpc.AttestationService.ManualVinVcCreation:input_type -> grpc.ManualVinVcCreationRequest
	1, // 5: grpc.AttestationService.EnsureVinVc:output_type -> grpc.EnsureVinVcResponse
	3, // 6: grpc.AttestationService.GetVinVcLatest:output_type -> grpc.GetLatestVinVcResponse
	5, // 7: grpc.AttestationService.TestVinVcCreation:output_type -> grpc.TestVinVcCreationResponse
	7, // 8: grpc.AttestationService.ManualVinVcCreation:output_type -> grpc.ManualVinVcCreationResponse
	5, // [5:9] is the sub-list for method output_type
	1, // [1:5] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_pkg_grpc_atttestation_api_proto_init() }
func file_pkg_grpc_atttestation_api_proto_init() {
	if File_pkg_grpc_atttestation_api_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_pkg_grpc_atttestation_api_proto_rawDesc), len(file_pkg_grpc_atttestation_api_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_pkg_grpc_atttestation_api_proto_goTypes,
		DependencyIndexes: file_pkg_grpc_atttestation_api_proto_depIdxs,
		MessageInfos:      file_pkg_grpc_atttestation_api_proto_msgTypes,
	}.Build()
	File_pkg_grpc_atttestation_api_proto = out.File
	file_pkg_grpc_atttestation_api_proto_goTypes = nil
	file_pkg_grpc_atttestation_api_proto_depIdxs = nil
}
