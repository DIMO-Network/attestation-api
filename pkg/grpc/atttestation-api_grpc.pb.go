// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v5.28.2
// source: pkg/grpc/atttestation-api.proto

package grpc

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	AttestationService_EnsureVinVc_FullMethodName    = "/grpc.AttestationService/EnsureVinVc"
	AttestationService_GetVinVcLatest_FullMethodName = "/grpc.AttestationService/GetVinVcLatest"
)

// AttestationServiceClient is the client API for AttestationService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type AttestationServiceClient interface {
	EnsureVinVc(ctx context.Context, in *EnsureVinVcRequest, opts ...grpc.CallOption) (*EnsureVinVcResponse, error)
	GetVinVcLatest(ctx context.Context, in *GetLatestVinVcRequest, opts ...grpc.CallOption) (*GetLatestVinVcResponse, error)
}

type attestationServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewAttestationServiceClient(cc grpc.ClientConnInterface) AttestationServiceClient {
	return &attestationServiceClient{cc}
}

func (c *attestationServiceClient) EnsureVinVc(ctx context.Context, in *EnsureVinVcRequest, opts ...grpc.CallOption) (*EnsureVinVcResponse, error) {
	out := new(EnsureVinVcResponse)
	err := c.cc.Invoke(ctx, AttestationService_EnsureVinVc_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *attestationServiceClient) GetVinVcLatest(ctx context.Context, in *GetLatestVinVcRequest, opts ...grpc.CallOption) (*GetLatestVinVcResponse, error) {
	out := new(GetLatestVinVcResponse)
	err := c.cc.Invoke(ctx, AttestationService_GetVinVcLatest_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AttestationServiceServer is the server API for AttestationService service.
// All implementations must embed UnimplementedAttestationServiceServer
// for forward compatibility
type AttestationServiceServer interface {
	EnsureVinVc(context.Context, *EnsureVinVcRequest) (*EnsureVinVcResponse, error)
	GetVinVcLatest(context.Context, *GetLatestVinVcRequest) (*GetLatestVinVcResponse, error)
	mustEmbedUnimplementedAttestationServiceServer()
}

// UnimplementedAttestationServiceServer must be embedded to have forward compatible implementations.
type UnimplementedAttestationServiceServer struct {
}

func (UnimplementedAttestationServiceServer) EnsureVinVc(context.Context, *EnsureVinVcRequest) (*EnsureVinVcResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method EnsureVinVc not implemented")
}
func (UnimplementedAttestationServiceServer) GetVinVcLatest(context.Context, *GetLatestVinVcRequest) (*GetLatestVinVcResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetVinVcLatest not implemented")
}
func (UnimplementedAttestationServiceServer) mustEmbedUnimplementedAttestationServiceServer() {}

// UnsafeAttestationServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to AttestationServiceServer will
// result in compilation errors.
type UnsafeAttestationServiceServer interface {
	mustEmbedUnimplementedAttestationServiceServer()
}

func RegisterAttestationServiceServer(s grpc.ServiceRegistrar, srv AttestationServiceServer) {
	s.RegisterService(&AttestationService_ServiceDesc, srv)
}

func _AttestationService_EnsureVinVc_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(EnsureVinVcRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AttestationServiceServer).EnsureVinVc(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AttestationService_EnsureVinVc_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AttestationServiceServer).EnsureVinVc(ctx, req.(*EnsureVinVcRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AttestationService_GetVinVcLatest_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetLatestVinVcRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AttestationServiceServer).GetVinVcLatest(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AttestationService_GetVinVcLatest_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AttestationServiceServer).GetVinVcLatest(ctx, req.(*GetLatestVinVcRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// AttestationService_ServiceDesc is the grpc.ServiceDesc for AttestationService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var AttestationService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "grpc.AttestationService",
	HandlerType: (*AttestationServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "EnsureVinVc",
			Handler:    _AttestationService_EnsureVinVc_Handler,
		},
		{
			MethodName: "GetVinVcLatest",
			Handler:    _AttestationService_GetVinVcLatest_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "pkg/grpc/atttestation-api.proto",
}
