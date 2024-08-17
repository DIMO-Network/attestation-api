package rpc

import (
	"context"

	"github.com/DIMO-Network/attestation-api/pkg/grpc"
)

type Server struct {
	ctrl VINVCService
}

type VINVCService interface {
	GetOrCreateVC(ctx context.Context, tokenID uint32, force bool) error
}

func (s *Server) BatchCreateVINVC(ctx context.Context, req *grpc.CreateVinVcRequest) (*grpc.CreateVinVcResponse, error) {
	if err := s.ctrl.GetOrCreateVC(ctx, req.TokenId, req.Force); err != nil {
		return nil, err
	}
	return &grpc.CreateVinVcResponse{}, nil
}
