package rpc

import (
	"context"
	"encoding/json"

	"github.com/DIMO-Network/attestation-api/pkg/grpc"
	"github.com/DIMO-Network/attestation-api/pkg/verifiable"
)

type Server struct {
	ctrl vinCtrl
}

type vinCtrl interface {
	GetOrCreateVCReturning(ctx context.Context, tokenID uint32, force bool) (*verifiable.Credential, error)
}

func (s *Server) CreateVINVC(ctx context.Context, req *grpc.CreateVinVcRequest) (*grpc.CreateVinVcResponse, error) {
	vc, err := s.ctrl.GetOrCreateVCReturning(ctx, req.TokenId, req.Force)
	if err != nil {
		return nil, err
	}
	vcBits, err := json.Marshal(vc)
	if err != nil {
		return nil, err
	}
	return &grpc.CreateVinVcResponse{RawVc: string(vcBits)}, nil
}
