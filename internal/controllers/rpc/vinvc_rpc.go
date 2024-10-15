package rpc

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/DIMO-Network/attestation-api/pkg/grpc"
	"github.com/DIMO-Network/attestation-api/pkg/verifiable"
)

type Server struct {
	ctrl vinCtrl
	repo vinRepo
}

type vinCtrl interface {
	GetOrCreateVC(ctx context.Context, tokenID uint32, force bool) error
}

type vinRepo interface {
	GetLatestVINVC(ctx context.Context, vehicleTokenID uint32) (*verifiable.Credential, error)
}

func (s *Server) EnsureVinVc(ctx context.Context, req *grpc.EnsureVinVcRequest) (*grpc.EnsureVinVcResponse, error) {
	err := s.ctrl.GetOrCreateVC(ctx, req.TokenId, req.Force)
	if err != nil {
		return nil, err
	}
	return &grpc.EnsureVinVcResponse{}, nil
}

func (s *Server) GetVinVcLatest(ctx context.Context, req *grpc.GetLatestVinVcRequest) (*grpc.GetLatestVinVcResponse, error) {
	cred, err := s.repo.GetLatestVINVC(ctx, req.TokenId)
	if err != nil {
		return nil, err
	}

	raw, err := json.Marshal(cred)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal VIN VC: %w", err)
	}

	return &grpc.GetLatestVinVcResponse{RawVc: string(raw)}, nil
}
