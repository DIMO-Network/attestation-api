package rpc

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/DIMO-Network/attestation-api/pkg/grpc"
	"github.com/DIMO-Network/attestation-api/pkg/verifiable"
	"github.com/DIMO-Network/model-garage/pkg/cloudevent"
	"github.com/ethereum/go-ethereum/common"
)

type Server struct {
	grpc.UnimplementedAttestationServiceServer
	ctrl              vinCtrl
	repo              vinRepo
	vehicleNFTAddress common.Address
	chainID           uint64
}

func NewServer(ctrl vinCtrl, repo vinRepo, vehicleNFTAddr common.Address, chainID int64) *Server {
	return &Server{
		ctrl:              ctrl,
		repo:              repo,
		vehicleNFTAddress: vehicleNFTAddr,
		chainID:           uint64(chainID),
	}
}

type vinCtrl interface {
	GetOrCreateVC(ctx context.Context, tokenID uint32, force bool) error
	GenerateVINVC(ctx context.Context, tokenID uint32) (json.RawMessage, error)
}

type vinRepo interface {
	GetLatestVINVC(ctx context.Context, vehicleNFTDID cloudevent.NFTDID) (*verifiable.Credential, error)
}

func (s *Server) EnsureVinVc(ctx context.Context, req *grpc.EnsureVinVcRequest) (*grpc.EnsureVinVcResponse, error) {
	err := s.ctrl.GetOrCreateVC(ctx, req.GetTokenId(), req.GetForce())
	if err != nil {
		return nil, err
	}
	return &grpc.EnsureVinVcResponse{}, nil
}

func (s *Server) GetVinVcLatest(ctx context.Context, req *grpc.GetLatestVinVcRequest) (*grpc.GetLatestVinVcResponse, error) {
	vehicleDID := cloudevent.NFTDID{
		ChainID:         s.chainID,
		ContractAddress: s.vehicleNFTAddress,
		TokenID:         req.GetTokenId(),
	}
	cred, err := s.repo.GetLatestVINVC(ctx, vehicleDID)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest VIN VC: %w", err)
	}

	raw, err := json.Marshal(cred)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal VIN VC: %w", err)
	}

	return &grpc.GetLatestVinVcResponse{RawVc: string(raw)}, nil
}

func (s Server) TestVinVcCreation(ctx context.Context, req *grpc.TestVinVcCreationRequest) (*grpc.TestVinVcCreationResponse, error) {
	_, err := s.ctrl.GenerateVINVC(ctx, req.GetTokenId())
	if err != nil {
		return nil, fmt.Errorf("failed to generate VIN VC: %w", err)
	}
	return &grpc.TestVinVcCreationResponse{}, nil
}
