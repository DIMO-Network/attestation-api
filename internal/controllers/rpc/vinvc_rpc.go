package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/DIMO-Network/attestation-api/pkg/grpc"
	"github.com/DIMO-Network/attestation-api/pkg/verifiable"
	"github.com/DIMO-Network/model-garage/pkg/cloudevent"
	"github.com/ethereum/go-ethereum/common"
)

// Server implements the AttestationServiceServer interface.
type Server struct {
	grpc.UnimplementedAttestationServiceServer
	ctrl              vinCtrl
	repo              vinRepo
	vehicleNFTAddress common.Address
	chainID           uint64
}

// NewServer creates a new instance of the Server.
func NewServer(ctrl vinCtrl, repo vinRepo, vehicleNFTAddr common.Address, chainID int64) *Server {
	return &Server{
		ctrl:              ctrl,
		repo:              repo,
		vehicleNFTAddress: vehicleNFTAddr,
		chainID:           uint64(chainID),
	}
}

type vinCtrl interface {
	GetOrCreateVC(ctx context.Context, tokenID uint32, before time.Time, force bool) (json.RawMessage, error)
	GenerateVINVC(ctx context.Context, tokenID uint32) (json.RawMessage, error)
	GenerateManualVC(ctx context.Context, tokenID uint32, vin string, countryCode string) (json.RawMessage, error)
}

type vinRepo interface {
	GetLatestVINVC(ctx context.Context, vehicleNFTDID cloudevent.NFTDID) (*verifiable.Credential, error)
}

// EnsureVinVc ensures that a VC exists for the given token ID.
func (s *Server) EnsureVinVc(ctx context.Context, req *grpc.EnsureVinVcRequest) (*grpc.EnsureVinVcResponse, error) {
	rawVC, err := s.ctrl.GetOrCreateVC(ctx, req.GetTokenId(), req.GetBefore().AsTime(), req.GetForce())
	if err != nil {
		return nil, err
	}
	return &grpc.EnsureVinVcResponse{
		RawVc: string(rawVC),
	}, nil
}

// GetVinVcLatest retrieves the latest VIN VC for the given token ID.
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

// TestVinVcCreation generates a VIN VC for the given token ID.
func (s *Server) TestVinVcCreation(ctx context.Context, req *grpc.TestVinVcCreationRequest) (*grpc.TestVinVcCreationResponse, error) {
	rawVC, err := s.ctrl.GenerateVINVC(ctx, req.GetTokenId())
	if err != nil {
		return nil, fmt.Errorf("failed to generate VIN VC: %w", err)
	}
	return &grpc.TestVinVcCreationResponse{
		RawVc: string(rawVC),
	}, nil
}

// ManualVinVcCreation generates a VIN VC for the given token ID.
func (s *Server) ManualVinVcCreation(ctx context.Context, req *grpc.ManualVinVcCreationRequest) (*grpc.ManualVinVcCreationResponse, error) {
	rawVC, err := s.ctrl.GenerateManualVC(ctx, req.GetTokenId(), req.GetVin(), req.GetCountryCode())
	if err != nil {
		return nil, fmt.Errorf("failed to generate VIN VC: %w", err)
	}
	return &grpc.ManualVinVcCreationResponse{
		RawVc: string(rawVC),
	}, nil
}
