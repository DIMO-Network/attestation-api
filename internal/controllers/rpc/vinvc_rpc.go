package rpc

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/DIMO-Network/attestation-api/internal/config"
	"github.com/DIMO-Network/attestation-api/pkg/grpc"
	"github.com/DIMO-Network/cloudevent"
	"github.com/ethereum/go-ethereum/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server implements the AttestationServiceServer interface.
type Server struct {
	grpc.UnimplementedAttestationServiceServer
	ctrl              vinCtrl
	vehicleNFTAddress common.Address
	chainID           uint64
}

// NewServer creates a new instance of the Server.
func NewServer(ctrl vinCtrl, settings *config.Settings) *Server {
	return &Server{
		ctrl:              ctrl,
		vehicleNFTAddress: settings.VehicleNFTAddress,
		chainID:           uint64(settings.DIMORegistryChainID),
	}
}

type vinCtrl interface {
	CreateAndStoreVINAttestation(ctx context.Context, tokenID uint32) (*cloudevent.RawEvent, error)
	CreateVINAttestation(ctx context.Context, tokenID uint32) (*cloudevent.RawEvent, error)
	CreateManualVINAttestation(ctx context.Context, tokenID uint32, vin string, countryCode string) (*cloudevent.RawEvent, error)
}

// EnsureVinVc ensures that a VC exists for the given token ID.
func (s *Server) EnsureVinVc(ctx context.Context, req *grpc.EnsureVinVcRequest) (*grpc.EnsureVinVcResponse, error) {
	rawVC, err := s.ctrl.CreateVINAttestation(ctx, req.GetTokenId())
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(rawVC)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal VIN VC: %w", err)
	}
	return &grpc.EnsureVinVcResponse{
		RawVc: string(raw),
	}, nil
}

func (s *Server) GetVinVcLatest(ctx context.Context, req *grpc.GetLatestVinVcRequest) (*grpc.GetLatestVinVcResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method has been removed, use fetch api instead")
}

// TestVinVcCreation generates a VIN VC for the given token ID.
func (s *Server) TestVinVcCreation(ctx context.Context, req *grpc.TestVinVcCreationRequest) (*grpc.TestVinVcCreationResponse, error) {
	rawVC, err := s.ctrl.CreateVINAttestation(ctx, req.GetTokenId())
	if err != nil {
		return nil, fmt.Errorf("failed to generate VIN VC: %w", err)
	}
	raw, err := json.Marshal(rawVC)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal VIN VC: %w", err)
	}
	return &grpc.TestVinVcCreationResponse{
		RawVc: string(raw),
	}, nil
}

// ManualVinVcCreation generates a VIN VC for the given token ID.
func (s *Server) ManualVinVcCreation(ctx context.Context, req *grpc.ManualVinVcCreationRequest) (*grpc.ManualVinVcCreationResponse, error) {
	rawVC, err := s.ctrl.CreateManualVINAttestation(ctx, req.GetTokenId(), req.GetVin(), req.GetCountryCode())
	if err != nil {
		return nil, fmt.Errorf("failed to generate VIN VC: %w", err)
	}
	raw, err := json.Marshal(rawVC)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal VIN VC: %w", err)
	}
	return &grpc.ManualVinVcCreationResponse{
		RawVc: string(raw),
	}, nil
}
