package vinvalidator

import (
	"context"
	"fmt"

	ddgrpc "github.com/DIMO-Network/device-definitions-api/pkg/grpc"
)

type InvalidVINErr string

func (i InvalidVINErr) Error() string {
	return fmt.Sprintf("invalid VIN %s", string(i))
}

type Service struct {
	grpcClient ddgrpc.VinDecoderServiceClient
}

func New(client ddgrpc.VinDecoderServiceClient) *Service {
	return &Service{
		grpcClient: client,
	}
}

// DecodeVIN decodes the provided VIN and returns the associated name slug.
func (s *Service) DecodeVIN(ctx context.Context, vin, countryCode string) (string, error) {
	if len(vin) != 17 {
		return "", InvalidVINErr("vin must be 17 chars")
	}

	resp, err := s.grpcClient.DecodeVin(ctx, &ddgrpc.DecodeVinRequest{
		Vin:     vin,
		Country: countryCode,
	})
	if err != nil {
		return "", fmt.Errorf("failed to decode vin %s: %w", vin, err)
	}
	return resp.GetDefinitionId(), nil
}
