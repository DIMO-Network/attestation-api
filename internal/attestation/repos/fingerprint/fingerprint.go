package fingerprint

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/DIMO-Network/attestation-api/internal/client/fetchapi"
	"github.com/DIMO-Network/attestation-api/internal/models"
	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/fetch-api/pkg/grpc"
	"github.com/DIMO-Network/model-garage/pkg/modules"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type decodeError string

var basicVINExp = regexp.MustCompile(`^[A-Z0-9]{17}$`)

func (d decodeError) Error() string {
	return fmt.Sprintf("failed to decode fingerprint message: %s", string(d))
}

// Service manages and retrieves fingerprint messages.
type Service struct {
	fetchService *fetchapi.FetchAPIService
}

// New creates a new instance of Service.
func New(fetchService *fetchapi.FetchAPIService) *Service {
	return &Service{
		fetchService: fetchService,
	}
}

// GetLatestFingerprintMessages fetches the latest fingerprint message from S3.
func (s *Service) GetLatestFingerprintMessages(ctx context.Context, vehicleDID cloudevent.ERC721DID, device models.PairedDevice) (*models.DecodedFingerprintData, error) {
	fingerprintType := cloudevent.TypeFingerprint
	opts := &grpc.SearchOptions{
		Subject:  wrapperspb.String(vehicleDID.String()),
		Producer: wrapperspb.String(device.DID.String()),
		Type:     wrapperspb.String(fingerprintType),
	}
	dataObj, err := s.fetchService.GetLatestCloudEvent(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get fingerprint message: %w", err)
	}
	msg, err := s.decodeFingerprintMessage(ctx, dataObj)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

func (s *Service) decodeFingerprintMessage(ctx context.Context, msg cloudevent.RawEvent) (*models.DecodedFingerprintData, error) {
	var vin string
	var err error
	fp, err := modules.ConvertToFingerprint(ctx, msg.Source, msg)
	if err != nil {
		return nil, fmt.Errorf("failed to convert to fingerprint: %w", err)
	}
	vin = fp.VIN

	if vin == "" {
		return nil, decodeError("missing vin")
	}
	// Minor cleaning.
	vin = strings.ToUpper(strings.ReplaceAll(vin, " ", ""))

	// We have seen crazy VINs like "\u000" before.
	if !basicVINExp.MatchString(vin) {
		return nil, decodeError("invalid vin")
	}
	return &models.DecodedFingerprintData{
		CloudEventHeader: msg.CloudEventHeader,
		VIN:              vin,
	}, nil
}
