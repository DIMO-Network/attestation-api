package fingerprint

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/DIMO-Network/attestation-api/internal/client/fetchapi"
	"github.com/DIMO-Network/attestation-api/internal/controllers/ctrlerrors"
	"github.com/DIMO-Network/attestation-api/internal/models"
	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/fetch-api/pkg/grpc"
	"github.com/DIMO-Network/model-garage/pkg/modules"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"

	vinutil "github.com/DIMO-Network/shared/pkg/vin"
)

type decodeError string

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
		if status.Code(err) == codes.NotFound {
			return nil, ctrlerrors.Error{
				Code:          http.StatusBadRequest,
				InternalError: err,
				ExternalMsg:   "No fingerprint message found",
			}
		}
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
		return nil, ctrlerrors.Error{
			Code:          http.StatusBadRequest,
			InternalError: err,
			ExternalMsg:   "Failed to extract VIN from vehicle payload",
		}
	}
	vin = fp.VIN

	if vin == "" {
		return nil, ctrlerrors.Error{
			Code:          http.StatusBadRequest,
			InternalError: decodeError("missing vin"),
			ExternalMsg:   "Vehicle payload was missing VIN",
		}
	}
	// Minor cleaning.
	vin = strings.ToUpper(strings.ReplaceAll(vin, " ", ""))

	// We have seen crazy VINs like "\u000" before.
	if !validateVIN(vin) {
		return nil, ctrlerrors.Error{
			Code:          http.StatusBadRequest,
			InternalError: decodeError("invalid vin " + vin),
			ExternalMsg:   fmt.Sprintf("VIN in vehicle payload failed validation rules %s", vin),
		}
	}
	return &models.DecodedFingerprintData{
		CloudEventHeader: msg.CloudEventHeader,
		VIN:              vin,
	}, nil
}

// validateVIN checks if VIN is valid as a 17 character traditional VIN or as a japanese chassis number
func validateVIN(vin string) bool {
	vinObj := vinutil.VIN(vin)

	if vinObj.IsValidVIN() {
		return true
	} else if vinObj.IsValidJapanChassis() {
		return true
	}
	return false
}
