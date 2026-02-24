package fingerprint

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/DIMO-Network/attestation-api/internal/client/fetchapi"
	"github.com/DIMO-Network/attestation-api/internal/models"
	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/fetch-api/pkg/grpc"
	"github.com/DIMO-Network/model-garage/pkg/modules"
	"github.com/DIMO-Network/server-garage/pkg/richerrors"
	"github.com/DIMO-Network/shared/pkg/vin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
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

// GetLatestFingerprintMessages fetches the latest fingerprint message, from either TypeFingerprint events or
// status events tagged with vehicle.fingerprint (e.g. Ruptela), and returns the single latest by timestamp.
func (s *Service) GetLatestFingerprintMessages(ctx context.Context, vehicleDID cloudevent.ERC721DID, device models.PairedDevice) (*models.DecodedFingerprintData, error) {
	subject := vehicleDID.String()
	producer := device.DID.String()

	// 1) Latest TypeFingerprint event
	fingerprintType := cloudevent.TypeFingerprint
	opts := &grpc.SearchOptions{
		Subject:  wrapperspb.String(subject),
		Producer: wrapperspb.String(producer),
		Type:     wrapperspb.String(fingerprintType),
	}
	fpEvent, fpErr := s.fetchService.GetLatestCloudEvent(ctx, opts)

	// 2) Latest status event with vehicle.fingerprint tag (VIN in status payload)
	statusOpts := fetchapi.BuildAdvancedOptionsForStatusWithFingerprintTag(subject, producer)
	statusEvent, statusErr := s.fetchService.GetLatestCloudEventAdvanced(ctx, statusOpts)

	// Pick the latest by timestamp from the two (ignore NotFound for either)
	var candidates []cloudevent.RawEvent
	if fpErr == nil {
		candidates = append(candidates, cloudevent.RawEvent{CloudEventHeader: fpEvent.CloudEventHeader, Data: fpEvent.Data})
	}
	if statusErr == nil {
		candidates = append(candidates, cloudevent.RawEvent{CloudEventHeader: statusEvent.CloudEventHeader, Data: statusEvent.Data})
	}
	if len(candidates) == 0 {
		if status.Code(fpErr) == codes.NotFound && (statusErr == nil || status.Code(statusErr) == codes.NotFound) {
			return nil, richerrors.Error{
				Code:        http.StatusBadRequest,
				Err:         fpErr,
				ExternalMsg: "No fingerprint message found",
			}
		}
		err := fpErr
		if err == nil {
			err = statusErr
		}
		return nil, fmt.Errorf("failed to get fingerprint message: %w", err)
	}

	latest := candidates[0]
	for i := 1; i < len(candidates); i++ {
		if candidates[i].Time.After(latest.Time) {
			latest = candidates[i]
		}
	}

	msg, err := s.decodeFingerprintMessage(ctx, latest)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

func (s *Service) decodeFingerprintMessage(ctx context.Context, msg cloudevent.RawEvent) (*models.DecodedFingerprintData, error) {
	var vinVal string
	var err error
	fp, err := modules.ConvertToFingerprint(ctx, msg.Source, msg)
	if err != nil {
		return nil, richerrors.Error{
			Code:        http.StatusBadRequest,
			Err:         err,
			ExternalMsg: "Failed to extract VIN from vehicle payload",
		}
	}
	vinVal = fp.VIN

	if vinVal == "" {
		return nil, richerrors.Error{
			Code:        http.StatusBadRequest,
			Err:         decodeError("missing vin"),
			ExternalMsg: "Vehicle payload was missing VIN",
		}
	}
	// Minor cleaning.
	vinVal = strings.ToUpper(strings.ReplaceAll(vinVal, " ", ""))

	// We have seen crazy VINs like "\u000" before.
	if !validateVIN(vinVal) {
		return nil, richerrors.Error{
			Code:        http.StatusBadRequest,
			Err:         decodeError("invalid vin " + vinVal),
			ExternalMsg: fmt.Sprintf("VIN in vehicle payload failed validation rules %s", vinVal),
		}
	}
	return &models.DecodedFingerprintData{
		CloudEventHeader: msg.CloudEventHeader,
		VIN:              vinVal,
	}, nil
}

// validateVIN checks if VIN is valid as a 17 character traditional VIN or as a japanese chassis number
func validateVIN(vinValue string) bool {
	vinObj := vin.VIN(vinValue)

	if vinObj.IsValidVIN() {
		return true
	} else if vinObj.IsValidJapanChassis() {
		return true
	}
	return false
}
