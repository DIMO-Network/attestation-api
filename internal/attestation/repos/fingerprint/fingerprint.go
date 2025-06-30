package fingerprint

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/DIMO-Network/attestation-api/internal/client/fetchapi"
	"github.com/DIMO-Network/attestation-api/internal/models"
	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/cloudevent/pkg/clickhouse/eventrepo"
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

	// TODO (kevin): Remove with smartcar deprecation
	bucketName   string
	indexService *eventrepo.Service
	dataType     string
}

// New creates a new instance of Service.
func New(fetchService *fetchapi.FetchAPIService, legacyBucketName, fingerprintDataType string,
	chConn clickhouse.Conn, objGetter eventrepo.ObjectGetter) *Service {
	return &Service{
		fetchService: fetchService,

		// TODO (kevin): Remove with smartcar deprecation
		indexService: eventrepo.New(chConn, objGetter),
		dataType:     fingerprintDataType,
		bucketName:   legacyBucketName,
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
		// if we can't find a fingerprint message in the new bucket, try the old bucket
		if errors.Is(err, sql.ErrNoRows) {
			return s.legacyGetLatestFingerprintMessages(ctx, device)
		}
		return nil, fmt.Errorf("failed to get fingerprint message: %w", err)
	}
	msg, err := s.decodeFingerprintMessage(dataObj)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

// TODO (kevin): Remove with smartcar deprecation
func (s *Service) legacyGetLatestFingerprintMessages(ctx context.Context, device models.PairedDevice) (*models.DecodedFingerprintData, error) {
	encodedAddress := device.Address[2:]
	opts := &eventrepo.SearchOptions{
		Subject:     &encodedAddress,
		DataVersion: &s.dataType,
	}
	cloudIdx, err := s.indexService.GetLatestIndex(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest fingerprint: %w", err)
	}
	dataObj, err := s.indexService.GetObjectFromKey(ctx, cloudIdx.Data.Key, s.bucketName)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest fingerprint object: %w", err)
	}
	embeddedEvent := cloudevent.CloudEvent[json.RawMessage]{}
	err = json.Unmarshal(dataObj, &embeddedEvent)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal legacy fingerprint message: %w", err)
	}
	msg, err := s.decodeFingerprintMessage(embeddedEvent)
	if err != nil {
		return nil, err
	}
	if msg.Producer == "" {
		msg.Producer = device.DID.String()
	}
	return msg, nil
}

func (s *Service) decodeFingerprintMessage(msg cloudevent.RawEvent) (*models.DecodedFingerprintData, error) {
	var vin string
	var err error
	fp, err := modules.ConvertToFingerprint(context.TODO(), msg.Source, msg)
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

func ref[T any](v T) *T {
	return &v
}
