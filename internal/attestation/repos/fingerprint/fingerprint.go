package fingerprint

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/DIMO-Network/attestation-api/internal/models"
	"github.com/DIMO-Network/model-garage/pkg/cloudevent"
	"github.com/DIMO-Network/model-garage/pkg/ruptela/fingerprint"
	"github.com/DIMO-Network/nameindexer"
	"github.com/DIMO-Network/nameindexer/pkg/clickhouse/indexrepo"
	"github.com/ethereum/go-ethereum/common"
)

type decodeError string

var (
	basicVINExp     = regexp.MustCompile(`^[A-Z0-9]{17}$`)
	macaronSource   = "macaron/fingerprint"
	autopiSource    = "aftermarket/device/fingerprint"
	syntheticSource = "synthetic/device/fingerprint"
)

func (d decodeError) Error() string {
	return fmt.Sprintf("failed to decode fingerprint message: %s", string(d))
}

// Service manages and retrieves fingerprint messages.
type Service struct {
	indexService     *indexrepo.Service
	dataType         string
	cloudEventBucket string
	ruptelaSource    common.Address

	// TODO (kevin): Remove this when ingest is updated
	bucketName string
}

// New creates a new instance of Service.
func New(chConn clickhouse.Conn, objGetter indexrepo.ObjectGetter, cloudeventBucket, legacyBucketName, fingerprintDataType string, ruptelaSource common.Address) *Service {
	return &Service{
		indexService:     indexrepo.New(chConn, objGetter),
		dataType:         fingerprintDataType,
		bucketName:       legacyBucketName,
		cloudEventBucket: cloudeventBucket,
		ruptelaSource:    ruptelaSource,
	}
}

// GetLatestFingerprintMessages fetches the latest fingerprint message from S3.
func (s *Service) GetLatestFingerprintMessages(ctx context.Context, vehicleDID cloudevent.NFTDID, device models.PairedDevice) (*models.DecodedFingerprintData, error) {
	filler := nameindexer.CloudTypeToFiller(cloudevent.TypeFingerprint)
	opts := indexrepo.CloudEventSearchOptions{
		Subject:       &vehicleDID,
		Producer:      &device.DID,
		PrimaryFiller: &filler,
	}
	dataObj, err := s.indexService.GetLatestCloudEventData(ctx, s.cloudEventBucket, opts)
	if err != nil {
		// if we can't find a fingerprint message in the new bucket, try the old bucket
		if errors.Is(err, sql.ErrNoRows) {
			return s.legacyGetLatestFingerprintMessages(ctx, device)
		}
		return nil, fmt.Errorf("failed to get vc: %w", err)
	}
	msg, err := s.decodeFingerprintMessage(dataObj.Data)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

// TODO (kevin): Remove this when ingest is updated
func (s *Service) legacyGetLatestFingerprintMessages(ctx context.Context, device models.PairedDevice) (*models.DecodedFingerprintData, error) {
	encdoedAddress := device.Address[2:]
	opts := indexrepo.SearchOptions{
		Subject:  &encdoedAddress,
		DataType: &s.dataType,
	}
	dataObj, err := s.indexService.GetLatestObject(ctx, s.bucketName, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get vc: %w", err)
	}
	msg, err := s.decodeFingerprintMessage(dataObj.Data)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

func (s *Service) decodeFingerprintMessage(data []byte) (*models.DecodedFingerprintData, error) {
	msg := cloudevent.CloudEvent[map[string]any]{}
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal fingerprint message: %w", err)
	}
	var vin string
	var err error
	switch {
	case msg.Source == autopiSource || msg.Source == syntheticSource:
		vin, err = decodeVINFromData(msg.Data)
		if err != nil {
			return nil, err
		}
	case msg.Source == macaronSource:
		if msg.Extras == nil {
			return nil, decodeError("missing data for macaron fingerprint")
		}
		base64Data, ok := msg.Extras["data_base64"].(string)
		if !ok {
			return nil, decodeError("missing data for macaron fingerprint")
		}
		vin, err = decodeVINFromBase64(base64Data)
		if err != nil {
			return nil, err
		}
	case s.ruptelaSource.Cmp(common.HexToAddress(msg.Source)) == 0:
		fpEvent, err := fingerprint.DecodeFingerprint(data)
		if err != nil {
			return nil, err
		}
		vin = fpEvent.Data.VIN
	}

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

// macronFingerPrint represents the structure of a fingerprint message from a Macron device.
type macronFingerPrint struct {
	Header    uint8
	Timestamp uint32
	Latitude  float32
	Longitude float32
	Protocol  uint8
	VIN       [17]byte
}

func decodeVINFromData(data map[string]interface{}) (string, error) {
	vinObj, ok := data["vin"]
	if !ok {
		return "", decodeError("missing vin")
	}
	vin, ok := vinObj.(string)
	if !ok {
		return "", decodeError(fmt.Sprintf("invalid vin type: %T", vinObj))
	}
	return vin, nil
}

func decodeVINFromBase64(data string) (string, error) {
	decodedBytes := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	_, err := base64.StdEncoding.Decode(decodedBytes, []byte(data))
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 data: %w", err)
	}
	// Verify the length of decodedBytes: 1 byte header, 4 bytes timestamp, 8 bytes location, 1 byte protocol, 17 bytes VIN
	if len(decodedBytes) < 31 {
		return "", decodeError("invalid data length")
	}

	macData := macronFingerPrint{}
	reader := bytes.NewReader(decodedBytes)
	err = binary.Read(reader, binary.LittleEndian, &macData)
	if err != nil {
		return "", fmt.Errorf("failed to read binary data: %w", err)
	}
	return string(macData.VIN[:]), nil
}
