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
	"github.com/DIMO-Network/attestation-api/internal/sources"
	"github.com/DIMO-Network/model-garage/pkg/cloudevent"
	"github.com/DIMO-Network/model-garage/pkg/ruptela/fingerprint"
	teslafp "github.com/DIMO-Network/model-garage/pkg/tesla/fingerprint"
	"github.com/DIMO-Network/nameindexer/pkg/clickhouse/indexrepo"
)

type decodeError string

var basicVINExp = regexp.MustCompile(`^[A-Z0-9]{17}$`)

func (d decodeError) Error() string {
	return fmt.Sprintf("failed to decode fingerprint message: %s", string(d))
}

// Service manages and retrieves fingerprint messages.
type Service struct {
	indexService     *indexrepo.Service
	dataType         string
	cloudEventBucket string

	// TODO (kevin): Remove this when ingest is updated
	bucketName string
}

// New creates a new instance of Service.
func New(chConn clickhouse.Conn, objGetter indexrepo.ObjectGetter, cloudeventBucket, legacyBucketName, fingerprintDataType string) *Service {
	return &Service{
		indexService:     indexrepo.New(chConn, objGetter),
		dataType:         fingerprintDataType,
		bucketName:       legacyBucketName,
		cloudEventBucket: cloudeventBucket,
	}
}

// GetLatestFingerprintMessages fetches the latest fingerprint message from S3.
func (s *Service) GetLatestFingerprintMessages(ctx context.Context, vehicleDID cloudevent.NFTDID, device models.PairedDevice) (*models.DecodedFingerprintData, error) {
	fingerprintType := cloudevent.TypeFingerprint
	opts := &indexrepo.SearchOptions{
		Subject:  ref(vehicleDID.String()),
		Producer: ref(device.DID.String()),
		Type:     &fingerprintType,
	}
	dataObj, err := s.indexService.GetLatestCloudEvent(ctx, s.cloudEventBucket, opts)
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

// TODO (kevin): Remove this when ingest is updated
func (s *Service) legacyGetLatestFingerprintMessages(ctx context.Context, device models.PairedDevice) (*models.DecodedFingerprintData, error) {
	encodedAddress := device.Address[2:]
	opts := &indexrepo.SearchOptions{
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

func (s *Service) decodeFingerprintMessage(msg cloudevent.CloudEvent[json.RawMessage]) (*models.DecodedFingerprintData, error) {
	var vin string
	var err error
	switch {
	case msg.Source == sources.SyntheticOldSource || msg.Source == sources.AutiPiOldSource || sources.AddrEqualString(sources.AutoPiSource, msg.Source):
		vin, err = decodeVINFromData(msg.Data)
		if err != nil {
			return nil, err
		}
	case msg.Source == sources.MacaronOldFpSource:
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
	case sources.AddrEqualString(sources.RuptelaSource, msg.Source):
		fullMsgData, err := json.Marshal(msg)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal fingerprint message: %w", err)
		}
		fpEvent, err := fingerprint.DecodeFingerprint(fullMsgData)
		if err != nil {
			return nil, fmt.Errorf("failed to decode fingerprint: %w", err)
		}
		vin = fpEvent.Data.VIN
	case sources.AddrEqualString(sources.TeslaSource, msg.Source):
		fpEvent, err := teslafp.DecodeFingerprintFromData(msg.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to decode fingerprint: %w", err)
		}
		vin = fpEvent.VIN
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

type basicFingerprint struct {
	VIN string `json:"vin"`
}

func decodeVINFromData(data json.RawMessage) (string, error) {
	fpData := basicFingerprint{}
	err := json.Unmarshal(data, &fpData)
	if err != nil {
		return "", fmt.Errorf("failed to autoPi unmarshal data: %w", err)
	}
	return fpData.VIN, nil
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

func ref[T any](v T) *T {
	return &v
}
