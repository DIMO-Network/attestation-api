//go:generate mockgen -source=./ -destination=interfaces_mock_test.go -package=fingerprint_test
package fingerprint

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/DIMO-Network/attestation-api/internal/services/indexfile"
	"github.com/DIMO-Network/attestation-api/pkg/models"
	"github.com/DIMO-Network/nameindexer"
	"github.com/ethereum/go-ethereum/common"
)

// Service manages and retrieves fingerprint messages.
type Service struct {
	indexfile.Service
}

// New creates a new instance of Service.
func New(chConn clickhouse.Conn, objGetter indexfile.ObjectGetter, bucketName, fingerprintDataType string) *Service {
	return &Service{
		Service: *indexfile.New(chConn, objGetter, bucketName, fingerprintDataType),
	}
}

// GetLatestFingerprintMessages fetches the latest fingerprint message from S3.
func (s *Service) GetLatestFingerprintMessages(ctx context.Context, deviceAddr common.Address) (*models.FingerprintMessage, error) {
	subject := nameindexer.Subject{
		Address: &deviceAddr,
	}
	data, err := s.GetLatestData(ctx, subject)
	if err != nil {
		return nil, fmt.Errorf("failed to get vc: %w", err)
	}
	msg := models.FingerprintMessage{}
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal fingerprint message: %w", err)
	}
	return &msg, nil
}
