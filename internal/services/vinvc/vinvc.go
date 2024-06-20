package vinvc

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/DIMO-Network/attestation-api/internal/services/indexfile"
	"github.com/DIMO-Network/attestation-api/pkg/models"
	"github.com/DIMO-Network/attestation-api/pkg/verfiable"
	"github.com/DIMO-Network/nameindexer"
)

// Service manages and retrieves fingerprint messages.
type Service struct {
	indexfile.Service
	issuer *verfiable.Issuer
}

// New creates a new instance of Service.
func New(chConn clickhouse.Conn, objGetter indexfile.ObjectGetter, issuer *verfiable.Issuer, bucketName, vinvcDataType string) *Service {
	return &Service{
		Service: *indexfile.New(chConn, objGetter, bucketName, vinvcDataType),
		issuer:  issuer,
	}
}

// GetLatestVC fetches the latest fingerprint message from S3.
func (s *Service) GetLatestVC(ctx context.Context, vehicleTokenId uint32) (*models.VINVC, error) {
	subject := nameindexer.Subject{
		TokenID: &vehicleTokenId,
	}
	data, err := s.GetLatestData(ctx, subject)
	if err != nil {
		return nil, fmt.Errorf("failed to get vc: %w", err)
	}
	msg := models.VINVC{}
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal fingerprint message: %w", err)
	}
	return &msg, nil
}

// GenerateAndStoreVC generates a new VC and stores it in S3.
func (s *Service) GenerateAndStoreVC(ctx context.Context, vehicleTokenID uint32, vin string) error {
	newVC, err := s.issuer.CreateVINVC(vin, vehicleTokenID, time.Time{})
	if err != nil {
		return fmt.Errorf("failed to create VC: %w", err)
	}

	index := nameindexer.Index{
		Timestamp: time.Now(),
		Subject: nameindexer.Subject{
			TokenID: &vehicleTokenID,
		},
		DataType: "vinvc_0.1",
	}

	err = s.StoreFile(ctx, &index, newVC)
	if err != nil {
		return fmt.Errorf("failed to store VC: %w", err)
	}

	return nil
}
