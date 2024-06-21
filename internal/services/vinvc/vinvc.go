package vinvc

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/DIMO-Network/attestation-api/internal/services/indexfile"
	"github.com/DIMO-Network/attestation-api/pkg/verifiable"
	"github.com/DIMO-Network/nameindexer"
)

// Service manages and retrieves fingerprint messages.
type Service struct {
	indexfile.Service
	issuer     *verifiable.Issuer
	revokedMap map[uint32]struct{}
}

// New creates a new instance of Service.
func New(chConn clickhouse.Conn, objGetter indexfile.ObjectGetter, issuer *verifiable.Issuer, bucketName, vinvcDataType string, revokedList []uint32) *Service {

	revokeMap := make(map[uint32]struct{}, len(revokedList))
	for _, id := range revokedList {
		revokeMap[id] = struct{}{}
	}
	return &Service{
		Service:    *indexfile.New(chConn, objGetter, bucketName, vinvcDataType),
		issuer:     issuer,
		revokedMap: revokeMap,
	}
}

// GetLatestVC fetches the latest fingerprint message from S3.
func (s *Service) GetLatestVC(ctx context.Context, vehicleTokenId uint32) (*verifiable.Credential, error) {
	subject := nameindexer.Subject{
		TokenID: &vehicleTokenId,
	}
	data, err := s.GetLatestData(ctx, subject)
	if err != nil {
		return nil, fmt.Errorf("failed to get vc: %w", err)
	}
	msg := verifiable.Credential{}
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal fingerprint message: %w", err)
	}
	return &msg, nil
}

// GenerateAndStoreVINVC generates a new VIN VC and stores it in S3.
func (s *Service) GenerateAndStoreVINVC(ctx context.Context, vehicleTokenID uint32, vin string) error {
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

// GenerateStatusVC generates a new status VC.
func (s *Service) GenerateStatusVC(tokenID uint32) (json.RawMessage, error) {
	revoked := false
	if _, ok := s.revokedMap[tokenID]; ok {
		revoked = true
	}
	vcData, err := s.issuer.CreateBitstringStatusListVC(tokenID, revoked)
	if err != nil {
		return nil, fmt.Errorf("failed to create VC: %w", err)
	}
	return vcData, nil
}
