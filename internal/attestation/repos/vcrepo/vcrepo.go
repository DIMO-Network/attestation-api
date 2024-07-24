package vcrepo

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/DIMO-Network/attestation-api/pkg/verifiable"
	"github.com/DIMO-Network/nameindexer"
	"github.com/DIMO-Network/nameindexer/pkg/clickhouse/service"
)

// Repo manages storing and retrieving VCs.
type Repo struct {
	indexService *service.Service
	dataType     string
}

// New creates a new instance of VCRepo.
func New(chConn clickhouse.Conn, objGetter service.ObjectGetter, bucketName, vinvcDataType string) *Repo {
	return &Repo{
		indexService: service.New(chConn, objGetter, bucketName),
		dataType:     vinvcDataType,
	}
}

// GetLatestVINVC fetches the latest vinvc from S3.
func (r *Repo) GetLatestVINVC(ctx context.Context, vehicleTokenID uint32) (*verifiable.Credential, error) {
	subject := nameindexer.Subject{
		TokenID: &vehicleTokenID,
	}
	data, err := r.indexService.GetLatestData(ctx, r.dataType, subject)
	if err != nil {
		return nil, fmt.Errorf("failed to get vc: %w", err)
	}
	msg := verifiable.Credential{}
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal fingerprint message: %w", err)
	}
	return &msg, nil
}

// StoreVINVC stores a new VC in S3.
func (r *Repo) StoreVINVC(ctx context.Context, vehicleTokenID uint32, rawVC json.RawMessage) error {
	// expire at the end of the wee
	index := nameindexer.Index{
		Timestamp: time.Now(),
		Subject: nameindexer.Subject{
			TokenID: &vehicleTokenID,
		},
		DataType: r.dataType,
	}

	err := r.indexService.StoreFile(ctx, &index, rawVC)
	if err != nil {
		return fmt.Errorf("failed to store VC: %w", err)
	}

	return nil
}
