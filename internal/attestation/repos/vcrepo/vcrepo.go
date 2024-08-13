package vcrepo

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/DIMO-Network/attestation-api/pkg/verifiable"
	"github.com/DIMO-Network/nameindexer"
	"github.com/DIMO-Network/nameindexer/pkg/clickhouse/indexrepo"
)

// Repo manages storing and retrieving VCs.
type Repo struct {
	indexService *indexrepo.Service
	dataType     string
	bucketName   string
}

// New creates a new instance of VCRepo.
func New(chConn clickhouse.Conn, objGetter indexrepo.ObjectGetter, bucketName, vinvcDataType string) *Repo {
	return &Repo{
		indexService: indexrepo.New(chConn, objGetter),
		dataType:     vinvcDataType,
		bucketName:   bucketName,
	}
}

// GetLatestVINVC fetches the latest vinvc from S3.
func (r *Repo) GetLatestVINVC(ctx context.Context, vehicleTokenID uint32) (*verifiable.Credential, error) {
	opts := indexrepo.SearchOptions{
		Subject: &nameindexer.Subject{
			Identifier: nameindexer.TokenID(vehicleTokenID),
		},
		DataType: &r.dataType,
	}
	data, err := r.indexService.GetLatestData(ctx, r.bucketName, opts)
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
			Identifier: nameindexer.TokenID(vehicleTokenID),
		},
		DataType: r.dataType,
	}

	err := r.indexService.StoreFile(ctx, &index, r.bucketName, rawVC)
	if err != nil {
		return fmt.Errorf("failed to store VC: %w", err)
	}

	return nil
}
