package vcrepo

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/DIMO-Network/attestation-api/internal/sources"
	"github.com/DIMO-Network/attestation-api/pkg/verifiable"
	"github.com/DIMO-Network/model-garage/pkg/cloudevent"
	"github.com/DIMO-Network/nameindexer/pkg/clickhouse/indexrepo"
	"github.com/segmentio/ksuid"
)

// Repo manages storing and retrieving VCs.
type Repo struct {
	indexService   *indexrepo.Service
	vinDataVersion string
	pomDataVersion string
	vcBucketName   string
}

// New creates a new instance of VCRepo.
func New(chConn clickhouse.Conn, objGetter indexrepo.ObjectGetter, vcBucketName, vinVCDataVersion, pomVCDataversion string) *Repo {
	return &Repo{
		indexService:   indexrepo.New(chConn, objGetter),
		vinDataVersion: vinVCDataVersion,
		pomDataVersion: pomVCDataversion,
		vcBucketName:   vcBucketName,
	}
}

// GetLatestVINVC fetches the latest vinvc from S3.
func (r *Repo) GetLatestVINVC(ctx context.Context, vehicleDID cloudevent.NFTDID) (*verifiable.Credential, error) {
	opts := &indexrepo.SearchOptions{
		Subject:     ref(vehicleDID.String()),
		DataVersion: &r.vinDataVersion,
	}
	dataObj, err := r.indexService.GetLatestCloudEvent(ctx, r.vcBucketName, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get vc: %w", err)
	}
	msg := cloudevent.CloudEvent[verifiable.Credential]{}
	if err := json.Unmarshal(dataObj.Data, &msg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal fingerprint message: %w", err)
	}
	return &msg.Data, nil
}

// StoreVINVC stores a new VC in S3.
func (r *Repo) StoreVINVC(ctx context.Context, vehicleDID, producerDID cloudevent.NFTDID, rawVC json.RawMessage) error {
	return r.storeVC(ctx, vehicleDID, producerDID, rawVC, r.vinDataVersion)
}

// StorePOMVC stores a new VC in S3.
func (r *Repo) StorePOMVC(ctx context.Context, vehicleDID, producerDID cloudevent.NFTDID, rawVC json.RawMessage) error {
	return r.storeVC(ctx, vehicleDID, producerDID, rawVC, r.pomDataVersion)
}

func (r *Repo) storeVC(ctx context.Context, vehicleDID, producerDID cloudevent.NFTDID, rawVC json.RawMessage, dataVersion string) error {
	// expire at the end of the week
	cloudEvent := cloudevent.CloudEvent[json.RawMessage]{
		CloudEventHeader: cloudevent.CloudEventHeader{
			SpecVersion:     "1.0",
			ID:              ksuid.New().String(),
			Time:            time.Now(),
			Source:          sources.DINCSource.String(),
			Subject:         vehicleDID.String(),
			Producer:        producerDID.String(),
			Type:            cloudevent.TypeVerifableCredential,
			DataContentType: "application/json",
			DataVersion:     dataVersion,
		},
		Data: rawVC,
	}

	err := r.indexService.StoreCloudEvent(ctx, r.vcBucketName, cloudEvent)
	if err != nil {
		return fmt.Errorf("failed to store VC: %w", err)
	}

	return nil
}

func ref[T any](v T) *T {
	return &v
}
