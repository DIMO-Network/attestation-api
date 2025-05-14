package vcrepo

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/DIMO-Network/attestation-api/internal/sources"
	"github.com/DIMO-Network/attestation-api/pkg/verifiable"
	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/cloudevent/pkg/clickhouse/eventrepo"
	"github.com/segmentio/ksuid"
)

// Repo manages storing and retrieving VCs.
type Repo struct {
	indexService   *eventrepo.Service
	vinDataVersion string
	pomDataVersion string
	vcBucketName   string
}

// New creates a new instance of VCRepo.
func New(chConn clickhouse.Conn, objGetter eventrepo.ObjectGetter, vcBucketName, vinVCDataVersion, pomVCDataversion string) *Repo {
	return &Repo{
		indexService:   eventrepo.New(chConn, objGetter),
		vinDataVersion: vinVCDataVersion,
		pomDataVersion: pomVCDataversion,
		vcBucketName:   vcBucketName,
	}
}

// GetLatestVINVC fetches the latest vinvc from S3.
func (r *Repo) GetLatestVINVC(ctx context.Context, vehicleDID cloudevent.ERC721DID) (*verifiable.Credential, error) {
	opts := &eventrepo.SearchOptions{
		Subject:     ref(vehicleDID.String()),
		DataVersion: &r.vinDataVersion,
	}
	dataObj, err := r.indexService.GetLatestCloudEvent(ctx, r.vcBucketName, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get vc: %w", err)
	}
	var vinVC verifiable.Credential
	if err := json.Unmarshal(dataObj.Data, &vinVC); err != nil {
		return nil, fmt.Errorf("failed to unmarshal verifiable credential message: %w", err)
	}
	return &vinVC, nil
}

// StoreVINVC stores a new VC in S3.
func (r *Repo) StoreVINVC(ctx context.Context, vehicleDID, producerDID string, rawVC json.RawMessage) error {
	return r.storeVC(ctx, vehicleDID, producerDID, rawVC, r.vinDataVersion)
}

// StorePOMVC stores a new VC in S3.
func (r *Repo) StorePOMVC(ctx context.Context, vehicleDID, producerDID string, rawVC json.RawMessage) error {
	return r.storeVC(ctx, vehicleDID, producerDID, rawVC, r.pomDataVersion)
}

func (r *Repo) storeVC(ctx context.Context, vehicleDID, producerDID string, rawVC json.RawMessage, dataVersion string) error {
	// expire at the end of the week
	cloudEvent := cloudevent.CloudEvent[json.RawMessage]{
		CloudEventHeader: cloudevent.CloudEventHeader{
			SpecVersion:     "1.0",
			ID:              ksuid.New().String(),
			Time:            time.Now(),
			Source:          sources.DINCSource.String(),
			Subject:         vehicleDID,
			Producer:        producerDID,
			Type:            cloudevent.TypeVerifableCredential,
			DataContentType: "application/json",
			DataVersion:     dataVersion,
		},
		Data: rawVC,
	}
	eventBytes, err := json.Marshal(cloudEvent)
	if err != nil {
		return fmt.Errorf("failed to marshal cloud event: %w", err)
	}
	err = r.indexService.StoreObject(ctx, r.vcBucketName, &cloudEvent.CloudEventHeader, eventBytes)
	if err != nil {
		return fmt.Errorf("failed to store VC: %w", err)
	}

	return nil
}

func ref[T any](v T) *T {
	return &v
}
