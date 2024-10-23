package vcrepo

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/DIMO-Network/attestation-api/pkg/verifiable"
	"github.com/DIMO-Network/model-garage/pkg/cloudevent"
	"github.com/DIMO-Network/nameindexer"
	"github.com/DIMO-Network/nameindexer/pkg/clickhouse/indexrepo"
	"github.com/ethereum/go-ethereum/common"
	"github.com/segmentio/ksuid"
)

// Repo manages storing and retrieving VCs.
type Repo struct {
	indexService  *indexrepo.Service
	vinDataType   string
	vinBucketName string
	pomDataType   string
	pomBucketName string
}

// New creates a new instance of VCRepo.
func New(chConn clickhouse.Conn, objGetter indexrepo.ObjectGetter, vinbucketName, vinvcDataType, pombucketName, pomvcDataType string) *Repo {
	return &Repo{
		indexService:  indexrepo.New(chConn, objGetter),
		vinDataType:   vinvcDataType,
		vinBucketName: vinbucketName,
		pomDataType:   pomvcDataType,
		pomBucketName: pombucketName,
	}
}

// GetLatestVINVC fetches the latest vinvc from S3.
func (r *Repo) GetLatestVINVC(ctx context.Context, vehicleDID cloudevent.NFTDID) (*verifiable.Credential, error) {
	opts := indexrepo.CloudEventSearchOptions{
		Subject:  &vehicleDID,
		DataType: &r.vinDataType,
	}
	data, err := r.indexService.GetLatestCloudEventData(ctx, r.vinBucketName, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get vc: %w", err)
	}
	msg := cloudevent.CloudEvent[verifiable.Credential]{}
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal fingerprint message: %w", err)
	}
	return &msg.Data, nil
}

// StoreVINVC stores a new VC in S3.
func (r *Repo) StoreVINVC(ctx context.Context, vehicleDID, producerDID cloudevent.NFTDID, rawVC json.RawMessage) error {
	return r.storeVC(ctx, vehicleDID, producerDID, rawVC, r.vinDataType)
}

// StorePOMVC stores a new VC in S3.
func (r *Repo) StorePOMVC(ctx context.Context, vehicleDID, producerDID cloudevent.NFTDID, rawVC json.RawMessage) error {
	return r.storeVC(ctx, vehicleDID, producerDID, rawVC, r.pomDataType)
}

func (r *Repo) storeVC(ctx context.Context, vehicleDID, producerDID cloudevent.NFTDID, rawVC json.RawMessage, dataType string) error {
	// expire at the end of the week
	cloudEvent := cloudevent.CloudEvent[json.RawMessage]{
		CloudEventHeader: cloudevent.CloudEventHeader{
			SpecVersion:     "1.0",
			ID:              ksuid.New().String(),
			Time:            time.Now(),
			Source:          common.HexToAddress("0x0").String(),
			Subject:         vehicleDID.String(),
			Producer:        producerDID.String(),
			Type:            "dimo.verifiableCredential",
			DataContentType: "application/json",

			DataVersion: dataType,
		},
		Data: rawVC,
	}
	cloudIdx, err := nameindexer.CloudEventToCloudIndex(&cloudEvent.CloudEventHeader, nameindexer.DefaultSecondaryFiller)
	if err != nil {
		return fmt.Errorf("failed to convert VC to cloud index: %w", err)
	}
	eventData, err := json.Marshal(cloudEvent)
	if err != nil {
		return fmt.Errorf("failed to marshal VC as cloud event: %w", err)
	}

	err = r.indexService.StoreCloudEventFile(ctx, cloudIdx, r.pomBucketName, eventData)
	if err != nil {
		return fmt.Errorf("failed to store VC: %w", err)
	}

	return nil
}
