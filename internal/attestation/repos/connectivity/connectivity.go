package connectivity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/DIMO-Network/attestation-api/internal/attestation/repos"
	"github.com/DIMO-Network/attestation-api/internal/models"
	"github.com/DIMO-Network/model-garage/pkg/cloudevent"
	"github.com/DIMO-Network/nameindexer/pkg/clickhouse/indexrepo"
	"github.com/ethereum/go-ethereum/common"
)

var cloudEventStatus = cloudevent.TypeStatus

var (
	// TODO: Replace with actual addresses of each connection or DIMO connection
	syntheticSource = common.HexToAddress("0x0000000000000000000000000000000000000000")
	twilioSource    = common.HexToAddress("0x0000000000000000000000000000000000000000")
	hashDogSource   = common.HexToAddress("0x0000000000000000000000000000000000000000")
)

// ConnectivityRepo is a repository for retrieving connectivity events.
type ConnectivityRepo struct {
	indexService      *indexrepo.Service
	autoPiDataType    string
	autoPiBucketName  string
	hashDogDataType   string
	hashDogBucketName string
	statusDataType    string
	statusBucketName  string
	cloudEventBucket  string
	ruptelaSource     common.Address
}

// NewConnectivityRepo creates a new instance of ConnectivityRepoImpl.
func NewConnectivityRepo(chConn clickhouse.Conn, objGetter indexrepo.ObjectGetter, autoPiDataType, autoPiBucketName, hashDogDataType, hashDogBucketName, statusDataType, statusBucketName, cloudEventBucketName string, ruptelaSource common.Address) *ConnectivityRepo {
	return &ConnectivityRepo{
		indexService:     indexrepo.New(chConn, objGetter),
		cloudEventBucket: cloudEventBucketName,
		ruptelaSource:    ruptelaSource,

		// These can go away when we switch storage
		autoPiDataType:    autoPiDataType,
		autoPiBucketName:  autoPiBucketName,
		hashDogDataType:   hashDogDataType,
		hashDogBucketName: hashDogBucketName,
		statusDataType:    statusDataType,
		statusBucketName:  statusBucketName,
	}
}

// GetAutoPiEvents returns the twilio events for a autopi device.
func (r *ConnectivityRepo) GetAutoPiEvents(ctx context.Context, device *models.PairedDevice, after, before time.Time, limit int) ([]cloudevent.CloudEvent[json.RawMessage], error) {
	records, err := r.getEvents(ctx, twilioSource, device.DID, after, before, limit)
	if errors.Is(err, sql.ErrNoRows) {
		subject := repos.IMEIToString(device.IMEI)
		return r.getLegacyEvents(ctx, r.autoPiBucketName, r.autoPiDataType, subject, after, before, limit)
	}
	if err != nil {
		return nil, err
	}
	return records, nil
}

// GetHashDogEvents returns the lorawan events for a hashdog device.
func (r *ConnectivityRepo) GetHashDogEvents(ctx context.Context, device *models.PairedDevice, after, before time.Time, limit int) ([]cloudevent.CloudEvent[json.RawMessage], error) {
	records, err := r.getEvents(ctx, hashDogSource, device.DID, after, before, limit)
	if errors.Is(err, sql.ErrNoRows) {
		subject := device.Address[2:]
		return r.getLegacyEvents(ctx, r.hashDogBucketName, r.hashDogDataType, subject, after, before, limit)
	}
	if err != nil {
		return nil, err
	}
	return records, nil
}

// GetSyntheticstatusEvents returns the status events for a vehicle.
func (r *ConnectivityRepo) GetSyntheticstatusEvents(ctx context.Context, vehicleDID cloudevent.NFTDID, after, before time.Time, limit int) ([]cloudevent.CloudEvent[json.RawMessage], error) {
	records, err := r.getEvents(ctx, syntheticSource, vehicleDID, after, before, limit)
	if errors.Is(err, sql.ErrNoRows) {
		subject := repos.TokenIDToString(vehicleDID.TokenID)
		return r.getLegacyEvents(ctx, r.statusBucketName, r.statusDataType, subject, after, before, limit)
	}
	if err != nil {
		return nil, err
	}
	return records, nil
}

// GetRuptelaStatusEvents returns the status events for a vehicle.
func (r *ConnectivityRepo) GetRuptelaStatusEvents(ctx context.Context, vehicleDID cloudevent.NFTDID, after, before time.Time, limit int) ([]cloudevent.CloudEvent[json.RawMessage], error) {
	records, err := r.getEvents(ctx, r.ruptelaSource, vehicleDID, after, before, limit)
	if errors.Is(err, sql.ErrNoRows) {
		subject := repos.TokenIDToString(vehicleDID.TokenID)
		return r.getLegacyEvents(ctx, r.statusBucketName, r.statusDataType, subject, after, before, limit)
	}
	if err != nil {
		return nil, err
	}
	return records, nil
}

func (r *ConnectivityRepo) getEvents(ctx context.Context, source common.Address, subject cloudevent.NFTDID, after, before time.Time, limit int) ([]cloudevent.CloudEvent[json.RawMessage], error) {
	opts := indexrepo.SearchOptions{
		Subject: &subject,
		Type:    &cloudEventStatus,
		Source:  &source,
		After:   after,
		Before:  before,
	}
	events, err := r.indexService.ListCloudEvents(ctx, r.cloudEventBucket, limit, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get filenames: %w", err)
	}
	return events, nil
}

func (r *ConnectivityRepo) getLegacyEvents(ctx context.Context, bucketName string, dataType string, subject string, after, before time.Time, limit int) ([]cloudevent.CloudEvent[json.RawMessage], error) {
	opts := indexrepo.RawSearchOptions{
		Subject:     &subject,
		DataVersion: &dataType,
		After:       after,
		Before:      before,
	}
	events, err := r.indexService.ListCloudEventsFromRaw(ctx, bucketName, limit, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get filenames: %w", err)
	}
	return events, nil
}
