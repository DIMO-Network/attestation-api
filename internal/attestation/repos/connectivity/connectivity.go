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
	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/cloudevent/pkg/clickhouse/eventrepo"
	"github.com/DIMO-Network/model-garage/pkg/modules"
	"github.com/ethereum/go-ethereum/common"
)

var (
	cloudEventStatus = cloudevent.TypeStatus
	todoSource       = common.HexToAddress("0x00")
)

// ConnectivityRepo is a repository for retrieving connectivity events.
type ConnectivityRepo struct {
	indexService      *eventrepo.Service
	autoPiDataType    string
	autoPiBucketName  string
	hashDogDataType   string
	hashDogBucketName string
	statusDataType    string
	statusBucketName  string
	cloudEventBucket  string
}

// NewConnectivityRepo creates a new instance of ConnectivityRepoImpl.
func NewConnectivityRepo(chConn clickhouse.Conn, objGetter eventrepo.ObjectGetter, autoPiDataType, autoPiBucketName, hashDogDataType, hashDogBucketName, statusDataType, statusBucketName, cloudEventBucketName string) *ConnectivityRepo {
	return &ConnectivityRepo{
		indexService:     eventrepo.New(chConn, objGetter),
		cloudEventBucket: cloudEventBucketName,

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
	records, err := r.getEvents(ctx, todoSource, device.DID, after, before, limit)
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
	records, err := r.getEvents(ctx, modules.HashDogSource, device.DID, after, before, limit)
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
	records, err := r.getEvents(ctx, todoSource, vehicleDID, after, before, limit)
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
	records, err := r.getEvents(ctx, modules.RuptelaSource, vehicleDID, after, before, limit)
	if errors.Is(err, sql.ErrNoRows) {
		subject := repos.TokenIDToString(vehicleDID.TokenID)
		return r.getLegacyEvents(ctx, r.statusBucketName, r.statusDataType, subject, after, before, limit)
	}
	if err != nil {
		return nil, err
	}
	return records, nil
}

// GetCompassStatusEvents returns the status events for a vehicle.
func (r *ConnectivityRepo) GetCompassStatusEvents(ctx context.Context, vehicleDID cloudevent.NFTDID, after, before time.Time, limit int) ([]cloudevent.CloudEvent[json.RawMessage], error) {
	records, err := r.getEvents(ctx, modules.CompassSource, vehicleDID, after, before, limit)
	if errors.Is(err, sql.ErrNoRows) {
		subject := repos.TokenIDToString(vehicleDID.TokenID)
		return r.getLegacyEvents(ctx, r.statusBucketName, r.statusDataType, subject, after, before, limit)
	}
	if err != nil {
		return nil, err
	}
	return records, nil
}

// GetMotorqStatusEvents returns the status events for a vehicle.
func (r *ConnectivityRepo) GetMotorqStatusEvents(ctx context.Context, vehicleDID cloudevent.NFTDID, after, before time.Time, limit int) ([]cloudevent.CloudEvent[json.RawMessage], error) {
	records, err := r.getEvents(ctx, common.HexToAddress("0x5879B43D88Fa93CE8072d6612cBc8dE93E98CE5d"), vehicleDID, after, before, limit)
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
	opts := &eventrepo.SearchOptions{
		Subject: ref(subject.String()),
		Type:    &cloudEventStatus,
		Source:  ref(source.String()),
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
	opts := &eventrepo.SearchOptions{
		Subject:     &subject,
		DataVersion: &dataType,
		After:       after,
		Before:      before,
	}
	events, err := r.indexService.ListCloudEvents(ctx, bucketName, limit, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get filenames: %w", err)
	}
	for i := range events {
		embededEvent := cloudevent.CloudEvent[json.RawMessage]{}
		err = json.Unmarshal(events[i].Data, &embededEvent)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal event: %w", err)
		}
		events[i] = embededEvent
	}
	return events, nil
}

func ref[T any](v T) *T {
	return &v
}
