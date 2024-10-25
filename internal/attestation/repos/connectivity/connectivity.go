package connectivity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/DIMO-Network/attestation-api/internal/attestation/repos"
	"github.com/DIMO-Network/attestation-api/internal/models"
	"github.com/DIMO-Network/model-garage/pkg/cloudevent"
	"github.com/DIMO-Network/nameindexer"
	"github.com/DIMO-Network/nameindexer/pkg/clickhouse/indexrepo"
	"github.com/ethereum/go-ethereum/common"
)

var statusFiller = nameindexer.CloudTypeToFiller(cloudevent.TypeStatus)

var (
	ruptelaSource = common.HexToAddress("0x3A6603E1065C9b3142403b1b7e349a6Ae936E819")

	// TODO: Replace with actual addresses of each connection or DIMO connection
	smartCarSource = common.HexToAddress("0x0000000000000000000000000000000000000000")
	twilioSource   = common.HexToAddress("0x0000000000000000000000000000000000000000")
	hashDogSource  = common.HexToAddress("0x0000000000000000000000000000000000000000")
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
}

// NewConnectivityRepo creates a new instance of ConnectivityRepoImpl.
func NewConnectivityRepo(chConn clickhouse.Conn, objGetter indexrepo.ObjectGetter, autoPiDataType, autoPiBucketName, hashDogDataType, hashDogBucketName, statusDataType, statusBucketName, cloudEventBucketName string) *ConnectivityRepo {
	return &ConnectivityRepo{
		indexService:     indexrepo.New(chConn, objGetter),
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
func (r *ConnectivityRepo) GetAutoPiEvents(ctx context.Context, device *models.PairedDevice, after, before time.Time, limit int) ([][]byte, error) {
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
func (r *ConnectivityRepo) GetHashDogEvents(ctx context.Context, device *models.PairedDevice, after, before time.Time, limit int) ([][]byte, error) {
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

// GetSmartCarStatusEvents returns the status events for a vehicle.
func (r *ConnectivityRepo) GetSmartCarStatusEvents(ctx context.Context, vehicleDID cloudevent.NFTDID, after, before time.Time, limit int) ([][]byte, error) {
	records, err := r.getEvents(ctx, smartCarSource, vehicleDID, after, before, limit)
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
func (r *ConnectivityRepo) GetRuptelaStatusEvents(ctx context.Context, vehicleDID cloudevent.NFTDID, after, before time.Time, limit int) ([][]byte, error) {
	records, err := r.getEvents(ctx, ruptelaSource, vehicleDID, after, before, limit)
	if errors.Is(err, sql.ErrNoRows) {
		subject := repos.TokenIDToString(vehicleDID.TokenID)
		return r.getLegacyEvents(ctx, r.statusBucketName, r.statusDataType, subject, after, before, limit)
	}
	if err != nil {
		return nil, err
	}
	return records, nil
}

func (r *ConnectivityRepo) getEvents(ctx context.Context, source common.Address, subject cloudevent.NFTDID, after, before time.Time, limit int) ([][]byte, error) {
	opts := indexrepo.CloudEventSearchOptions{
		Subject:       &subject,
		PrimaryFiller: &statusFiller,
		Source:        &source,
		After:         after,
		Before:        before,
	}
	fileData, err := r.indexService.GetCloudEventData(ctx, r.cloudEventBucket, limit, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get filenames: %w", err)
	}
	return fileData, nil
}

func (r *ConnectivityRepo) getLegacyEvents(ctx context.Context, bucketName string, dataType string, subject string, after, before time.Time, limit int) ([][]byte, error) {
	opts := indexrepo.SearchOptions{
		Subject:  &subject,
		DataType: &dataType,
		After:    after,
		Before:   before,
	}
	fileData, err := r.indexService.GetData(ctx, bucketName, limit, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get filenames: %w", err)
	}
	return fileData, nil
}
