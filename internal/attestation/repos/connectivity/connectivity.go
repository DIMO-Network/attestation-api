package connectivity

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/DIMO-Network/nameindexer"
	"github.com/DIMO-Network/nameindexer/pkg/clickhouse/indexrepo"
	"github.com/ethereum/go-ethereum/common"
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
}

// NewConnectivityRepo creates a new instance of ConnectivityRepoImpl.
func NewConnectivityRepo(chConn clickhouse.Conn, objGetter indexrepo.ObjectGetter, autoPiDataType, autoPiBucketName, hashDogDataType, hashDogBucketName, statusDataType, statusBucketName string) *ConnectivityRepo {
	return &ConnectivityRepo{
		indexService:      indexrepo.New(chConn, objGetter),
		autoPiDataType:    autoPiDataType,
		autoPiBucketName:  autoPiBucketName,
		hashDogDataType:   hashDogDataType,
		hashDogBucketName: hashDogBucketName,
		statusDataType:    statusDataType,
		statusBucketName:  statusBucketName,
	}
}

// GetAutoPiEvents returns the twilio events for a autopi device.
func (r *ConnectivityRepo) GetAutoPiEvents(ctx context.Context, IMEI string, after, before time.Time, limit int) ([][]byte, error) {
	subject := nameindexer.Subject{
		Identifier: nameindexer.IMEI(IMEI),
	}
	return r.getEvents(ctx, r.autoPiBucketName, r.autoPiDataType, subject, after, before, limit)
}

// GetHashDogEvents returns the lorawan events for a hashdog device.
func (r *ConnectivityRepo) GetHashDogEvents(ctx context.Context, pairedDeviceAddr common.Address, after, before time.Time, limit int) ([][]byte, error) {
	subject := nameindexer.Subject{
		Identifier: nameindexer.Address(pairedDeviceAddr),
	}
	return r.getEvents(ctx, r.hashDogBucketName, r.hashDogDataType, subject, after, before, limit)
}

// GetStatusEvents returns the status events for a vehicle.
func (r *ConnectivityRepo) GetStatusEvents(ctx context.Context, vehicleTokenID uint32, after, before time.Time, limit int) ([][]byte, error) {
	subject := nameindexer.Subject{
		Identifier: nameindexer.TokenID(vehicleTokenID),
	}
	return r.getEvents(ctx, r.statusBucketName, r.statusDataType, subject, after, before, limit)
}

func (r *ConnectivityRepo) getEvents(ctx context.Context, bucketName string, dataType string, subject nameindexer.Subject, after, before time.Time, limit int) ([][]byte, error) {
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
