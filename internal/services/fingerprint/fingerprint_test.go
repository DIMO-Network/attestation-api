package fingerprint_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/DIMO-Network/attestation-api/internal/services/fingerprint"
	"github.com/DIMO-Network/attestation-api/pkg/models"
	chConfig "github.com/DIMO-Network/clickhouse-infra/pkg/connect/config"
	"github.com/DIMO-Network/clickhouse-infra/pkg/container"
	"github.com/DIMO-Network/nameindexer"
	chindexer "github.com/DIMO-Network/nameindexer/pkg/clickhouse"
	"github.com/DIMO-Network/nameindexer/pkg/clickhouse/migrations"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

var fingerprintDataType = "0123456789"

// setupClickHouseContainer starts a ClickHouse container for testing and returns the connection.
func setupClickHouseContainer(t *testing.T) *container.Container {
	ctx := context.Background()
	settings := chConfig.Settings{
		User:     "default",
		Database: "dimo",
	}

	chContainer, err := container.CreateClickHouseContainer(ctx, settings)
	require.NoError(t, err)

	chDB, err := chContainer.GetClickhouseAsDB()
	require.NoError(t, err)

	// Ensure we terminate the container at the end
	t.Cleanup(func() {
		chContainer.Terminate(ctx)
	})

	err = migrations.RunGoose(ctx, []string{"up"}, chDB)
	require.NoError(t, err)

	return chContainer
}

// insertTestData inserts test data into ClickHouse.
func insertTestData(t *testing.T, ctx context.Context, conn clickhouse.Conn, subject nameindexer.Subject, filename string, timestamp time.Time) {
	query := fmt.Sprintf("INSERT INTO %s (%s, %s, %s, %s)   VALUES (?, ?, ?, ?)", chindexer.TableName,
		chindexer.SubjectColumn, chindexer.FileNameColumn, chindexer.TimestampColumn, chindexer.DataTypeColumn)
	err := conn.Exec(ctx, query, subject, filename, timestamp, fingerprintDataType)
	require.NoError(t, err)
}

// TestGetFingerprintMessage tests the GetFingerprintMessage function.
func TestGetFingerprintMessage(t *testing.T) {
	chContainer := setupClickHouseContainer(t)
	deviceAddr1 := randAddress()
	deviceAddr2 := randAddress()

	conn, err := chContainer.GetClickHouseAsConn()
	require.NoError(t, err)
	ctx := context.Background()
	insertTestData(t, ctx, conn, nameindexer.Subject{Address: ref(deviceAddr1)}, "fingerprint1.json", time.Now().Add(-1*time.Hour))
	tests := []struct {
		name            string
		deviceAddr      common.Address
		expectedMessage *models.DecodedFingerprintData
		expectedError   bool
	}{
		{
			name:       "valid fingerprint message",
			deviceAddr: deviceAddr1,
			expectedMessage: &models.DecodedFingerprintData{
				VIN: "1HGCM82633A123456",
			},
		},
		{
			name:          "no records",
			deviceAddr:    deviceAddr2,
			expectedError: true,
		},
	}

	ctrl := gomock.NewController(t)
	mockS3Client := NewMockObjectGetter(ctrl)
	content := []byte(`{"vin": "1HGCM82633A123456"}`)
	mockS3Client.EXPECT().GetObjectWithContext(gomock.Any(), gomock.Any(), gomock.Any()).Return(&s3.GetObjectOutput{
		Body:          io.NopCloser(bytes.NewReader(content)),
		ContentLength: ref(int64(len(content))),
	}, nil)

	fingerprintService := fingerprint.New(conn, mockS3Client, "test-bucket", fingerprintDataType)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message, err := fingerprintService.GetLatestFingerprintMessages(context.Background(), tt.deviceAddr)

			if tt.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expectedMessage.VIN, message.VIN)
			}
		})
	}
}

func ref[T any](x T) *T {
	return &x
}

func randAddress() common.Address {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}
	return crypto.PubkeyToAddress(privateKey.PublicKey)
}
