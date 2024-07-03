package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/DIMO-Network/attestation-api/internal/config"
	"github.com/DIMO-Network/attestation-api/internal/controllers/vc"
	"github.com/DIMO-Network/attestation-api/internal/services/fingerprint"
	"github.com/DIMO-Network/attestation-api/internal/services/identity"
	"github.com/DIMO-Network/attestation-api/internal/services/vinvalidator"
	"github.com/DIMO-Network/attestation-api/internal/services/vinvc"
	"github.com/DIMO-Network/attestation-api/pkg/verifiable"
	"github.com/DIMO-Network/clickhouse-infra/pkg/connect"
	ddgrpc "github.com/DIMO-Network/device-definitions-api/pkg/grpc"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func createVINController(logger *zerolog.Logger, settings *config.Settings) (*vc.Controller, error) {
	// Initialize ClickHouse connection
	chConn, err := connect.GetClickhouseConn(&settings.Clickhouse)
	if err != nil {
		return nil, fmt.Errorf("failed to create ClickHouse connection: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	err = chConn.Ping(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to ping ClickHouse: %w", err)
	}

	s3Client := s3ClientFromSettings(settings)

	issuer, err := issuerFromSettings(settings)
	if err != nil {
		return nil, err
	}
	revokedList, err := revokedListFromSettings(settings)
	if err != nil {
		return nil, err
	}

	fingerprintService := fingerprint.New(chConn, s3Client, settings.FingerprintBucket, settings.FingerprintDataType)
	identityService, err := identity.NewService(settings.IdentityAPIURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create identity service: %w", err)
	}
	vinvcService := vinvc.New(chConn, s3Client, issuer, settings.VINVCBucket, settings.VINVCDataType, revokedList)
	deviceDefAPIClient, err := deviceDefAPIClientFromSettings(settings)
	if err != nil {
		return nil, fmt.Errorf("failed to create device definition API client: %w", err)
	}
	vinValidateSerivce := vinvalidator.New(deviceDefAPIClient)
	vinvcCtrl, err := vc.NewVCController(logger, vinvcService, identityService, fingerprintService, vinValidateSerivce, settings.TelemetryURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create VC controller: %w", err)
	}

	return vinvcCtrl, nil
}

// s3ClientFromSettings creates an S3 client from the given settings.
func s3ClientFromSettings(settings *config.Settings) *s3.Client {
	// Create an AWS session
	conf := aws.Config{
		Region: settings.S3AWSRegion,
		Credentials: credentials.NewStaticCredentialsProvider(
			settings.S3AWSAccessKeyID,
			settings.S3AWSSecretAccessKey,
			"",
		),
	}
	return s3.NewFromConfig(conf)
}

func issuerFromSettings(settings *config.Settings) (*verifiable.Issuer, error) {
	baseURL := url.URL{
		Scheme: "https",
		Host:   settings.ExternalHostname,
		Path:   "/v1/vc/status",
	}
	privateKey, err := hex.DecodeString(settings.VINVCPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}
	verifiableConfig := verifiable.Config{
		PrivateKey:        privateKey,
		ChainID:           big.NewInt(settings.DIMORegistryChainID),
		VehicleNFTAddress: common.HexToAddress(settings.VehicleNFTAddress),
		BaseStatusURL:     baseURL.String(),
	}
	issuer, err := verifiable.NewIssuer(verifiableConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create VC issuer: %w", err)
	}
	return issuer, nil
}

func revokedListFromSettings(settings *config.Settings) ([]uint32, error) {
	if settings.RevokedTokenIDs == "" {
		return nil, nil
	}
	tokenIDs := strings.Split(settings.RevokedTokenIDs, ",")
	revokedList := make([]uint32, len(tokenIDs))
	for i, id := range tokenIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		tokenID, err := strconv.Atoi(strings.TrimSpace(id))
		if err != nil {
			return nil, fmt.Errorf("failed to convert revoked token ID to int: %w", err)
		}
		revokedList[i] = uint32(tokenID)
	}
	return revokedList, nil
}

func deviceDefAPIClientFromSettings(settings *config.Settings) (ddgrpc.VinDecoderServiceClient, error) {
	conn, err := grpc.NewClient(settings.DefinitionsGRPCAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client: %w", err)
	}
	definitionsClient := ddgrpc.NewVinDecoderServiceClient(conn)
	return definitionsClient, nil
}
