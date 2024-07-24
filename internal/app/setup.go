package app

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/DIMO-Network/attestation-api/internal/attestation/apis/identity"
	"github.com/DIMO-Network/attestation-api/internal/attestation/apis/vinvalidator"
	"github.com/DIMO-Network/attestation-api/internal/attestation/repos/fingerprint"
	"github.com/DIMO-Network/attestation-api/internal/attestation/repos/vcrepo"
	"github.com/DIMO-Network/attestation-api/internal/attestation/vinvc"
	"github.com/DIMO-Network/attestation-api/internal/config"
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

// createVINController creates a new VINVC controller by initializing the required services using the provided settings.
func createVINCService(logger *zerolog.Logger, settings *config.Settings, statusRoute, keysRoute string) (*vinvc.Service, error) {
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

	// Initialize S3 client
	s3Client := s3ClientFromSettings(settings)

	// Initialize VC issuer and revoked list
	issuer, err := issuerFromSettings(settings, statusRoute, keysRoute)
	if err != nil {
		return nil, err
	}
	revokedList, err := revokedListFromSettings(settings)
	if err != nil {
		return nil, err
	}

	// Initialize device definition API client
	deviceDefGRPCClient, err := deviceDefAPIClientFromSettings(settings)
	if err != nil {
		return nil, fmt.Errorf("failed to create device definition API client: %w", err)
	}
	vinValidateSerivce := vinvalidator.New(deviceDefGRPCClient)

	// Initialize fingerprint repository
	fingerprintRepo := fingerprint.New(chConn, s3Client, settings.FingerprintBucket, settings.FingerprintDataType)

	// Initialize VC repository
	vcRepo := vcrepo.New(chConn, s3Client, settings.VINVCBucket, settings.VINVCDataType)

	// Initialize identity API client
	identityAPI, err := identity.NewService(settings.IdentityAPIURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create identity service: %w", err)
	}

	// Initialize VC service using the initialized services
	vinvcService := vinvc.NewService(logger, vcRepo, identityAPI, fingerprintRepo, vinValidateSerivce, issuer, revokedList)

	return vinvcService, nil
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

func issuerFromSettings(settings *config.Settings, statusRoute, keysRoute string) (*verifiable.Issuer, error) {
	baseStatusURL := url.URL{
		Scheme: "https",
		Host:   settings.ExternalHostname,
		Path:   statusRoute,
	}
	baseKeyURL := url.URL{
		Scheme: "https",
		Host:   settings.ExternalHostname,
		Path:   keysRoute,
	}
	privateKey, err := hex.DecodeString(settings.VINVCPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}
	verifiableConfig := verifiable.Config{
		PrivateKey:        privateKey,
		ChainID:           big.NewInt(settings.DIMORegistryChainID),
		VehicleNFTAddress: common.HexToAddress(settings.VehicleNFTAddress),
		BaseStatusURL:     baseStatusURL.String(),
		BaseKeyURL:        baseKeyURL.String(),
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
