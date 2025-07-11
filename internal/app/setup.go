package app

import (
	"fmt"
	"time"

	"github.com/DIMO-Network/attestation-api/internal/attestation/apis/identity"
	"github.com/DIMO-Network/attestation-api/internal/attestation/apis/vinvalidator"
	"github.com/DIMO-Network/attestation-api/internal/attestation/repos/fingerprint"
	"github.com/DIMO-Network/attestation-api/internal/attestation/repos/vcrepo"
	"github.com/DIMO-Network/attestation-api/internal/attestation/vinvc"
	"github.com/DIMO-Network/attestation-api/internal/client/dex"
	"github.com/DIMO-Network/attestation-api/internal/client/fetchapi"
	"github.com/DIMO-Network/attestation-api/internal/client/tokencache"
	"github.com/DIMO-Network/attestation-api/internal/config"
	"github.com/DIMO-Network/attestation-api/internal/controllers/httphandlers"
	"github.com/DIMO-Network/attestation-api/internal/controllers/rpc"
	ddgrpc "github.com/DIMO-Network/device-definitions-api/pkg/grpc"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// createControllers creates a new controllers with the given settings.
func createControllers(logger *zerolog.Logger, settings *config.Settings, statusRoute, keysRoute, vocabRoute, jsonLDRoute string) (*httphandlers.HTTPController, *rpc.Server, error) {
	fetchAPIClient := fetchapi.New(settings)

	privateKey, err := crypto.HexToECDSA(settings.SignerPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode private key: %w", err)
	}

	// Initialize device definition API client
	deviceDefGRPCClient, err := deviceDefAPIClientFromSettings(settings)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create device definition API client: %w", err)
	}
	vinValidateSerivce := vinvalidator.New(deviceDefGRPCClient)

	// Initialize fingerprint repository
	fingerprintRepo := fingerprint.New(fetchAPIClient)

	dexClient, err := dex.NewClient(settings)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create dex client: %w", err)
	}

	// Initialize token cache with both token getters
	devLicenseTokenCache := tokencache.New(
		time.Hour,    // Default expiration
		time.Hour*24, // Cleanup interval
		dexClient,
	)
	// Initialize VC repository
	vcRepo, err := vcrepo.New(settings, devLicenseTokenCache)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create VC repository: %w", err)
	}

	// Initialize identity API client
	identityAPI, err := identity.NewService(settings.IdentityAPIURL, settings.AfterMarketNFTAddress, settings.SyntheticNFTAddress, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create identity service: %w", err)
	}

	// Initialize VC service using the initialized services
	vinvcService := vinvc.NewService(logger, vcRepo, identityAPI, fingerprintRepo, vinValidateSerivce, settings, privateKey)

	// conRepo := connectivity.NewConnectivityRepo(chConn, s3Client, settings.AutoPiDataType, settings.AutoPiBucketName, settings.HashDogDataType, settings.HashDogBucketName, settings.StatusDataType, settings.StatusBucketName, settings.CloudEventBucket)

	// pomService, err := pom.NewService(logger, identityAPI, conRepo, vcRepo, settings.VehicleNFTAddress, settings.DIMORegistryChainID)
	// if err != nil {
	// 	return nil, nil, fmt.Errorf("failed to create POM service: %w", err)
	// }

	ctrl, err := httphandlers.NewVCController(vinvcService, nil, settings.TelemetryURL)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create VC controller: %w", err)
	}

	server := rpc.NewServer(vinvcService, settings)

	return ctrl, server, nil

}

func deviceDefAPIClientFromSettings(settings *config.Settings) (ddgrpc.VinDecoderServiceClient, error) {
	conn, err := grpc.NewClient(settings.DefinitionsGRPCAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client: %w", err)
	}
	definitionsClient := ddgrpc.NewVinDecoderServiceClient(conn)
	return definitionsClient, nil
}
