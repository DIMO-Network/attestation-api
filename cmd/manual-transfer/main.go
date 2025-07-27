package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"slices"
	"strings"
	"syscall"
	"time"

	// import docs for swagger generation.
	_ "github.com/DIMO-Network/attestation-api/docs"
	"github.com/DIMO-Network/attestation-api/internal/attestation/apis/identity"
	"github.com/DIMO-Network/attestation-api/internal/attestation/repos/fingerprint"
	"github.com/DIMO-Network/attestation-api/internal/attestation/repos/vcrepo"
	"github.com/DIMO-Network/attestation-api/internal/attestation/vinvc"
	"github.com/DIMO-Network/attestation-api/internal/client/dex"
	"github.com/DIMO-Network/attestation-api/internal/client/fetchapi"
	"github.com/DIMO-Network/attestation-api/internal/client/tokencache"
	"github.com/DIMO-Network/attestation-api/internal/config"
	"github.com/DIMO-Network/attestation-api/internal/sources"
	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/fetch-api/pkg/grpc"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const vinVCDataVersion = "VINVCv1.0"

// @title                       DIMO Attestation API
// @version                     1.0
// @securityDefinitions.apikey  BearerAuth
// @in                          header
// @name                        Authorization
func main() {
	logger := zerolog.New(os.Stdout).With().Timestamp().Str("app", "manual-transfer").Logger()
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && len(s.Value) == 40 {
				logger = logger.With().Str("commit", s.Value[:7]).Logger()
				break
			}
		}
	}
	zerolog.DefaultContextLogger = &logger

	mainCtx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	go func() {
		<-mainCtx.Done()
		logger.Info().Msg("Received signal, shutting down...")
		cancel()
	}()

	// create flags for the settings file and subject list
	settingsFile := flag.String("settings", "settings.yaml", "settings file")
	flag.Parse()

	settings, err := config.LoadSettings(*settingsFile)
	if err != nil {
		logger.Fatal().Err(err).Msg("Couldn't load settings.")
	}

	subjects := strings.Split(settings.SubjectsList, ",")
	slices.Sort(subjects)

	// Initialize stats
	stats := &TransferStats{
		TotalSubjects:  len(settings.SubjectsList),
		StartTime:      time.Now(),
		LastUpdateTime: time.Now(),
	}

	// Start stats server
	go startStatsServer(settings.MonPort, stats, logger)

	err = run(mainCtx, &logger, settings, stats, subjects)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to run")
	}
	logger.Info().Msg("Finished")
}

func run(ctx context.Context, logger *zerolog.Logger, settings *config.Settings, stats *TransferStats, subjects []string) error {
	fetchAPIClient := fetchapi.New(settings)

	privateKey, err := crypto.HexToECDSA(settings.SignerPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to decode private key: %w", err)
	}

	// Initialize fingerprint repository
	fingerprintRepo := fingerprint.New(fetchAPIClient)

	dexClient, err := dex.NewClient(settings)
	if err != nil {
		return fmt.Errorf("failed to create dex client: %w", err)
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
		return fmt.Errorf("failed to create VC repository: %w", err)
	}

	// Initialize identity API client
	identityAPI, err := identity.NewService(settings.IdentityAPIURL, settings.AfterMarketNFTAddress, settings.SyntheticNFTAddress, nil)
	if err != nil {
		return fmt.Errorf("failed to create identity service: %w", err)
	}

	// Initialize VC service using the initialized services
	vinvcService := vinvc.NewService(logger, vcRepo, identityAPI, fingerprintRepo, nil, settings, privateKey)

	group, ctx := errgroup.WithContext(ctx)
	if settings.ConcurrencyLimit == 0 {
		settings.ConcurrencyLimit = 1
	}
	group.SetLimit(settings.ConcurrencyLimit)
	producer := cloudevent.EthrDID{
		ChainID:         uint64(settings.DIMORegistryChainID),
		ContractAddress: sources.DINCSource,
	}.String()

	for _, subject := range subjects {
		subject := subject // capture loop variable
		stats.SetCurrentSubject(subject)

		group.Go(func() error {
			stats.IncrementProcessed()

			hasNewVC, err := hasNewVC(ctx, fetchAPIClient, subject, producer, settings)
			if err != nil {
				errorMsg := fmt.Sprintf("failed to check if there is a new VC for %s: %v", subject, err)
				stats.AddError(errorMsg)
				stats.IncrementFailed(subject)
				return fmt.Errorf(errorMsg)
			}
			if !hasNewVC {
				logger.Info().Str("subject", subject).Msg("No new VC found, skipping")
				stats.IncrementSkipped()
				return nil
			}

			// get last manual VINVC
			vinVCEvent, err := getVINVC(ctx, fetchAPIClient, subject, producer)
			if err != nil {
				errorMsg := fmt.Sprintf("failed to get last manual VINVC for %s: %v", subject, err)
				stats.AddError(errorMsg)
				stats.IncrementFailed(subject)
				return nil
			}

			cred := Credential{}
			if err := json.Unmarshal(vinVCEvent.Data, &cred); err != nil {
				errorMsg := fmt.Sprintf("failed to unmarshal VIN VC for %s: %v", subject, err)
				stats.AddError(errorMsg)
				stats.IncrementFailed(subject)
				return nil
			}

			_, err = vinvcService.CreateManualVINAttestation(ctx, cred.CredentialSubject.VehicleTokenID, cred.CredentialSubject.VehicleIdentificationNumber, cred.CredentialSubject.CountryCode)
			if err != nil {
				errorMsg := fmt.Sprintf("failed to create manual VIN VC for %s: %v", subject, err)
				stats.AddError(errorMsg)
				stats.IncrementFailed(subject)
				return nil
			}

			logger.Info().Str("subject", subject).Msg("Successfully processed manual VIN VC")
			stats.IncrementSuccessful()
			return nil
		})
	}

	return group.Wait()
}

func getVINVC(ctx context.Context, fetchAPIClient *fetchapi.FetchAPIService, vehicleDID string, producer string) (cloudevent.RawEvent, error) {
	opts := &grpc.SearchOptions{
		DataVersion: &wrapperspb.StringValue{Value: vinVCDataVersion},
		Type:        &wrapperspb.StringValue{Value: cloudevent.TypeVerifableCredential},
		Subject:     &wrapperspb.StringValue{Value: vehicleDID},
		Producer:    &wrapperspb.StringValue{Value: producer},
	}
	dataObj, err := fetchAPIClient.GetLatestCloudEvent(ctx, opts)
	if err != nil {
		return cloudevent.RawEvent{}, fmt.Errorf("failed to get latest VIN VC data: %w", err)
	}
	return dataObj, nil
}
func hasNewVC(ctx context.Context, fetchAPIClient *fetchapi.FetchAPIService, vehicleDID string, producer string, settings *config.Settings) (bool, error) {
	opts := &grpc.SearchOptions{
		DataVersion: &wrapperspb.StringValue{Value: settings.VINDataVersion},
		Type:        &wrapperspb.StringValue{Value: cloudevent.TypeAttestation},
		Subject:     &wrapperspb.StringValue{Value: vehicleDID},
		Producer:    &wrapperspb.StringValue{Value: producer},
	}
	_, err := fetchAPIClient.GetLatestIndex(ctx, opts)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return false, nil
		}
		return false, fmt.Errorf("failed to get latest VIN VC data: %w", err)
	}
	return true, nil
}

// Credential represents a verifiable credential.
type Credential struct {
	ValidFrom         time.Time  `json:"validFrom,omitempty"`
	ValidTo           time.Time  `json:"validTo,omitempty"`
	CredentialSubject VINSubject `json:"credentialSubject,omitempty"`
}

// VINSubject represents the subject of the VIN verifiable credential.
type VINSubject struct {
	VehicleDID string `json:"id,omitempty"`
	// VehicleTokenID is the token ID of the vehicle NFT.
	VehicleTokenID uint32 `json:"vehicleTokenId,omitempty"`
	// VehicleContractAddress is the address of the vehicle contract.
	VehicleContractAddress string `json:"vehicleContractAddress,omitempty"`
	// VehicleIdentificationNumber is the VIN of the vehicle.
	VehicleIdentificationNumber string `json:"vehicleIdentificationNumber,omitempty"`
	// RecordedBy is the entity that recorded the VIN.
	RecordedBy string `json:"recordedBy,omitempty"`
	// RecordedAt is the time the VIN was recorded.
	RecordedAt time.Time `json:"recordedAt,omitempty"`
	// CountryCode that VIN belongs to.
	CountryCode string `json:"countryCode,omitempty"`
}
