package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"strconv"
	"strings"

	_ "github.com/DIMO-Network/attestation-api/docs"
	"github.com/DIMO-Network/attestation-api/internal/config"
	"github.com/DIMO-Network/attestation-api/internal/controllers/vc"
	"github.com/DIMO-Network/attestation-api/internal/services/fingerprint"
	"github.com/DIMO-Network/attestation-api/internal/services/identity"
	"github.com/DIMO-Network/attestation-api/internal/services/vinvalidator"
	"github.com/DIMO-Network/attestation-api/internal/services/vinvc"
	"github.com/DIMO-Network/attestation-api/pkg/auth"
	"github.com/DIMO-Network/attestation-api/pkg/verifiable"
	"github.com/DIMO-Network/clickhouse-infra/pkg/connect"
	ddgrpc "github.com/DIMO-Network/device-definitions-api/pkg/grpc"
	"github.com/DIMO-Network/shared"
	"github.com/DIMO-Network/shared/middleware/privilegetoken"
	"github.com/DIMO-Network/shared/privileges"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/ethereum/go-ethereum/common"
	jwtware "github.com/gofiber/contrib/jwt"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/swagger"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// @title                       DIMO Attestation API
// @version                     1.0
// @securityDefinitions.apikey  BearerAuth
// @in                          header
// @name                        Authorization
func main() {
	logger := zerolog.New(os.Stdout).With().Timestamp().Str("app", "attestation-api").Logger()
	// create a flag for the settings file
	settingsFile := flag.String("settings", "settings.yaml", "settings file")
	flag.Parse()
	settings, err := shared.LoadConfig[config.Settings](*settingsFile)
	if err != nil {
		logger.Fatal().Err(err).Msg("Couldn't load settings.")
	}

	serveMonitoring(strconv.Itoa(settings.MonPort), &logger)
	startWebAPI(&logger, &settings)
}

func serveMonitoring(port string, logger *zerolog.Logger) *fiber.App {
	logger.Info().Str("port", port).Msg("Starting monitoring web server.")

	monApp := fiber.New(fiber.Config{DisableStartupMessage: true})

	monApp.Get("/", func(*fiber.Ctx) error { return nil })
	monApp.Get("/metrics", adaptor.HTTPHandler(promhttp.Handler()))

	go func() {
		if err := monApp.Listen(":" + port); err != nil {
			logger.Fatal().Err(err).Str("port", port).Msg("Failed to start monitoring web server.")
		}
	}()

	return monApp
}

func startWebAPI(logger *zerolog.Logger, settings *config.Settings) {
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			return ErrorHandler(c, err, logger)
		},
		DisableStartupMessage: true,
	})

	jwtAuth := jwtware.New(jwtware.Config{
		JWKSetURLs: []string{settings.TokenExchangeJWTKeySetURL},
		Claims:     &privilegetoken.Token{},
	})

	vinvcCtrl, err := createVINController(logger, settings)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to create VC controller")
	}

	app.Use(recover.New(recover.Config{
		Next:              nil,
		EnableStackTrace:  true,
		StackTraceHandler: nil,
	}))
	app.Use(cors.New())
	app.Get("/", HealthCheck)

	// add v1 swagger to align with other services
	app.Get("/v1/swagger/*", swagger.HandlerDefault)
	app.Get("/swagger/*", swagger.HandlerDefault)

	// status route for entire vc list
	// status route for individual vc
	app.Get("/v1/vc/status/:"+vc.StatusGroupParam, vinvcCtrl.GetVCStatus)

	vehicleAddr := common.HexToAddress(settings.VehicleNFTAddress)

	vinMiddlewre := auth.AllOf(vehicleAddr, "tokenId", []privileges.Privilege{privileges.VehicleVinCredential})
	app.Get("/v1/vc/vin/:"+vc.TokenIDParam, jwtAuth, vinMiddlewre, vinvcCtrl.GetVINVC)

	logger.Info().Int("port", settings.Port).Msg("Server Started")

	// Start Server
	if err := app.Listen(":" + strconv.Itoa(settings.Port)); err != nil {
		logger.Fatal().Err(err).Msg("Failed to run server")
	}
}

// HealthCheck godoc
// @Summary Show the status of server.
// @Description get the status of server.
// @Tags root
// @Accept */*
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router / [get]
func HealthCheck(ctx *fiber.Ctx) error {
	res := map[string]any{
		"data": "Server is up and running",
	}

	return ctx.JSON(res)
}

// ErrorHandler custom handler to log recovered errors using our logger and return json instead of string
func ErrorHandler(ctx *fiber.Ctx, err error, logger *zerolog.Logger) error {
	code := fiber.StatusInternalServerError // Default 500 statuscode
	message := "Internal error."

	var e *fiber.Error
	if errors.As(err, &e) {
		code = e.Code
		message = e.Message
	}

	// don't log not found errors
	if code != fiber.StatusNotFound {
		logger.Err(err).Int("httpStatusCode", code).
			Str("httpPath", strings.TrimPrefix(ctx.Path(), "/")).
			Str("httpMethod", ctx.Method()).
			Msg("caught an error from http request")
	}

	return ctx.Status(code).JSON(codeResp{Code: code, Message: message})
}

type codeResp struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}

func createVINController(logger *zerolog.Logger, settings *config.Settings) (*vc.Controller, error) {
	// Initialize ClickHouse connection
	chConn, err := connect.GetClickhouseConn(&settings.Clickhouse)
	if err != nil {
		return nil, fmt.Errorf("failed to create ClickHouse connection: %w", err)
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
