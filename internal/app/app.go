package app

import (
	"errors"
	"strconv"
	"strings"

	"github.com/DIMO-Network/attestation-api/internal/config"
	"github.com/DIMO-Network/attestation-api/internal/controllers/httphandlers"
	"github.com/DIMO-Network/attestation-api/pkg/auth"
	"github.com/DIMO-Network/shared/middleware/privilegetoken"
	"github.com/DIMO-Network/shared/privileges"
	"github.com/ethereum/go-ethereum/common"
	jwtware "github.com/gofiber/contrib/jwt"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/swagger"
	"github.com/rs/zerolog"
)

func StartWebAPI(logger *zerolog.Logger, settings *config.Settings) {
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
	statusRoute := "/v1/vc/status"
	keysRoute := "/v1/vc/keys"
	vocabRoute := "/v1/vc/context/vocab"
	jsonLDRoute := "/v1/vc/context"
	vinvcService, err := createVINCService(logger, settings, statusRoute, keysRoute, vocabRoute, jsonLDRoute)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to create VC service")
	}

	httpHandler, err := httphandlers.NewVCController(vinvcService, settings.TelemetryURL)
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

	// unauthenticated routes for vc
	app.Get(statusRoute+"/:"+httphandlers.StatusGroupParam, httpHandler.GetVCStatus)
	app.Get(keysRoute, httpHandler.GetPublicKeyDoc)
	app.Get(vocabRoute, httpHandler.GetVocabDoc)
	app.Get(jsonLDRoute, httpHandler.GetJSONLDDoc)

	vehicleAddr := common.HexToAddress(settings.VehicleNFTAddress)

	vinMiddleware := auth.AllOf(vehicleAddr, "tokenId", []privileges.Privilege{privileges.VehicleVinCredential})
	app.Post("/v1/vc/vin/:"+httphandlers.TokenIDParam, jwtAuth, vinMiddleware, httpHandler.GetVINVC)

	logger.Info().Int("port", settings.Port).Msg("Server Started")

	// Start Server
	if err := app.Listen(":" + strconv.Itoa(settings.Port)); err != nil {
		logger.Fatal().Err(err).Msg("Failed to run server")
	}
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
