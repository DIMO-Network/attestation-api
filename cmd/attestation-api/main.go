package main

import (
	"errors"
	"flag"
	"os"
	"strconv"
	"strings"

	"github.com/DIMO-Network/attestation-api/internal/config"
	"github.com/DIMO-Network/attestation-api/internal/controllers/vc"
	"github.com/DIMO-Network/shared"
	"github.com/DIMO-Network/shared/middleware/privilegetoken"
	"github.com/DIMO-Network/shared/privileges"
	"github.com/ethereum/go-ethereum/common"
	jwtware "github.com/gofiber/contrib/jwt"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/swagger"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
)

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
	startWebAPI(logger, &settings)
}

func serveMonitoring(port string, logger *zerolog.Logger) *fiber.App {
	logger.Info().Str("port", port).Msg("Starting monitoring web server.")

	monApp := fiber.New(fiber.Config{DisableStartupMessage: true})

	monApp.Get("/", func(c *fiber.Ctx) error { return nil })
	monApp.Get("/metrics", adaptor.HTTPHandler(promhttp.Handler()))

	go func() {
		if err := monApp.Listen(":" + port); err != nil {
			logger.Fatal().Err(err).Str("port", port).Msg("Failed to start monitoring web server.")
		}
	}()

	return monApp
}

func startWebAPI(logger zerolog.Logger, settings *config.Settings) {
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			return ErrorHandler(c, err, logger)
		},
		DisableStartupMessage: true,
	})

	jwtAuth := jwtware.New(jwtware.Config{
		JWKSetURLs: []string{settings.TokenExchangeJWTKeySetURL},
		Claims:     privilegetoken.Token{},
	})

	vinvcCtrl, err := vc.NewVCController(&logger, nil, nil, nil, nil, settings.TelemetryURL)
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
	app.Get("/v1/swagger/*", swagger.HandlerDefault)

	vehicleAddr := common.HexToAddress(settings.VehicleNFTAddress)

	v1 := app.Group("/v1", jwtAuth, AllOf(vehicleAddr, []privileges.Privilege{privileges.VehicleVinCredential}))
	v1.Get("/vc/vin", vinvcCtrl.GetVINVC)

	logger.Info().Int("port", settings.Port).Msg("Server Started")

	// Start Server
	if err := app.Listen(":" + strconv.Itoa(settings.Port)); err != nil {
		logger.Fatal().Err(err)
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
func HealthCheck(c *fiber.Ctx) error {
	res := map[string]interface{}{
		"data": "Server is up and running",
	}

	if err := c.JSON(res); err != nil {
		return err
	}

	return nil
}

// ErrorHandler custom handler to log recovered errors using our logger and return json instead of string
func ErrorHandler(c *fiber.Ctx, err error, logger zerolog.Logger) error {
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
			Str("httpPath", strings.TrimPrefix(c.Path(), "/")).
			Str("httpMethod", c.Method()).
			Msg("caught an error from http request")
	}

	return c.Status(code).JSON(CodeResp{Code: code, Message: message})
}

type CodeResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}
