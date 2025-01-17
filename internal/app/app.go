package app

import (
	"errors"
	"strings"

	"github.com/DIMO-Network/attestation-api/internal/config"
	"github.com/DIMO-Network/attestation-api/internal/controllers/httphandlers"
	"github.com/DIMO-Network/attestation-api/internal/controllers/rpc"
	"github.com/DIMO-Network/attestation-api/pkg/auth"
	attgrpc "github.com/DIMO-Network/attestation-api/pkg/grpc"
	"github.com/DIMO-Network/shared/middleware/metrics"
	"github.com/DIMO-Network/shared/middleware/privilegetoken"
	"github.com/DIMO-Network/shared/privileges"
	"github.com/ethereum/go-ethereum/common"
	jwtware "github.com/gofiber/contrib/jwt"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/swagger"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/recovery"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
)

// CreateServers creates a new fiber app and grpc server with the given settings.
func CreateServers(logger *zerolog.Logger, settings *config.Settings) (*fiber.App, *grpc.Server, error) {
	statusRoute := "/v1/vc/status"
	keysRoute := "/v1/vc/keys"
	vocabRoute := "/v1/vc/context/vocab"
	jsonLDRoute := "/v1/vc/context"
	httpCtrl, rpcCtrl, err := createControllers(logger, settings, statusRoute, keysRoute, vocabRoute, jsonLDRoute)
	if err != nil {
		return nil, nil, err
	}
	app := setupHttpServer(logger, settings, httpCtrl, statusRoute, keysRoute, vocabRoute, jsonLDRoute)
	rpc := setupRPCServer(logger, settings, rpcCtrl)
	return app, rpc, nil
}
func setupHttpServer(logger *zerolog.Logger, settings *config.Settings, httpCtrl *httphandlers.HTTPController, statusRoute, keysRoute, vocabRoute, jsonLDRoute string) *fiber.App {
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
	app.Get(statusRoute+"/:"+httphandlers.StatusGroupParam, httpCtrl.GetVCStatus)
	app.Get(keysRoute, httpCtrl.GetPublicKeyDoc)
	app.Get(vocabRoute, httpCtrl.GetVocabDoc)
	app.Get(jsonLDRoute, httpCtrl.GetJSONLDDoc)

	vehicleAddr := common.HexToAddress(settings.VehicleNFTAddress)

	vinMiddleware := auth.AllOf(vehicleAddr, "tokenId", []privileges.Privilege{privileges.VehicleVinCredential})
	app.Post("/v1/vc/vin/:"+httphandlers.TokenIDParam, jwtAuth, vinMiddleware, httpCtrl.GetVINVC)

	pomMiddleware := auth.AllOf(vehicleAddr, "tokenId", []privileges.Privilege{privileges.VehicleAllTimeLocation})
	app.Post("/v1/vc/pom/:"+httphandlers.TokenIDParam, jwtAuth, pomMiddleware, httpCtrl.GetPOMVC)

	return app
}

func setupRPCServer(logger *zerolog.Logger, settings *config.Settings, rpcCtrl *rpc.Server) *grpc.Server {
	grpcPanic := metrics.GRPCPanicker{Logger: logger}
	server := grpc.NewServer(
		grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(
			metrics.GRPCMetricsAndLogMiddleware(logger),
			grpc_ctxtags.UnaryServerInterceptor(),
			grpc_prometheus.UnaryServerInterceptor,
			recovery.UnaryServerInterceptor(recovery.WithRecoveryHandler(grpcPanic.GRPCPanicRecoveryHandler)),
		)),
		grpc.StreamInterceptor(grpc_prometheus.StreamServerInterceptor),
	)
	attgrpc.RegisterAttestationServiceServer(server, rpcCtrl)
	return server
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
