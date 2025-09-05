package app

import (
	"github.com/DIMO-Network/attestation-api/internal/config"
	"github.com/DIMO-Network/attestation-api/internal/controllers/httphandlers"
	"github.com/DIMO-Network/attestation-api/internal/controllers/rpc"
	"github.com/DIMO-Network/attestation-api/pkg/auth"
	attgrpc "github.com/DIMO-Network/attestation-api/pkg/grpc"
	"github.com/DIMO-Network/server-garage/pkg/fibercommon"
	"github.com/DIMO-Network/shared/pkg/middleware/metrics"
	"github.com/DIMO-Network/shared/pkg/middleware/privilegetoken"
	"github.com/DIMO-Network/shared/pkg/privileges"
	"github.com/ethereum/go-ethereum/common"
	jwtware "github.com/gofiber/contrib/jwt"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/redirect"
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
	httpCtrl, rpcCtrl, err := createControllers(logger, settings)
	if err != nil {
		return nil, nil, err
	}
	app := setupHttpServer(logger, settings, httpCtrl)
	rpc := setupRPCServer(logger, rpcCtrl)
	return app, rpc, nil
}
func setupHttpServer(logger *zerolog.Logger, settings *config.Settings, httpCtrl *httphandlers.HTTPController) *fiber.App {
	app := fiber.New(fiber.Config{
		ErrorHandler:          fibercommon.ErrorHandler,
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

	vehicleAddr := common.HexToAddress(settings.VehicleNFTAddress)

	vinMiddleware := auth.AllOf(vehicleAddr, httphandlers.TokenIDParam, []privileges.Privilege{privileges.VehicleVinCredential})
	// redirect v1 to v2
	app.Use(redirect.New(redirect.Config{
		Rules: map[string]string{
			"/v1/vc/vin/*": "/v2/attestation/vin/$1",
		},
		StatusCode: fiber.StatusTemporaryRedirect,
	}))
	app.Post("/v2/attestation/vin/:"+httphandlers.TokenIDParam, jwtAuth, vinMiddleware, httpCtrl.CreateVINAttestation)

	// Vehicle position attestation endpoint
	locationMiddleware := auth.AllOf(vehicleAddr, httphandlers.TokenIDParam, []privileges.Privilege{privileges.VehicleAllTimeLocation})
	app.Post("/v2/attestation/vehicle-position/:"+httphandlers.TokenIDParam, jwtAuth, locationMiddleware, httpCtrl.CreateVehiclePositionAttestation)

	// Odometer and health attestation endpoints
	// OdometerStatement requires basic vehicle access
	odometerMiddleware := auth.AllOf(vehicleAddr, httphandlers.TokenIDParam, []privileges.Privilege{privileges.VehicleNonLocationData})
	app.Post("/v2/attestation/odometer-statement/:"+httphandlers.TokenIDParam, jwtAuth, odometerMiddleware, httpCtrl.CreateOdometerStatementAttestation)

	// VehicleHealth requires location privilege as it includes health data over time
	healthMiddleware := auth.AllOf(vehicleAddr, httphandlers.TokenIDParam, []privileges.Privilege{privileges.VehicleNonLocationData, privileges.VehicleAllTimeLocation})
	app.Post("/v2/attestation/vehicle-health/:"+httphandlers.TokenIDParam, jwtAuth, healthMiddleware, httpCtrl.CreateVehicleHealthAttestation)

	return app
}

func setupRPCServer(logger *zerolog.Logger, rpcCtrl *rpc.Server) *grpc.Server {
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
