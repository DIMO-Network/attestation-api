package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"syscall"

	// import docs for swagger generation.
	_ "github.com/DIMO-Network/attestation-api/docs"
	"github.com/DIMO-Network/attestation-api/internal/app"
	"github.com/DIMO-Network/attestation-api/internal/config"
	"github.com/DIMO-Network/server-garage/pkg/monserver"
	"github.com/DIMO-Network/server-garage/pkg/runner"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"
)

// @title                       DIMO Attestation API
// @version                     1.0
// @securityDefinitions.apikey  BearerAuth
// @in                          header
// @name                        Authorization
func main() {
	logger := zerolog.New(os.Stdout).With().Timestamp().Str("app", "attestation-api").Logger()
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

	runnerGroup, runnerCtx := errgroup.WithContext(mainCtx)
	// create a flag for the settings file
	settingsFile := flag.String("settings", "settings.yaml", "settings file")
	flag.Parse()
	settings, err := config.LoadSettings(*settingsFile)
	if err != nil {
		logger.Fatal().Err(err).Msg("Couldn't load settings.")
	}

	monApp := monserver.NewMonitoringServer(&logger, settings.EnablePprof)
	logger.Info().Str("port", strconv.Itoa(settings.MonPort)).Msgf("Starting monitoring server")
	runner.RunHandler(runnerCtx, runnerGroup, monApp, ":"+strconv.Itoa(settings.MonPort))

	webServer, rpcServer, err := app.CreateServers(&logger, settings)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to create servers.")
	}

	logger.Info().Str("port", strconv.Itoa(settings.Port)).Msgf("Starting web server")
	runner.RunFiber(runnerCtx, runnerGroup, webServer, ":"+strconv.Itoa(settings.Port))

	logger.Info().Str("port", strconv.Itoa(settings.GRPCPort)).Msgf("Starting gRPC server")
	runner.RunGRPC(runnerCtx, runnerGroup, rpcServer, ":"+strconv.Itoa(settings.GRPCPort))

	err = runnerGroup.Wait()
	if err != nil && !errors.Is(err, context.Canceled) {
		logger.Fatal().Err(err).Msg("Server shut down due to an error.")
	}
	logger.Info().Msg("Server shut down.")
}
