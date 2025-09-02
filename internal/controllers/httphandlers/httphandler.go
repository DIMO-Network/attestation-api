package httphandlers

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/DIMO-Network/cloudevent"
	"github.com/gofiber/fiber/v2"
)

const (
	// TokenIDParam is the parameter name for the vehicle token id.
	TokenIDParam = "tokenId"

	// StatusGroupParam is the parameter name for the status group.
	StatusGroupParam = "group"

	vinvcQuery = "query {vinVCLatest(tokenId: %d) {rawVC}}"
	pomQuery   = "query {pomVCLatest(tokenId: %d) {rawVC}}"
)

type getVCResponse struct {
	VCURL   string `json:"vcUrl"`
	VCQuery string `json:"vcQuery"`
	Message string `json:"message"`
}

// HTTPController handles VIN VC-related http requests.
type HTTPController struct {
	vinService               VINVCService
	pomService               POMVCService
	vehiclePositionService   VehiclePositionVCService
	odometerStatementService OdometerStatementVCService
	vehicleHealthService     VehicleHealthVCService
	telemetryBaseURL         *url.URL
}

// VINVCService defines the interface for VIN VC operations.
type VINVCService interface {
	CreateAndStoreVINAttestation(ctx context.Context, tokenID uint32) (*cloudevent.RawEvent, error)
}

type POMVCService interface {
	CreatePOMVC(ctx context.Context, tokenID uint32) error
}

// VehiclePositionVCService defines the interface for VehiclePositionVC operations.
type VehiclePositionVCService interface {
	CreateVehiclePositionVC(ctx context.Context, tokenID uint32, timestamp time.Time, jwtToken string) error
}

// OdometerStatementVCService defines the interface for OdometerStatementVC operations.
type OdometerStatementVCService interface {
	CreateOdometerStatementVC(ctx context.Context, tokenID uint32, timestamp *time.Time, jwtToken string) error
}

// VehicleHealthVCService defines the interface for VehicleHealthVC operations.
type VehicleHealthVCService interface {
	CreateVehicleHealthVC(ctx context.Context, tokenID uint32, startTime, endTime time.Time, jwtToken string) error
}

// NewVCController creates a new http VCController.
func NewVCController(vinService VINVCService, pomService POMVCService, vehiclePositionService VehiclePositionVCService, odometerStatementService OdometerStatementVCService, vehicleHealthService VehicleHealthVCService, telemetryURL string) (*HTTPController, error) {
	parsedURL, err := sanitizeTelemetryURL(telemetryURL)
	if err != nil {
		return nil, err
	}

	return &HTTPController{
		vinService:               vinService,
		pomService:               pomService,
		vehiclePositionService:   vehiclePositionService,
		odometerStatementService: odometerStatementService,
		vehicleHealthService:     vehicleHealthService,
		telemetryBaseURL:         parsedURL,
	}, nil
}

// @Summary Create VIN Attestation
// @Description Generate a new VIN attestation for a given token Id of a vehicle NFT.
// @Tags VINVC
// @Accept json
// @Produce json
// @Param  tokenId path int true "token Id of the vehicle NFT"
// @Success 200 {object} getVCResponse
// @Security     BearerAuth
// @Router /v2/attestation/vin/{tokenId} [post]
func (v *HTTPController) CreateVINAttestation(fiberCtx *fiber.Ctx) error {
	ctx := fiberCtx.Context()
	tokenIDStr := fiberCtx.Params(TokenIDParam)
	if tokenIDStr == "" {
		return fiber.NewError(fiber.StatusBadRequest, "token_id query parameter is required")
	}

	tokenID64, err := strconv.ParseUint(tokenIDStr, 10, 32)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid token_id format")
	}

	tokenID := uint32(tokenID64)
	_, err = v.vinService.CreateAndStoreVINAttestation(ctx, tokenID)
	if err != nil {
		return fmt.Errorf("failed to get or create VC: %w", err)
	}
	return fiberCtx.Status(fiber.StatusOK).JSON(v.successResponse(tokenID, vinvcQuery))
}

// successResponse generates a success response for the given token ID.
func (v *HTTPController) successResponse(tokenID uint32, query string) *getVCResponse {
	queryURL := v.telemetryBaseURL.JoinPath("query")
	gqlQuery := fmt.Sprintf(query, tokenID)
	return &getVCResponse{
		VCURL:   queryURL.String(),
		VCQuery: gqlQuery,
		Message: "VC generated successfully. Retrieve using the provided GQL URL and query parameter.",
	}
}

// sanitizeTelemetryURL parses and sanitizes the given telemetry URL.
func sanitizeTelemetryURL(telemetryURL string) (*url.URL, error) {
	parsedURL, err := url.ParseRequestURI(telemetryURL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		return nil, fmt.Errorf("invalid telemetry URL: %s", telemetryURL)
	}
	return parsedURL, nil
}

// @Summary Create POM VC
// @Description Create a Proof of Movement VC for a given token Id of a vehicle NFT.
// @Tags VINVC
// @Accept json
// @Produce json
// @Param  tokenId path int true "token Id of the vehicle NFT"
// @Success 200 {object} getVCResponse
// @Security     BearerAuth
// @Router /v1/vc/pom/{tokenId} [post]
// func (v *HTTPController) GetPOMVC(fiberCtx *fiber.Ctx) error {
// 	ctx := fiberCtx.Context()
// 	tokenIDStr := fiberCtx.Params(TokenIDParam)
// 	if tokenIDStr == "" {
// 		return fiber.NewError(fiber.StatusBadRequest, "token_id query parameter is required")
// 	}

// 	tokenID64, err := strconv.ParseUint(tokenIDStr, 10, 32)
// 	if err != nil {
// 		return fiber.NewError(fiber.StatusBadRequest, "invalid token_id format")
// 	}

// 	tokenID := uint32(tokenID64)
// 	err = v.pomService.CreatePOMVC(ctx, tokenID)
// 	if err != nil {
// 		return fmt.Errorf("failed to get or create VC: %w", err)
// 	}
// 	return fiberCtx.Status(fiber.StatusOK).JSON(v.successResponse(tokenID, pomQuery))
// }

// CreateVehiclePositionVCRequest represents the request body for creating a VehiclePositionVC.
type CreateVehiclePositionVCRequest struct {
	Timestamp time.Time `json:"timestamp" validate:"required"`
}

// @Summary Create Vehicle Position Attestation
// @Description Generate a new Vehicle Position attestation for a given token Id and timestamp.
// @Tags VehiclePositionVC
// @Accept json
// @Produce json
// @Param  tokenId path int true "token Id of the vehicle NFT"
// @Param  request body CreateVehiclePositionVCRequest true "Request body"
// @Success 200 {object} getVCResponse
// @Security     BearerAuth
// @Router /v2/attestation/vehicle-position/{tokenId} [post]
func (v *HTTPController) CreateVehiclePositionAttestation(fiberCtx *fiber.Ctx) error {
	ctx := fiberCtx.Context()
	tokenIDStr := fiberCtx.Params(TokenIDParam)
	if tokenIDStr == "" {
		return fiber.NewError(fiber.StatusBadRequest, "token_id path parameter is required")
	}

	tokenID64, err := strconv.ParseUint(tokenIDStr, 10, 32)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid token_id format")
	}

	var req CreateVehiclePositionVCRequest
	if err := fiberCtx.BodyParser(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}

	// Extract JWT token from Authorization header
	authHeader := fiberCtx.Get("Authorization")
	jwtToken := ""
	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		jwtToken = strings.TrimPrefix(authHeader, "Bearer ")
	}
	if jwtToken == "" {
		return fiber.NewError(fiber.StatusUnauthorized, "JWT token is required")
	}

	tokenID := uint32(tokenID64)
	err = v.vehiclePositionService.CreateVehiclePositionVC(ctx, tokenID, req.Timestamp, jwtToken)
	if err != nil {
		return fmt.Errorf("failed to create VehiclePositionVC: %w", err)
	}

	vehiclePositionQuery := fmt.Sprintf("query {vehiclePositionVCLatest(tokenId: %d) {rawVC}}", tokenID)
	return fiberCtx.Status(fiber.StatusOK).JSON(v.successResponse(tokenID, vehiclePositionQuery))
}

// CreateOdometerStatementVCRequest represents the request body for creating an OdometerStatementVC.
type CreateOdometerStatementVCRequest struct {
	Timestamp *time.Time `json:"timestamp,omitempty"` // Optional timestamp
}

// @Summary Create Odometer Statement Attestation
// @Description Generate a new Odometer Statement attestation for a given token Id. If timestamp is not provided, uses the latest odometer reading.
// @Tags OdometerStatementVC
// @Accept json
// @Produce json
// @Param  tokenId path int true "token Id of the vehicle NFT"
// @Param  request body CreateOdometerStatementVCRequest false "Request body"
// @Success 200 {object} getVCResponse
// @Security     BearerAuth
// @Router /v2/attestation/odometer-statement/{tokenId} [post]
func (v *HTTPController) CreateOdometerStatementAttestation(fiberCtx *fiber.Ctx) error {
	ctx := fiberCtx.Context()
	tokenIDStr := fiberCtx.Params(TokenIDParam)
	if tokenIDStr == "" {
		return fiber.NewError(fiber.StatusBadRequest, "token_id path parameter is required")
	}

	tokenID64, err := strconv.ParseUint(tokenIDStr, 10, 32)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid token_id format")
	}

	var req CreateOdometerStatementVCRequest
	// Body is optional for this endpoint
	_ = fiberCtx.BodyParser(&req)

	// Extract JWT token from Authorization header
	authHeader := fiberCtx.Get("Authorization")
	jwtToken := ""
	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		jwtToken = strings.TrimPrefix(authHeader, "Bearer ")
	}
	if jwtToken == "" {
		return fiber.NewError(fiber.StatusUnauthorized, "JWT token is required")
	}

	tokenID := uint32(tokenID64)
	err = v.odometerStatementService.CreateOdometerStatementVC(ctx, tokenID, req.Timestamp, jwtToken)
	if err != nil {
		return fmt.Errorf("failed to create OdometerStatementVC: %w", err)
	}

	odometerQuery := fmt.Sprintf("query {odometerStatementVCLatest(tokenId: %d) {rawVC}}", tokenID)
	return fiberCtx.Status(fiber.StatusOK).JSON(v.successResponse(tokenID, odometerQuery))
}

// CreateVehicleHealthVCRequest represents the request body for creating a VehicleHealthVC.
type CreateVehicleHealthVCRequest struct {
	StartTime time.Time `json:"startTime" validate:"required"`
	EndTime   time.Time `json:"endTime" validate:"required"`
}

// @Summary Create Vehicle Health Attestation
// @Description Generate a new Vehicle Health attestation for a given token Id and time range. The time range cannot exceed 30 days.
// @Tags VehicleHealthVC
// @Accept json
// @Produce json
// @Param  tokenId path int true "token Id of the vehicle NFT"
// @Param  request body CreateVehicleHealthVCRequest true "Request body"
// @Success 200 {object} getVCResponse
// @Security     BearerAuth
// @Router /v2/attestation/vehicle-health/{tokenId} [post]
func (v *HTTPController) CreateVehicleHealthAttestation(fiberCtx *fiber.Ctx) error {
	ctx := fiberCtx.Context()
	tokenIDStr := fiberCtx.Params(TokenIDParam)
	if tokenIDStr == "" {
		return fiber.NewError(fiber.StatusBadRequest, "token_id path parameter is required")
	}

	tokenID64, err := strconv.ParseUint(tokenIDStr, 10, 32)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid token_id format")
	}

	var req CreateVehicleHealthVCRequest
	if err := fiberCtx.BodyParser(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}

	// Validate time range
	if req.StartTime.After(req.EndTime) {
		return fiber.NewError(fiber.StatusBadRequest, "startTime must be before endTime")
	}

	// Validate time range is not more than 30 days
	maxDuration := 30 * 24 * time.Hour
	if req.EndTime.Sub(req.StartTime) > maxDuration {
		return fiber.NewError(fiber.StatusBadRequest, "time range cannot exceed 30 days")
	}

	// Extract JWT token from Authorization header
	authHeader := fiberCtx.Get("Authorization")
	jwtToken := ""
	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		jwtToken = strings.TrimPrefix(authHeader, "Bearer ")
	}
	if jwtToken == "" {
		return fiber.NewError(fiber.StatusUnauthorized, "JWT token is required")
	}

	tokenID := uint32(tokenID64)
	err = v.vehicleHealthService.CreateVehicleHealthVC(ctx, tokenID, req.StartTime, req.EndTime, jwtToken)
	if err != nil {
		return fmt.Errorf("failed to create VehicleHealthVC: %w", err)
	}

	vehicleHealthQuery := fmt.Sprintf("query {vehicleHealthVCLatest(tokenId: %d) {rawVC}}", tokenID)
	return fiberCtx.Status(fiber.StatusOK).JSON(v.successResponse(tokenID, vehicleHealthQuery))
}
