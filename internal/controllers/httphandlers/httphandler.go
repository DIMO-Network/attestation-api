package httphandlers

import (
	"context"
	"fmt"
	"net/url"
	"strconv"

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
	vinService       VINVCService
	pomService       POMVCService
	telemetryBaseURL *url.URL
}

// VINVCService defines the interface for VIN VC operations.
type VINVCService interface {
	CreateAndStoreVINAttestation(ctx context.Context, tokenID uint32) (*cloudevent.RawEvent, error)
}

type POMVCService interface {
	CreatePOMVC(ctx context.Context, tokenID uint32) error
}

// NewVCController creates a new http VCController.
func NewVCController(vinService VINVCService, pomService POMVCService, telemetryURL string) (*HTTPController, error) {
	parsedURL, err := sanitizeTelemetryURL(telemetryURL)
	if err != nil {
		return nil, err
	}

	return &HTTPController{
		vinService:       vinService,
		pomService:       pomService,
		telemetryBaseURL: parsedURL,
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
