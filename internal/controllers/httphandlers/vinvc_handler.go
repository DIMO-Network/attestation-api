package httphandlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"

	//  import verifable for swagger docs
	_ "github.com/DIMO-Network/attestation-api/pkg/verifiable"
	"github.com/gofiber/fiber/v2"
)

const (
	// TokenIDParam is the parameter name for the vehilce token ID.
	TokenIDParam = "tokenId"

	// StatusGroupParam is the parameter name for the status group.
	StatusGroupParam = "group"
)

type getVINVCResponse struct {
	VCURL   string `json:"vcUrl"`
	VCQuery string `json:"vcQuery"`
	Message string `json:"message"`
}

// VINVCController handles VIN VC-related http requests.
type VINVCController struct {
	vinService       VINVCService
	telemetryBaseURL *url.URL
	publicKeyDoc     json.RawMessage
}

// VINVCService defines the interface for VIN VC operations.
type VINVCService interface {
	GetOrCreateVC(ctx context.Context, tokenID uint32, force bool) error
	GenerateStatusVC(tokenID uint32) (json.RawMessage, error)
	GenerateKeyControlDocument() (json.RawMessage, error)
}

// NewVCController creates a new http VCController.
func NewVCController(vinService VINVCService, telemetryURL string) (*VINVCController, error) {
	parsedURL, err := sanitizeTelemetryURL(telemetryURL)
	if err != nil {
		return nil, err
	}

	publicKeyDoc, err := vinService.GenerateKeyControlDocument()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key control document: %w", err)
	}
	return &VINVCController{
		publicKeyDoc:     publicKeyDoc,
		vinService:       vinService,
		telemetryBaseURL: parsedURL,
	}, nil
}

// @Summary Get VIN VC
// @Description Get the VIN VC for a given token Id of a vehicle NFT. If a unexpired VC is not found, a new VC is generated.
// @Tags VINVC
// @Accept json
// @Produce json
// @Param  tokenId path int true "token Id of the vehicle NFT"
// @Param  force query bool false "force generation of a new VC even if an unexpired VC exists"
// @Success 200 {object} getVINVCResponse
// @Security     BearerAuth
// @Router /v1/vc/vin/{tokenId} [get]
func (v *VINVCController) GetVINVC(fiberCtx *fiber.Ctx) error {
	ctx := fiberCtx.Context()
	tokenIDStr := fiberCtx.Params(TokenIDParam)
	if tokenIDStr == "" {
		return fiber.NewError(fiber.StatusBadRequest, "token_id query parameter is required")
	}

	tokenID64, err := strconv.ParseUint(tokenIDStr, 10, 32)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid token_id format")
	}
	force := fiberCtx.Query("force") == "true"

	tokenID := uint32(tokenID64)
	err = v.vinService.GetOrCreateVC(ctx, tokenID, force)
	if err != nil {
		return fmt.Errorf("failed to get or create VC: %w", err)
	}
	return fiberCtx.Status(fiber.StatusOK).JSON(v.successResponse(tokenID))
}

// @Summary Get VC Status
// @Description Get the VC status for a given status group (currently this is just the vehcilesTokenId)
// @Tags VINVC
// @Accept json
// @Produce json
// @Param  group path int true "status list group"
// @Success 200 {object} verifiable.Credential
// @Router /v1/vc/status/{group} [get]
func (v *VINVCController) GetVCStatus(fiberCtx *fiber.Ctx) error {
	tokenIDStr := fiberCtx.Params(StatusGroupParam)
	if tokenIDStr == "" {
		return fiber.NewError(fiber.StatusBadRequest, "tokenId path parameter is required")
	}

	tokenID64, err := strconv.ParseUint(tokenIDStr, 10, 32)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid tokenId format")
	}

	tokenID := uint32(tokenID64)
	statusVC, err := v.vinService.GenerateStatusVC(tokenID)
	if err != nil {
		return fmt.Errorf("failed to generate status VC: %w", err)
	}
	return fiberCtx.Status(fiber.StatusOK).JSON(statusVC)
}

// @Summary Get verification control document
// @Description Returns the public key document for verifying VCs.
// @Tags VINVC
// @Accept json
// @Produce json
// @Success 200 {object} verifiable.VerificationControlDocument
// @Router /v1/vc/keys [get]
func (v *VINVCController) GetPublicKeyDoc(fiberCtx *fiber.Ctx) error {
	return fiberCtx.Status(fiber.StatusOK).JSON(v.publicKeyDoc)
}

// successResponse generates a success response for the given token ID.
func (v *VINVCController) successResponse(tokenID uint32) *getVINVCResponse {
	queryURL := v.telemetryBaseURL.JoinPath("query")
	gqlQuery := fmt.Sprintf("query {vinVCLatest(tokenId: %d) {rawVC}}", tokenID)
	return &getVINVCResponse{
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
