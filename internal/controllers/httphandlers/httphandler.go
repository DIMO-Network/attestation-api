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
	publicKeyDoc     json.RawMessage
	jsonLDDoc        json.RawMessage
	vocabDoc         json.RawMessage
}

// VINVCService defines the interface for VIN VC operations.
type VINVCService interface {
	GetOrCreateVC(ctx context.Context, tokenID uint32, force bool) (json.RawMessage, error)
	GenerateStatusVC(tokenID uint32) (json.RawMessage, error)
	GenerateKeyControlDocument() (json.RawMessage, error)
	GenerateJSONLDDocument() (json.RawMessage, error)
	GenerateVocabDocument() (json.RawMessage, error)
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

	publicKeyDoc, err := vinService.GenerateKeyControlDocument()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key control document: %w", err)
	}

	jsonLDDoc, err := vinService.GenerateJSONLDDocument()
	if err != nil {
		return nil, fmt.Errorf("failed to generate JSON-LD document: %w", err)
	}

	vocabDoc, err := vinService.GenerateVocabDocument()
	if err != nil {
		return nil, fmt.Errorf("failed to generate vocabulary document: %w", err)
	}

	return &HTTPController{
		publicKeyDoc:     publicKeyDoc,
		vinService:       vinService,
		pomService:       pomService,
		telemetryBaseURL: parsedURL,
		jsonLDDoc:        jsonLDDoc,
		vocabDoc:         vocabDoc,
	}, nil
}

// @Summary Get VIN VC
// @Description Get the VIN VC for a given token Id of a vehicle NFT. If a unexpired VC is not found, a new VC is generated.
// @Tags VINVC
// @Accept json
// @Produce json
// @Param  tokenId path int true "token Id of the vehicle NFT"
// @Param  force query bool false "force generation of a new VC even if an unexpired VC exists"
// @Success 200 {object} getVCResponse
// @Security     BearerAuth
// @Router /v1/vc/vin/{tokenId} [post]
func (v *HTTPController) GetVINVC(fiberCtx *fiber.Ctx) error {
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
	_, err = v.vinService.GetOrCreateVC(ctx, tokenID, force)
	if err != nil {
		return fmt.Errorf("failed to get or create VC: %w", err)
	}
	return fiberCtx.Status(fiber.StatusOK).JSON(v.successResponse(tokenID, vinvcQuery))
}

// @Summary Get VC Status
// @Description Get the VC status for a given status group (currently this is just the vehcilesTokenId)
// @Tags VINVC
// @Accept json
// @Produce json
// @Param  group path int true "status list group"
// @Success 200 {object} verifiable.Credential
// @Router /v1/vc/status/{group} [get]
func (v *HTTPController) GetVCStatus(fiberCtx *fiber.Ctx) error {
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
func (v *HTTPController) GetPublicKeyDoc(fiberCtx *fiber.Ctx) error {
	return fiberCtx.Status(fiber.StatusOK).JSON(v.publicKeyDoc)
}

// @Summary Get JSON-LD document
// @Description Returns the JSON-LD document for all VC types.
// @Tags VINVC
// @Accept json
// @Produce json
// @Success 200 {object} json.RawMessage
// @Router /v1/vc/context [get]
func (v *HTTPController) GetJSONLDDoc(fiberCtx *fiber.Ctx) error {
	return fiberCtx.Status(fiber.StatusOK).JSON(v.jsonLDDoc)
}

// @Summary Get vocabulary document
// @Description Returns the vocabulary document for all VC types.
// @Tags VINVC
// @Accept json
// @Produce html
// @Success 200 {string} string
// @Router /v1/vc/context/vocab [get]
func (v *HTTPController) GetVocabDoc(fiberCtx *fiber.Ctx) error {
	fiberCtx.Set(fiber.HeaderContentType, fiber.MIMETextHTML)
	return fiberCtx.Send(v.vocabDoc)
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
func (v *HTTPController) GetPOMVC(fiberCtx *fiber.Ctx) error {
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
	err = v.pomService.CreatePOMVC(ctx, tokenID)
	if err != nil {
		return fmt.Errorf("failed to get or create VC: %w", err)
	}
	return fiberCtx.Status(fiber.StatusOK).JSON(v.successResponse(tokenID, pomQuery))
}
