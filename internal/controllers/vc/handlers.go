package vc

import (
	"fmt"
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

// @Summary Get VIN VC
// @Description Get the VIN VC for a given token Id of a vehicle NFT. If a unexpired VC is not found, a new VC is generated.
// @Tags VINVC
// @Accept json
// @Produce json
// @Param  tokenId path int true "token Id of the vehicle NFT"
// @Success 200 {object} getVINVCResponse
// @Security     BearerAuth
// @Router /v1/vc/vin/{tokenId} [get]
func (v *Controller) GetVINVC(fiberCtx *fiber.Ctx) error {
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
	retObj, err := v.getVINVC(ctx, tokenID)
	if err != nil {
		return err
	}
	return fiberCtx.Status(fiber.StatusOK).JSON(retObj)
}

// @Summary Get VC Status
// @Description Get the VC status for a given status group (currently this is just the vehcilesTokenId)
// @Tags VINVC
// @Accept json
// @Produce json
// @Param  group path int true "status list group"
// @Success 200 {object} verifiable.Credential
// @Security     BearerAuth
// @Router /v1/vc/status/{group} [get]
func (v *Controller) GetVCStatus(fiberCtx *fiber.Ctx) error {
	tokenIDStr := fiberCtx.Params(StatusGroupParam)
	if tokenIDStr == "" {
		return fiber.NewError(fiber.StatusBadRequest, "tokenId path parameter is required")
	}

	tokenID64, err := strconv.ParseUint(tokenIDStr, 10, 32)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid tokenId format")
	}

	tokenID := uint32(tokenID64)
	statusVC, err := v.vcService.GenerateStatusVC(tokenID)
	if err != nil {
		return fmt.Errorf("failed to generate status VC: %w", err)
	}
	return fiberCtx.Status(fiber.StatusOK).JSON(statusVC)
}
