package vc

import (
	"fmt"
	"strconv"

	"github.com/gofiber/fiber/v2"
)

const (
	// TokenIDParam is the parameter name for the vehilce token ID.
	TokenIDParam = "tokenId"
)

type getVINVCResponse struct {
	VCURL   string `json:"vcUrl"`
	VCQuery string `json:"vcQuery"`
	Message string `json:"message"`
}

// @Summary Get VIN VC
// @Description Get the VIN VC for a given token Id
// @Tags VC
// @Accept json
// @Produce json
// @Param  tokenId path int true "token Id"
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

func (v *Controller) GetVCStatus(fiberCtx *fiber.Ctx) error {
	tokenIDStr := fiberCtx.Params(TokenIDParam)
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
