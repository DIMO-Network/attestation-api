package vc

import (
	"fmt"
	"strconv"

	"github.com/gofiber/fiber/v2"
)

const (
	// TokenIDParam is the parameter name for the vehilce token ID.
	TokenIDParam = "vehilceTokenID"
)

// GetVINVC handles requests to issue a VIN VC.
func (v *VCController) GetVINVC(fiberCtx *fiber.Ctx) error {
	ctx := fiberCtx.Context()
	tokenIDStr := fiberCtx.Query("token_id")
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

type getVINVCResponse struct {
	VCURL   string `json:"vcUrl"`
	VCQuery string `json:"vcQuery"`
	Message string `json:"message"`
}

func (v *VCController) GetVCStatus(fiberCtx *fiber.Ctx) error {
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
