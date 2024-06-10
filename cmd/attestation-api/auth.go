package main

import (
	"fmt"
	"slices"

	"github.com/DIMO-Network/shared/middleware/privilegetoken"
	"github.com/DIMO-Network/shared/privileges"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gofiber/fiber/v2"
)

const (
	tokenIDParam = "tokenID"
	// TokenClaimsKey is the key used to store the token claims in the fiber context
	TokenClaimsKey = "tokenClaims"
)

func AllOf(contract common.Address, privilegeIDs []privileges.Privilege) fiber.Handler {
	return func(c *fiber.Ctx) error {
		return checkAllPrivileges(c, contract, privilegeIDs)
	}
}
func checkAllPrivileges(ctx *fiber.Ctx, contract common.Address, privilegeIDs []privileges.Privilege) error {
	// This checks that the privileges are for the token specified by the path variable and the contract address is correct.
	err := validateTokenIDAndAddress(ctx, contract)
	if err != nil {
		return err
	}

	claims := getTokenClaim(ctx)
	for _, v := range privilegeIDs {
		if !slices.Contains(claims.PrivilegeIDs, v) {
			return fiber.NewError(fiber.StatusUnauthorized, "Unauthorized! Token does not contain required privileges")
		}
	}

	return ctx.Next()
}

func validateTokenIDAndAddress(ctx *fiber.Ctx, contract common.Address) error {
	claims := getTokenClaim(ctx)
	tokenID := ctx.Params(tokenIDParam)

	if tokenID != claims.TokenID {
		return fiber.NewError(fiber.StatusUnauthorized, "Unauthorized! Wrong device token provided")
	}
	if claims.ContractAddress != contract {
		return fiber.NewError(fiber.StatusUnauthorized, fmt.Sprintf("Provided token is for the wrong contract: %s", claims.ContractAddress))
	}
	return nil
}

func getTokenClaim(ctx *fiber.Ctx) *privilegetoken.Token {
	claim, ok := ctx.Locals("user").(*privilegetoken.Token)
	if !ok {
		panic("TokenClaimsKey not found in fiber context")
	}
	return claim
}
