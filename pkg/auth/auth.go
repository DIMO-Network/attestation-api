package auth

import (
	"fmt"
	"slices"

	"github.com/DIMO-Network/shared/pkg/middleware/privilegetoken"
	"github.com/DIMO-Network/shared/pkg/privileges"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

// AllOf creates a middleware that checks if the token contains all the required privileges
// this middleware also checks if the token is for the correct contract and token ID
func AllOf(contract common.Address, tokenIDParam string, privilegeIDs []privileges.Privilege) fiber.Handler {
	return func(c *fiber.Ctx) error {
		return checkAllPrivileges(c, contract, tokenIDParam, privilegeIDs)
	}
}

func checkAllPrivileges(ctx *fiber.Ctx, contract common.Address, tokenIDParam string, privilegeIDs []privileges.Privilege) error {
	// This checks that the privileges are for the token specified by the path variable and the contract address is correct.
	err := validateTokenIDAndAddress(ctx, contract, tokenIDParam)
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

func validateTokenIDAndAddress(ctx *fiber.Ctx, contract common.Address, tokenIDParam string) error {
	claims := getTokenClaim(ctx)
	tokenID := ctx.Params(tokenIDParam)

	if tokenID != claims.TokenID {
		return fiber.NewError(fiber.StatusUnauthorized, "Unauthorized! mismatch token Id provided")
	}
	if claims.ContractAddress != contract {
		return fiber.NewError(fiber.StatusUnauthorized, fmt.Sprintf("Provided token is for the wrong contract: %s", claims.ContractAddress))
	}
	return nil
}

func getTokenClaim(ctx *fiber.Ctx) *privilegetoken.Token {
	token := ctx.Locals("user").(*jwt.Token)
	claim, ok := token.Claims.(*privilegetoken.Token)
	if !ok {
		panic("TokenClaimsKey not found in fiber context")
	}
	return claim
}
