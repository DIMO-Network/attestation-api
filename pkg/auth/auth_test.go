package auth_test

import (
	"io"
	"net/http/httptest"
	"testing"

	"github.com/DIMO-Network/attestation-api/pkg/auth"
	"github.com/DIMO-Network/shared/middleware/privilegetoken"
	"github.com/DIMO-Network/shared/privileges"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestAllOf(t *testing.T) {
	contract := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	tokenIDParam := "tokenId"
	privilegeIDs := []privileges.Privilege{
		privileges.VehicleNonLocationData,
		privileges.VehicleCommands,
	}

	tests := []struct {
		name         string
		tokenClaims  *privilegetoken.Token
		tokenID      string
		expectedCode int
	}{
		{
			name: "Valid token with required privileges",
			tokenClaims: &privilegetoken.Token{
				CustomClaims: privilegetoken.CustomClaims{
					TokenID:         "1",
					ContractAddress: contract,
					PrivilegeIDs:    []privileges.Privilege{privileges.VehicleNonLocationData, privileges.VehicleCommands},
				},
			},
			tokenID:      "1",
			expectedCode: fiber.StatusOK,
		},
		{
			name: "Token with missing privileges",
			tokenClaims: &privilegetoken.Token{
				CustomClaims: privilegetoken.CustomClaims{
					TokenID:         "1",
					ContractAddress: contract,
					PrivilegeIDs:    []privileges.Privilege{privileges.VehicleNonLocationData},
				},
			},
			tokenID:      "1",
			expectedCode: fiber.StatusUnauthorized,
		},
		{
			name: "Token with wrong contract address",
			tokenClaims: &privilegetoken.Token{
				CustomClaims: privilegetoken.CustomClaims{
					TokenID:         "1",
					ContractAddress: common.HexToAddress("0xabcdefabcdefabcdefabcdefabcdefabcdef"),
					PrivilegeIDs:    []privileges.Privilege{privileges.VehicleNonLocationData, privileges.VehicleCommands},
				},
			},
			tokenID:      "1",
			expectedCode: fiber.StatusUnauthorized,
		},
		{
			name: "Token with wrong token ID",
			tokenClaims: &privilegetoken.Token{
				CustomClaims: privilegetoken.CustomClaims{
					TokenID:         "2",
					ContractAddress: contract,
					PrivilegeIDs:    []privileges.Privilege{privileges.VehicleNonLocationData, privileges.VehicleCommands},
				},
			},
			tokenID:      "1",
			expectedCode: fiber.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new JWT token with the claims
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, tt.tokenClaims)
			tokenString, err := token.SignedString([]byte("secret"))
			require.NoError(t, err)

			app := fiber.New()
			app.Get("/:tokenId", injectToken(token), auth.AllOf(contract, tokenIDParam, privilegeIDs),
				func(c *fiber.Ctx) error {
					return c.SendString("Success")
				})

			req := httptest.NewRequest("GET", "/"+tt.tokenID, nil)
			req.Header.Set("Authorization", "Bearer "+tokenString)

			resp, err := app.Test(req, 1) // 1 means no timeout
			require.NoError(t, err)

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.Equalf(t, tt.expectedCode, resp.StatusCode, "body: %s", string(body))

			if tt.expectedCode != fiber.StatusOK {
				return
			}

			require.Equal(t, "Success", string(body))
		})
	}
}

func injectToken(token *jwt.Token) fiber.Handler {
	return func(c *fiber.Ctx) error {
		c.Locals("user", token)
		return c.Next()
	}
}
