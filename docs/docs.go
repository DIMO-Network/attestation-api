// Package docs Code generated by swaggo/swag. DO NOT EDIT
package docs

import "github.com/swaggo/swag"

const docTemplate = `{
    "schemes": {{ marshal .Schemes }},
    "swagger": "2.0",
    "info": {
        "description": "{{escape .Description}}",
        "title": "{{.Title}}",
        "contact": {},
        "version": "{{.Version}}"
    },
    "host": "{{.Host}}",
    "basePath": "{{.BasePath}}",
    "paths": {
        "/": {
            "get": {
                "description": "get the status of server.",
                "consumes": [
                    "*/*"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "root"
                ],
                "summary": "Show the status of server.",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "type": "object",
                            "additionalProperties": true
                        }
                    }
                }
            }
        },
        "/v1/vc/keys": {
            "get": {
                "description": "Returns the public key document for verifying VCs.",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "VINVC"
                ],
                "summary": "Get verification control document",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/github_com_DIMO-Network_attestation-api_pkg_verifiable.VerificationControlDocument"
                        }
                    }
                }
            }
        },
        "/v1/vc/status/{group}": {
            "get": {
                "description": "Get the VC status for a given status group (currently this is just the vehcilesTokenId)",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "VINVC"
                ],
                "summary": "Get VC Status",
                "parameters": [
                    {
                        "type": "integer",
                        "description": "status list group",
                        "name": "group",
                        "in": "path",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/github_com_DIMO-Network_attestation-api_pkg_verifiable.Credential"
                        }
                    }
                }
            }
        },
        "/v1/vc/vin/{tokenId}": {
            "get": {
                "security": [
                    {
                        "BearerAuth": []
                    }
                ],
                "description": "Get the VIN VC for a given token Id of a vehicle NFT. If a unexpired VC is not found, a new VC is generated.",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "VINVC"
                ],
                "summary": "Get VIN VC",
                "parameters": [
                    {
                        "type": "integer",
                        "description": "token Id of the vehicle NFT",
                        "name": "tokenId",
                        "in": "path",
                        "required": true
                    },
                    {
                        "type": "boolean",
                        "description": "force generation of a new VC even if an unexpired VC exists",
                        "name": "force",
                        "in": "query"
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/internal_controllers_httphandlers.getVINVCResponse"
                        }
                    }
                }
            }
        }
    },
    "definitions": {
        "github_com_DIMO-Network_attestation-api_pkg_verifiable.Credential": {
            "type": "object",
            "properties": {
                "@context": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                },
                "credentialStatus": {
                    "$ref": "#/definitions/github_com_DIMO-Network_attestation-api_pkg_verifiable.CredentialStatus"
                },
                "credentialSubject": {
                    "type": "array",
                    "items": {
                        "type": "integer"
                    }
                },
                "id": {
                    "type": "string"
                },
                "issuer": {
                    "type": "string"
                },
                "proof": {
                    "$ref": "#/definitions/github_com_DIMO-Network_attestation-api_pkg_verifiable.Proof"
                },
                "type": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                },
                "validFrom": {
                    "type": "string"
                },
                "validTo": {
                    "type": "string"
                }
            }
        },
        "github_com_DIMO-Network_attestation-api_pkg_verifiable.CredentialStatus": {
            "type": "object",
            "properties": {
                "id": {
                    "type": "string"
                },
                "statusListCredential": {
                    "type": "string"
                },
                "statusListIndex": {
                    "type": "integer"
                },
                "statusPurpose": {
                    "type": "string"
                },
                "type": {
                    "type": "string"
                }
            }
        },
        "github_com_DIMO-Network_attestation-api_pkg_verifiable.MultiKey": {
            "type": "object",
            "properties": {
                "controller": {
                    "type": "string"
                },
                "id": {
                    "type": "string"
                },
                "publicKeyMultibase": {
                    "type": "string"
                },
                "type": {
                    "type": "string"
                }
            }
        },
        "github_com_DIMO-Network_attestation-api_pkg_verifiable.Proof": {
            "type": "object",
            "properties": {
                "created": {
                    "type": "string"
                },
                "cryptosuite": {
                    "type": "string"
                },
                "proofPurpose": {
                    "type": "string"
                },
                "proofValue": {
                    "type": "string"
                },
                "type": {
                    "type": "string"
                },
                "verificationMethod": {
                    "type": "string"
                }
            }
        },
        "github_com_DIMO-Network_attestation-api_pkg_verifiable.VerificationControlDocument": {
            "type": "object",
            "properties": {
                "@context": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                },
                "assertionMethod": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                },
                "authentication": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                },
                "capabilityDelegation": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                },
                "capabilityInvocation": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    }
                },
                "id": {
                    "type": "string"
                },
                "verificationMethod": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/github_com_DIMO-Network_attestation-api_pkg_verifiable.MultiKey"
                    }
                }
            }
        },
        "internal_controllers_httphandlers.getVINVCResponse": {
            "type": "object",
            "properties": {
                "message": {
                    "type": "string"
                },
                "vcQuery": {
                    "type": "string"
                },
                "vcUrl": {
                    "type": "string"
                }
            }
        }
    },
    "securityDefinitions": {
        "BearerAuth": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header"
        }
    }
}`

// SwaggerInfo holds exported Swagger Info so clients can modify it
var SwaggerInfo = &swag.Spec{
	Version:          "1.0",
	Host:             "",
	BasePath:         "",
	Schemes:          []string{},
	Title:            "DIMO Attestation API",
	Description:      "",
	InfoInstanceName: "swagger",
	SwaggerTemplate:  docTemplate,
	LeftDelim:        "{{",
	RightDelim:       "}}",
}

func init() {
	swag.Register(SwaggerInfo.InstanceName(), SwaggerInfo)
}
