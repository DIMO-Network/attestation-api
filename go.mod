module github.com/DIMO-Network/attestation-api

go 1.24

require (
	github.com/DIMO-Network/cloudevent v0.1.2
	github.com/DIMO-Network/device-definitions-api v1.5.6
	github.com/DIMO-Network/fetch-api v0.0.12
	github.com/DIMO-Network/model-garage v0.7.1
	github.com/DIMO-Network/server-garage v0.0.4
	github.com/DIMO-Network/shared v1.0.7
	github.com/ethereum/go-ethereum v1.16.2
	github.com/gofiber/contrib/jwt v1.1.2
	github.com/gofiber/fiber/v2 v2.52.9
	github.com/gofiber/swagger v1.1.1
	github.com/golang-jwt/jwt/v5 v5.3.0
	github.com/grpc-ecosystem/go-grpc-middleware v1.4.0
	github.com/grpc-ecosystem/go-grpc-middleware/v2 v2.3.2
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/rs/zerolog v1.34.0
	github.com/segmentio/ksuid v1.0.4
	github.com/stretchr/testify v1.10.0
	github.com/swaggo/swag v1.16.6
	github.com/uber/h3-go/v4 v4.3.0
	go.uber.org/mock v0.5.2
	golang.org/x/sync v0.16.0
	google.golang.org/grpc v1.74.2
	google.golang.org/protobuf v1.36.7
)

require (
	github.com/KyleBanks/depth v1.2.1 // indirect
	github.com/MicahParks/keyfunc/v2 v2.1.0 // indirect
	github.com/andybalholm/brotli v1.2.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/caarlos0/env/v11 v11.3.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.5 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/go-openapi/jsonpointer v0.21.1 // indirect
	github.com/go-openapi/jsonreference v0.21.0 // indirect
	github.com/go-openapi/spec v0.21.0 // indirect
	github.com/go-openapi/swag v0.23.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/holiman/uint256 v1.3.2 // indirect
	github.com/joho/godotenv v1.5.1 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/mailru/easyjson v0.9.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus/client_golang v1.22.0 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.65.0 // indirect
	github.com/prometheus/procfs v0.17.0 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/swaggo/files/v2 v2.0.2 // indirect
	github.com/teslamotors/fleet-telemetry v0.7.2 // indirect
	github.com/tidwall/gjson v1.18.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/tidwall/sjson v1.2.5 // indirect
	github.com/urfave/cli/v2 v2.27.5 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasthttp v1.63.0 // indirect
	github.com/xrash/smetrics v0.0.0-20240521201337-686a1a2994c1 // indirect
	golang.org/x/crypto v0.40.0 // indirect
	golang.org/x/exp v0.0.0-20250620022241-b7579e27df2b // indirect
	golang.org/x/mod v0.27.0 // indirect
	golang.org/x/net v0.42.0 // indirect
	golang.org/x/sys v0.34.0 // indirect
	golang.org/x/text v0.28.0 // indirect
	golang.org/x/tools v0.35.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250707201910-8d1bb00bc6a7 // indirect
	google.golang.org/grpc/cmd/protoc-gen-go-grpc v1.5.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	sigs.k8s.io/yaml v1.3.0 // indirect
)

tool (
	github.com/swaggo/swag/cmd/swag
	go.uber.org/mock/mockgen
	google.golang.org/grpc/cmd/protoc-gen-go-grpc
	google.golang.org/protobuf/cmd/protoc-gen-go
)
