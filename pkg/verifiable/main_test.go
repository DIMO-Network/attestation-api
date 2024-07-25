package verifiable_test

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"testing"

	"github.com/DIMO-Network/attestation-api/pkg/verifiable"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

var (
	testServer     *httptest.Server
	serverInitOnce sync.Once
	privateKey     *ecdsa.PrivateKey
)

func TestMain(m *testing.M) {
	var err error
	privateKey, err = crypto.GenerateKey()
	if err != nil {
		panic(fmt.Errorf("failed to generate private key: %w", err))
	}
	ret := m.Run()
	if testServer != nil {
		testServer.Close()
	}
	os.Exit(ret)
}

func getTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	serverInitOnce.Do(func() {
		var doc []byte
		testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, err := w.Write(doc)
			require.NoError(t, err)
		}))

		keyURL, err := url.Parse(testServer.URL)
		require.NoError(t, err)
		baseURL, err := url.Parse("https://status.example.com")
		require.NoError(t, err)
		issuerService, err := verifiable.NewIssuer(verifiable.Config{
			PrivateKey:        crypto.FromECDSA(privateKey),
			ChainID:           big.NewInt(1),
			VehicleNFTAddress: common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678"),
			BaseStatusURL:     baseURL,
			BaseKeyURL:        keyURL,
			BaseVocabURL:      baseURL,
			BaseJSONLDURL:     baseURL,
		})
		require.NoError(t, err)
		doc, err = issuerService.CreateKeyControlDoc()
		require.NoError(t, err)
	})
	return testServer
}
