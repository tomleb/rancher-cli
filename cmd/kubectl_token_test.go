package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestOAuthAuth(t *testing.T) {
	testCases := []struct {
		name                 string
		responseStatus       int
		initialFails         int
		deleteResponseStatus int
		expectedToken        string
		expectedError        bool
	}{
		{
			name:                 "success",
			responseStatus:       http.StatusOK,
			initialFails:         3,
			deleteResponseStatus: http.StatusOK,
			expectedToken:        "kubeconfig-user-fake:faketokenstring",
		},
		{
			name:                 "failure",
			responseStatus:       http.StatusBadRequest,
			initialFails:         0,
			deleteResponseStatus: http.StatusOK,
			expectedToken:        "",
		},
		{
			name:                 "delete fails after successful token fetch",
			responseStatus:       http.StatusOK,
			initialFails:         0,
			deleteResponseStatus: http.StatusNotFound,
			expectedToken:        "kubeconfig-user-fake:faketokenstring",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
			mux := http.NewServeMux()

			// In the typical flow, the token will not be found immediately, so we simulate a few polls
			// where the token is not yet created.
			notFoundYetCounter := 0
			// GETs are trying to fetch the encrypted token, DETETEs are also possible.
			mux.HandleFunc("/v3-public/authTokens/", func(w http.ResponseWriter, r *http.Request) {
				switch r.Method {
				case http.MethodGet:
					if notFoundYetCounter < tc.initialFails {
						notFoundYetCounter++
						w.WriteHeader(http.StatusOK)
						response := "{\"token\":\"\"}"
						w.Write([]byte(response))
						logrus.Infof("Simulating token not present yet %v", notFoundYetCounter)
					} else {
						encryptedToken, err := makeEncodedEncryptedToken(tc.expectedToken, privateKey)
						if err != nil {
							logrus.Errorf("unable to generate encrypted token: %v", err)
						}
						response := "{\"token\":\"" + encryptedToken + "\"}"
						w.WriteHeader(tc.responseStatus)
						w.Header().Set("Content-Type", "application/json")
						w.Write([]byte(response))
					}
				default:
					w.WriteHeader(tc.deleteResponseStatus)
				}
			})

			server := httptest.NewServer(mux)
			defer server.Close()

			token, err := oauthAuth(&LoginInput{server: server.URL}, &tls.Config{}, privateKey)

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedToken, token.Token)
		})
	}
}

// makeEncodedEncryptedToken takes a token string and will encrypt it with the provided key and then
// base64 encode it for use in the tests.
func makeEncodedEncryptedToken(tokenString string, key *rsa.PrivateKey) (string, error) {
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, []byte(tokenString), nil)
	if err != nil {
		return "", err
	}
	encodedToken := base64.StdEncoding.EncodeToString(ciphertext)
	return encodedToken, nil
}
