// Package azure provides Microsoft cloud integration.
// This is work in progress. Do NOT use in production!
package azure

import (
	"bytes"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/pascaldekloe/jwt"
)

// HTTPClient is used to connect to the Azure REST.
var HTTPClient = http.DefaultClient

// Algorithm support is configured with hash registrations.
// For a full list of options, see the REST documentation at
// <https://docs.microsoft.com/en-us/rest/api/keyvault/sign/sign#jsonwebkeysignaturealgorithm>.
var KeyVaultAlgs = map[string]crypto.Hash{
	jwt.ES256: crypto.SHA256,
	jwt.ES384: crypto.SHA384,
	jwt.ES512: crypto.SHA512,
	jwt.HS256: crypto.SHA256,
	jwt.HS384: crypto.SHA384,
	jwt.HS512: crypto.SHA512,
	jwt.PS256: crypto.SHA256,
	jwt.PS384: crypto.SHA384,
	jwt.PS512: crypto.SHA512,
	jwt.RS256: crypto.SHA256,
	jwt.RS384: crypto.SHA384,
	jwt.RS512: crypto.SHA512,
}

func hashLookup(alg string) (crypto.Hash, error) {
	hash, ok := KeyVaultAlgs[alg]
	if !ok {
		return 0, jwt.AlgError(alg)
	}
	if !hash.Available() {
		return 0, errors.New("azure: hash function not linked into binary")

	}
	return hash, nil
}

// Credentials represent the hosting account.
type Credentials struct {
	// The application ID that's assigned to your app. You can find
	// this  information in the portal where you registered your app.
	AppID string

	// The directory tenant the application plans to operate against,
	// in GUID or domain-name format.
	Tenant string

	// The client secret that you generated for your app in the app
	// registration portal.
	Secret string
}

// KeyVaultClient provides access to an Azure Key Vault instance.
// Multiple goroutines may invoke methods on a KeyVaultClient similtaneously.
type KeyVaultClient struct {
	baseURL       string
	creds         Credentials
	authorization string
}

// NewKeyVaultClient launches a connection to an Azure Key Vault.
// The base URL configures the vault name, e.g. "https://myvault.vault.azure.net".
func NewKeyVaultClient(baseURL string, creds Credentials) *KeyVaultClient {
	client := &KeyVaultClient{
		baseURL: baseURL,
		creds:   creds,
	}

	// BUG(pascaldekloe): Token management & renewal not in place.
	client.auth()

	return client
}

// Sign updates the Claims.Raw field and returns a new JWT.
// The return is an jwt.AlgError when alg is not in KeyVaultAlgs.
func (client *KeyVaultClient) Sign(claims *jwt.Claims, alg, keyName, keyVersion string) (token []byte, err error) {
	if keyName == "" || keyVersion == "" {
		return nil, errors.New("azure: key name and version required")
	}

	hash, err := hashLookup(alg)
	if err != nil {
		return nil, err
	}
	tokenWithoutSignature, err := claims.FormatWithoutSign(alg)
	if err != nil {
		return nil, err
	}

	digest := hash.New()
	digest.Write(tokenWithoutSignature)
	signRequest, err := json.Marshal(&struct {
		Alg   string `json:"alg"`
		Value []byte `json:"value"`
	}{alg, digest.Sum(nil)})
	if err != nil {
		return nil, fmt.Errorf("azure: sign request compose: %w", err)
	}

	resource := fmt.Sprintf("%s/keys/%s/%s/sign?api-version=7.0", client.baseURL, url.PathEscape(keyName), url.PathEscape(keyVersion))
	req, err := http.NewRequest("POST", resource, bytes.NewReader(signRequest))
	if err != nil {
		return nil, fmt.Errorf("azure: sign request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", client.authorization)

	resp, err := HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("azure: sign request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		errorResponse := new(keyVaultErrorResponse)
		if err := json.NewDecoder(resp.Body).Decode(errorResponse); err != nil {
			return nil, fmt.Errorf("azure: sign status %q followed by %w", resp.Status, err)
		}
		return nil, fmt.Errorf("azure: sign status %q: %w", resp.Status, &errorResponse.Error)
	}

	var signResponse struct{ Value string }
	if err := json.NewDecoder(resp.Body).Decode(&signResponse); err != nil {
		return nil, fmt.Errorf("azure: sign response: %w", err)
	}
	if signResponse.Value == "" {
		return nil, errors.New("azure: sign response without value")
	}

	token = append(tokenWithoutSignature, '.')
	token = append(token, signResponse.Value...)
	return token, nil
}

func (client *KeyVaultClient) auth() {
	accessToken, err := client.getAccessToken()
	if err != nil {
		panic(err)
	}
	claims, err := jwt.ParseWithoutCheck([]byte(accessToken))
	if err != nil {
		panic(err)
	}
	fmt.Println("access token expires on ", claims.Expires)

	client.authorization = "Bearer " + accessToken
}

func (client *KeyVaultClient) getAccessToken() (string, error) {
	values := url.Values{
		"grant_type":    []string{"client_credentials"},
		"resource":      []string{"https://vault.azure.net"},
		"scope":         []string{"https://vault.azure.net/.default"},
		"client_id":     []string{client.creds.AppID},
		"client_secret": []string{client.creds.Secret},
	}

	resp, err := HTTPClient.PostForm(fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/token", url.PathEscape(client.creds.Tenant)), values)
	if err != nil {
		return "", fmt.Errorf("azure: OAuth2 request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		var buf [256]byte
		n, err := io.ReadFull(resp.Body, buf[:])
		if err != nil {
			return "", fmt.Errorf("azure: OAuth2 status %q followed by %w", resp.Status, err)
		}
		for i, r := range string(buf[:n]) {
			const truncateMarker = "…"
			if r == utf8.RuneError || len(buf)-i < 2*utf8.UTFMax+len(truncateMarker) {
				n = len(append(buf[:i], truncateMarker...))
				break
			}
		}
		return "", fmt.Errorf("azure: OAuth2 status %q: %s", resp.Status, buf[:n])
	}

	var authResponse struct {
		TokenType   string `json:"token_type"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&authResponse); err != nil {
		return "", fmt.Errorf("azure: OAuth2 response: %w", err)
	}
	if authResponse.TokenType != "Bearer" {
		return "", fmt.Errorf("azure: unsupporetd OAuth2 token_type %q", authResponse.TokenType)
	}
	if authResponse.AccessToken == "" {
		return "", errors.New("azure: OAuth2 response without access_token")
	}

	return authResponse.AccessToken, nil
}

type keyVaultErrorResponse struct {
	Error KeyVaultError
}

// KeyVaultError is a server error response (JSON).
type KeyVaultError struct {
	Code       string
	Message    string
	Innererror *KeyVaultError
}

// Error honors the error interface.
func (e *KeyVaultError) Error() string {
	var buf strings.Builder
	for {
		buf.WriteString(e.Message)
		buf.WriteString(" [")
		buf.WriteString(e.Code)
		buf.WriteByte(']')

		e = e.Innererror
		if e == nil {
			return buf.String()
		}
		buf.WriteString(": ")
	}
}
