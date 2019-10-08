// Package azure provides Microsoft cloud integration.
// This is work in progress. Do NOT use in production!
package azure

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/pascaldekloe/jwt"
)

// HTTPClient is used to connect to the Azure REST.
var HTTPClient = http.DefaultClient

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

// NewKeyVaultClient launches a managed connection to an Azure Key Vault.
// The base URL configures the vault name, e.g. "https://myvault.vault.azure.net".
func NewKeyVaultClient(baseURL string, creds Credentials) *KeyVaultClient {
	c := &KeyVaultClient{
		baseURL: baseURL,
		creds:   creds,
	}

	// BUG(pascaldekloe): Token management & renewal not in place.
	authorization, _, err := c.getAuthorization()
	if err != nil {
		panic(err)
	}
	c.authorization = authorization

	return c
}

// Sign updates the Claims.Raw field and returns a new JWT.
// The algorithm options are listed on the REST documentation page at
// <https://docs.microsoft.com/en-us/rest/api/keyvault/sign/sign#jsonwebkeysignaturealgorithm>.
func (client *KeyVaultClient) Sign(claims *jwt.Claims, alg, keyName, keyVersion string) (token []byte, err error) {
	tokenWithoutSignature, err := claims.FormatWithoutSign(alg)
	if err != nil {
		return nil, err
	}

	signRequest := fmt.Sprintf(`{"alg": %q, "value": "%s"}`, alg, tokenWithoutSignature)
	resource := fmt.Sprintf("%s/keys/%s/%s/sign?api-version=7.0", client.baseURL, url.PathEscape(keyName), url.PathEscape(keyVersion))
	req, err := http.NewRequest("POST", resource, strings.NewReader(signRequest))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", client.authorization)

	resp, err := HTTPClient.Post(resource, "application/json", strings.NewReader(signRequest))
	if err != nil {
		return nil, fmt.Errorf("azure: sign request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		errorResponse := new(KeyVaultError)
		if err := json.NewDecoder(resp.Body).Decode(errorResponse); err != nil {
			return nil, fmt.Errorf("azure: sign status %q followed by %w", resp.Status, err)
		}
		// BUG(pascaldekloe): jwt.AlgError mapping not implemented.
		return nil, fmt.Errorf("azure: sign status %q: %w", resp.Status, errorResponse)
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

func (c *KeyVaultClient) getAuthorization() (header string, expire time.Duration, err error) {
	values := make(url.Values, 4)
	values.Set("grant_type", "client_credentials")
	values.Set("resource", "https://management.azure.com/")
	values.Set("client_id", c.creds.AppID)
	values.Set("client_secret", c.creds.Secret)
	values.Set("scope", "https://vault.azure.net/.default")

	resp, err := HTTPClient.PostForm(fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/token", url.PathEscape(c.creds.Tenant)), values)
	if err != nil {
		return "", 0, fmt.Errorf("azure: OAuth2 request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		var buf [256]byte
		n, err := io.ReadFull(resp.Body, buf[:])
		if err != nil {
			return "", 0, fmt.Errorf("azure: OAuth2 status %q followed by %w", resp.Status, err)
		}
		for i, r := range string(buf[:n]) {
			const truncateMarker = "…"
			if r == utf8.RuneError || len(buf)-i < 2*utf8.UTFMax+len(truncateMarker) {
				n = len(append(buf[:i], truncateMarker...))
				break
			}
		}
		return "", 0, fmt.Errorf("azure: OAuth2 status %q: %s", resp.Status, buf[:n])
	}

	var authResponse struct {
		TokenType   string  `json:"token_type"`
		AccessToken string  `json:"access_token"`
		ExpiresIn   float64 `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&authResponse); err != nil {
		return "", 0, fmt.Errorf("azure: OAuth2 response: %w", err)
	}
	if authResponse.TokenType == "" {
		return "", 0, errors.New("azure: OAuth2 response without token_type")
	}
	if authResponse.AccessToken == "" {
		return "", 0, errors.New("azure: OAuth2 response without access_token")
	}
	if authResponse.ExpiresIn == 0 {
		return "", 0, errors.New("azure: OAuth2 response without expires_in")
	}

	return authResponse.TokenType + " " + authResponse.AccessToken, time.Duration(authResponse.ExpiresIn) * time.Second, nil
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
