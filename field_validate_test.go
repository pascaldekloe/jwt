package jwt

import (
	"crypto"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

/*
	Validator Creations
*/

// Test IssValidator function, it is not expected to return an error
func TestIssValidator(t *testing.T) {
	// Act
	validator := IssuerValidator("testing")

	// Assert
	assert.NotNil(t, validator)
}

// Test NewSignerService function, it is not expected to return an error
func TestSubValidator(t *testing.T) {
	// Act
	validator := SubjectValidator("testing")

	// Assert
	assert.NotNil(t, validator)
}

// Test NewSignerService function, it is not expected to return an error
func TestAudValidator(t *testing.T) {
	// Act
	validator := AudiencesValidator([]string{"testing"})

	// Assert
	assert.NotNil(t, validator)
}

// Test NewSignerService function, it is not expected to return an error
func TestTimeFieldValidator(t *testing.T) {
	// Act
	validator := TimeFieldValidator(time.Now())

	// Assert
	assert.NotNil(t, validator)
}

// Test NewSignerService function, it is not expected to return an error
func TestTimeIdValidator(t *testing.T) {
	// Act
	validator := IdValidator("testing")

	// Assert
	assert.NotNil(t, validator)
}

// Test NewSignerService function, it is not expected to return an error
func TestTimeCustomValidator(t *testing.T) {
	// Act
	validator := CustomFieldValidator("testing", "custom")

	// Assert
	assert.NotNil(t, validator)
}

/*
	Validator Usage
*/

// Tests ValidateTokenFields with an IssValidator, it is not expected to return an error
func TestIssFieldValidation(t *testing.T) {
	// Arrange
	now := time.Now()
	sub := strconv.Itoa(1)

	baseClaims := Claims{}
	baseClaims.Issuer = "testIssuer"
	baseClaims.Audiences = []string{"testAudienceOne", "testAudienceTwo"}
	baseClaims.Expires = NewNumericTime(now.Add(time.Duration(10) * time.Minute))
	baseClaims.Subject = sub
	HMACAlgs["HS256"] = crypto.SHA256

	baseClaims.Set = map[string]interface{}{
		"iat":  now,
		"nfb":  now,
		"user": "testName",
	}

	var err error

	if !baseClaims.Valid(now) {
		err = errors.New("token has expired")
	}

	var token []byte
	if err == nil {
		token, err = baseClaims.HMACSign("HS256", []byte("guest"))
	}

	var tokenClaims *Claims
	if err == nil {
		tokenClaims, err = HMACCheck(token, []byte("guest"))
	}

	var validator JwtPayloadClaimsValidator
	if err == nil {
		validator = IssuerValidator("testIssuer")
	}

	// Act
	err = ValidatePayloadClaims(tokenClaims, validator)

	// Assert
	assert.NotNil(t, validator)
	assert.NoError(t, err)
}

// Tests ValidateTokenFields with an IssValidator but no iss, it is expected to return an error
func TestIssFieldValidation_NoIssuer(t *testing.T) {
	// Arrange
	now := time.Now()
	sub := strconv.Itoa(1)

	baseClaims := Claims{}
	baseClaims.Issuer = ""
	baseClaims.Audiences = []string{"testAudienceOne", "testAudienceTwo"}
	baseClaims.Expires = NewNumericTime(now.Add(time.Duration(10) * time.Minute))
	baseClaims.Subject = sub
	HMACAlgs["HS256"] = crypto.SHA256

	baseClaims.Set = map[string]interface{}{
		"iat":  now,
		"nfb":  now,
		"user": "testName",
	}

	var err error

	if !baseClaims.Valid(now) {
		err = errors.New("token has expired")
	}

	var token []byte
	if err == nil {
		token, err = baseClaims.HMACSign("HS256", []byte("guest"))
	}

	var tokenClaims *Claims
	if err == nil {
		tokenClaims, err = HMACCheck(token, []byte("guest"))
	}

	var validator JwtPayloadClaimsValidator
	if err == nil {
		validator = IssuerValidator("testIssuer")
	}

	// Act
	err = ValidatePayloadClaims(tokenClaims, validator)

	// Assert
	assert.NotNil(t, validator)
	assert.Equal(t, errors.New("jwt issuers is missing and is required"), err)
}

// Tests ValidateTokenFields with a SubValidator, it is not expected to return an error
func TestSubFieldValidation(t *testing.T) {
	// Arrange
	now := time.Now()
	sub := strconv.Itoa(1)

	baseClaims := Claims{}
	baseClaims.Issuer = "testIssuer"
	baseClaims.Audiences = []string{"testAudienceOne", "testAudienceTwo"}
	baseClaims.Expires = NewNumericTime(now.Add(time.Duration(10) * time.Minute))
	baseClaims.Subject = sub
	HMACAlgs["HS256"] = crypto.SHA256

	baseClaims.Set = map[string]interface{}{
		"iat":  now,
		"nfb":  now,
		"user": "testName",
	}

	var err error

	if !baseClaims.Valid(now) {
		err = errors.New("token has expired")
	}

	var token []byte
	if err == nil {
		token, err = baseClaims.HMACSign("HS256", []byte("guest"))
	}

	var tokenClaims *Claims
	if err == nil {
		tokenClaims, err = HMACCheck(token, []byte("guest"))
	}

	var validator JwtPayloadClaimsValidator
	if err == nil {
		validator = SubjectValidator("1")
	}

	// Act
	err = ValidatePayloadClaims(tokenClaims, validator)

	// Assert
	assert.NotNil(t, validator)
	assert.NoError(t, err)
}

// Tests ValidateTokenFields with a SubValidator but no sub, it is expected to return an error
func TestSubFieldValidation_NoSubject(t *testing.T) {
	// Arrange
	now := time.Now()

	baseClaims := Claims{}
	baseClaims.Issuer = "testIssuer"
	baseClaims.Audiences = []string{"testAudienceOne", "testAudienceTwo"}
	baseClaims.Expires = NewNumericTime(now.Add(time.Duration(10) * time.Minute))
	baseClaims.Subject = ""
	HMACAlgs["HS256"] = crypto.SHA256

	baseClaims.Set = map[string]interface{}{
		"iat":  now,
		"nfb":  now,
		"user": "testName",
	}

	var err error

	if !baseClaims.Valid(now) {
		err = errors.New("token has expired")
	}

	var token []byte
	if err == nil {
		token, err = baseClaims.HMACSign("HS256", []byte("guest"))
	}

	var tokenClaims *Claims
	if err == nil {
		tokenClaims, err = HMACCheck(token, []byte("guest"))
	}

	var validator JwtPayloadClaimsValidator
	if err == nil {
		validator = SubjectValidator("testIssuer")
	}

	// Act
	err = ValidatePayloadClaims(tokenClaims, validator)

	// Assert
	assert.NotNil(t, validator)
	assert.Equal(t, errors.New("missing subject claim"), err)
}

// Tests ValidateTokenFields with an AudValidator, it is not expected to return an error
func TestAudFieldValidation(t *testing.T) {
	// Arrange
	now := time.Now()
	sub := strconv.Itoa(1)

	baseClaims := Claims{}
	baseClaims.Issuer = "testIssuer"
	baseClaims.Audiences = []string{"testAudienceOne", "testAudienceTwo"}
	baseClaims.Expires = NewNumericTime(now.Add(time.Duration(10) * time.Minute))
	baseClaims.Subject = sub
	HMACAlgs["HS256"] = crypto.SHA256

	baseClaims.Set = map[string]interface{}{
		"iat":  now,
		"nfb":  now,
		"user": "testName",
	}

	var err error

	if !baseClaims.Valid(now) {
		err = errors.New("token has expired")
	}

	var token []byte
	if err == nil {
		token, err = baseClaims.HMACSign("HS256", []byte("guest"))
	}

	var tokenClaims *Claims
	if err == nil {
		tokenClaims, err = HMACCheck(token, []byte("guest"))
	}

	var validator JwtPayloadClaimsValidator
	if err == nil {
		validator = AudiencesValidator([]string{"testAudienceOne", "testAudienceTwo"})
	}

	// Act
	err = ValidatePayloadClaims(tokenClaims, validator)

	// Assert
	assert.NotNil(t, validator)
	assert.NoError(t, err)
}

// Tests ValidateTokenFields with an AudValidator but no aud, it is expected to return an error
func TestAudFieldValidation_NoAudience(t *testing.T) {
	// Arrange
	now := time.Now()

	baseClaims := Claims{}
	baseClaims.Issuer = "testIssuer"
	baseClaims.Audiences = []string{}
	baseClaims.Expires = NewNumericTime(now.Add(time.Duration(10) * time.Minute))
	baseClaims.Subject = ""
	HMACAlgs["HS256"] = crypto.SHA256

	baseClaims.Set = map[string]interface{}{
		"iat":  now,
		"nfb":  now,
		"user": "testName",
	}

	var err error

	if !baseClaims.Valid(now) {
		err = errors.New("token has expired")
	}

	var token []byte
	if err == nil {
		token, err = baseClaims.HMACSign("HS256", []byte("guest"))
	}

	var tokenClaims *Claims
	if err == nil {
		tokenClaims, err = HMACCheck(token, []byte("guest"))
	}

	var validator JwtPayloadClaimsValidator
	if err == nil {
		validator = AudiencesValidator([]string{"testAudienceOne", "testAudienceTwo"})
	}

	// Act
	err = ValidatePayloadClaims(tokenClaims, validator)

	// Assert
	assert.NotNil(t, validator)
	assert.Equal(t, errors.New("missing audience claim"), err)
}

// Tests ValidateTokenFields with an TimeFieldValidator, it is not expected to return an error
func TestTimeFieldValidation(t *testing.T) {
	// Arrange
	now := time.Now()
	sub := strconv.Itoa(1)

	baseClaims := Claims{}
	baseClaims.Issuer = "testIssuer"
	baseClaims.Audiences = []string{"testAudienceOne", "testAudienceTwo"}
	baseClaims.Expires = NewNumericTime(now.Add(time.Duration(10) * time.Minute))
	baseClaims.Subject = sub
	HMACAlgs["HS256"] = crypto.SHA256

	baseClaims.Set = map[string]interface{}{
		"iat":  now,
		"nfb":  now,
		"user": "testName",
	}

	var err error

	if !baseClaims.Valid(now) {
		err = errors.New("token has expired")
	}

	var token []byte
	if err == nil {
		token, err = baseClaims.HMACSign("HS256", []byte("guest"))
	}

	var tokenClaims *Claims
	if err == nil {
		tokenClaims, err = HMACCheck(token, []byte("guest"))
	}

	var validator JwtPayloadClaimsValidator
	if err == nil {
		validator = TimeFieldValidator(now)
	}

	// Act
	err = ValidatePayloadClaims(tokenClaims, validator)

	// Assert
	assert.NotNil(t, validator)
	assert.NoError(t, err)
}

// Tests ValidateTokenFields with an TimeFieldValidator but no time.Time, it is expected to return an error
func TestTimeFieldValidation_NoTime(t *testing.T) {
	// Arrange
	now := time.Now()

	baseClaims := Claims{}
	baseClaims.Issuer = "testIssuer"
	baseClaims.Audiences = []string{}
	baseClaims.Expires = NewNumericTime(now.Add(time.Duration(10) * time.Minute))
	baseClaims.Subject = ""
	HMACAlgs["HS256"] = crypto.SHA256

	baseClaims.Set = map[string]interface{}{
		"iat":  now,
		"nfb":  now,
		"user": "testName",
	}

	var err error

	if !baseClaims.Valid(now) {
		err = errors.New("token has expired")
	}

	var token []byte
	if err == nil {
		token, err = baseClaims.HMACSign("HS256", []byte("guest"))
	}

	var tokenClaims *Claims
	if err == nil {
		tokenClaims, err = HMACCheck(token, []byte("guest"))
	}

	var validator JwtPayloadClaimsValidator
	if err == nil {
		validator = TimeFieldValidator(time.Time{})
	}

	// Act
	err = ValidatePayloadClaims(tokenClaims, validator)

	// Assert
	assert.NotNil(t, validator)
	assert.Equal(t, errors.New("token has expired"), err)
}

// Tests ValidateTokenFields with a IdValidator, it is not expected to return an error
func TestIdFieldValidation(t *testing.T) {
	// Arrange
	now := time.Now()
	sub := strconv.Itoa(1)

	baseClaims := Claims{}
	baseClaims.ID = strconv.Itoa(1)
	baseClaims.Issuer = "testIssuer"
	baseClaims.Audiences = []string{}
	baseClaims.Expires = NewNumericTime(now.Add(time.Duration(10) * time.Minute))
	baseClaims.Subject = sub
	HMACAlgs["HS256"] = crypto.SHA256

	baseClaims.Set = map[string]interface{}{
		"iat":  now,
		"nfb":  now,
		"user": "testName",
	}

	var err error

	if !baseClaims.Valid(now) {
		err = errors.New("token has expired")
	}

	var token []byte
	if err == nil {
		token, err = baseClaims.HMACSign("HS256", []byte("guest"))
	}

	var tokenClaims *Claims
	if err == nil {
		tokenClaims, err = HMACCheck(token, []byte("guest"))
	}

	var validator JwtPayloadClaimsValidator
	if err == nil {
		validator = IdValidator("1")
	}

	// Act
	err = ValidatePayloadClaims(tokenClaims, validator)

	// Assert
	assert.NotNil(t, validator)
	assert.NoError(t, err)
}

// Tests ValidateTokenFields with a IdValidator but no sub, it is expected to return an error
func TestIdFieldValidation_NoId(t *testing.T) {
	// Arrange
	now := time.Now()

	baseClaims := Claims{}
	baseClaims.Issuer = "testIssuer"
	baseClaims.Audiences = []string{}
	baseClaims.Expires = NewNumericTime(now.Add(time.Duration(10) * time.Minute))
	baseClaims.Subject = ""
	HMACAlgs["HS256"] = crypto.SHA256

	baseClaims.Set = map[string]interface{}{
		"iat":  now,
		"nfb":  now,
		"user": "testName",
	}

	var err error

	if !baseClaims.Valid(now) {
		err = errors.New("token has expired")
	}

	var token []byte
	if err == nil {
		token, err = baseClaims.HMACSign("HS256", []byte("guest"))
	}

	var tokenClaims *Claims
	if err == nil {
		tokenClaims, err = HMACCheck(token, []byte("guest"))
	}

	var validator JwtPayloadClaimsValidator
	if err == nil {
		validator = IdValidator("testIssuer")
	}

	// Act
	err = ValidatePayloadClaims(tokenClaims, validator)

	// Assert
	assert.NotNil(t, validator)
	assert.Equal(t, errors.New("missing id claim"), err)
}

// Tests ValidateTokenFields with a CustomFieldValidator, it is not expected to return an error
func TestCustomFieldValidation(t *testing.T) {
	// Arrange
	now := time.Now()
	sub := strconv.Itoa(1)

	baseClaims := Claims{}
	baseClaims.ID = strconv.Itoa(1)
	baseClaims.Issuer = "testIssuer"
	baseClaims.Audiences = []string{}
	baseClaims.Expires = NewNumericTime(now.Add(time.Duration(10) * time.Minute))
	baseClaims.Subject = sub
	HMACAlgs["HS256"] = crypto.SHA256

	baseClaims.Set = map[string]interface{}{
		"iat":  now,
		"nfb":  now,
		"user": "testName",
		"test": "1",
	}

	var err error

	if !baseClaims.Valid(now) {
		err = errors.New("token has expired")
	}

	var token []byte
	if err == nil {
		token, err = baseClaims.HMACSign("HS256", []byte("guest"))
	}

	var tokenClaims *Claims
	if err == nil {
		tokenClaims, err = HMACCheck(token, []byte("guest"))
	}

	var validator JwtPayloadClaimsValidator
	if err == nil {
		validator = CustomFieldValidator("1", "test")
	}

	// Act
	err = ValidatePayloadClaims(tokenClaims, validator)

	// Assert
	assert.NotNil(t, validator)
	assert.NoError(t, err)
}

// Tests ValidateTokenFields with a CustomFieldValidator but no custom field, it is expected to return an error
func TestCustomFieldValidation_NoCustomField(t *testing.T) {
	// Arrange
	now := time.Now()

	baseClaims := Claims{}
	baseClaims.Issuer = "testIssuer"
	baseClaims.Audiences = []string{}
	baseClaims.Expires = NewNumericTime(now.Add(time.Duration(10) * time.Minute))
	baseClaims.Subject = ""
	HMACAlgs["HS256"] = crypto.SHA256

	baseClaims.Set = map[string]interface{}{
		"iat":  now,
		"nfb":  now,
		"user": "testName",
	}

	var err error

	if !baseClaims.Valid(now) {
		err = errors.New("token has expired")
	}

	var token []byte
	if err == nil {
		token, err = baseClaims.HMACSign("HS256", []byte("guest"))
	}

	var tokenClaims *Claims
	if err == nil {
		tokenClaims, err = HMACCheck(token, []byte("guest"))
	}

	var validator JwtPayloadClaimsValidator
	if err == nil {
		validator = CustomFieldValidator("1", "test")
	}

	// Act
	err = ValidatePayloadClaims(tokenClaims, validator)

	// Assert
	assert.NotNil(t, validator)
	assert.Equal(t, errors.New("missing custom claim"), err)
}
