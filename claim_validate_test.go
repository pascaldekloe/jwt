package jwt

import (
	"crypto"
	"errors"
	"strconv"
	"testing"
	"time"
)

/*
	Validator Creations
*/

// Test IssValidator function, it is not expected to return an error
func TestIssValidator(t *testing.T) {
	// Act
	validator := IssuerValidator("testing")

	// Assert
	if validator == nil {
		t.Errorf("Issuer validator is nil")
	}
}

// Test NewSignerService function, it is not expected to return an error
func TestSubValidator(t *testing.T) {
	// Act
	validator := SubjectValidator("testing")

	// Assert
	if validator == nil {
		t.Errorf("Subject validator is nil")
	}
}

// Test NewSignerService function, it is not expected to return an error
func TestAudValidator(t *testing.T) {
	// Act
	validator := AudiencesValidator([]string{"testing"})

	// Assert
	if validator == nil {
		t.Errorf("Audiences validator is nil")
	}
}

// Test NewSignerService function, it is not expected to return an error
func TestTimeFieldValidator(t *testing.T) {
	// Act
	validator := TimeFieldValidator(time.Now())

	// Assert
	if validator == nil {
		t.Errorf("TimeField validator is nil")
	}
}

// Test NewSignerService function, it is not expected to return an error
func TestIdValidator(t *testing.T) {
	// Act
	validator := IdValidator("testing")

	// Assert
	if validator == nil {
		t.Errorf("Id validator is nil")
	}
}

// Test NewSignerService function, it is not expected to return an error
func TestCustomClaimValidator(t *testing.T) {
	// Act
	validator := CustomClaimValidator("testing", "custom")

	// Assert
	if validator == nil {
		t.Errorf("CustomClaim validator is nil")
	}
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
	if validator == nil {
		t.Errorf("Issuer validator is nil")
	}
	if err != nil {
		t.Errorf("Expected error no message, got %s", err.Error())
	}
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
	if validator == nil {
		t.Errorf("Issuer validator is nil")
	}
	if err.Error() != "jwt issuer is missing and is required" {
		t.Errorf("Expected error message: %s, got %s", "jwt issuer is missing and is required", err.Error())
	}
}

// Tests ValidatePayloadClaims with a SubjectValidator, it is not expected to return an error
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
	if validator == nil {
		t.Errorf("Subject validator is nil")
	}
	if err != nil {
		t.Errorf("Expected error no message, got %s", err.Error())
	}
}

// Tests ValidatePayloadClaims with a SubjectValidator but no sub, it is expected to return an error
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
	if validator == nil {
		t.Errorf("Subject validator is nil")
	}
	if err.Error() != "missing subject claim" {
		t.Errorf("Expected error message: %s, got %s", "missing subject claim", err.Error())
	}
}

// Tests ValidatePayloadClaims with an AudiencesValidator, it is not expected to return an error
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
	if validator == nil {
		t.Errorf("Audiences validator is nil")
	}
	if err != nil {
		t.Errorf("Expected error no message, got %s", err.Error())
	}
}

// Tests ValidatePayloadClaims with an AudiencesValidator but no aud, it is expected to return an error
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
	if validator == nil {
		t.Errorf("Audiences validator is nil")
	}
	if err.Error() != "missing audience claim" {
		t.Errorf("Expected error message: %s, got %s", "missing audience claim", err.Error())
	}
}

// Tests ValidatePayloadClaims with an TimeFieldValidator, it is not expected to return an error
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
	if validator == nil {
		t.Errorf("TimeField validator is nil")
	}
	if err != nil {
		t.Errorf("Expected error no message, got %s", err.Error())
	}
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
	if validator == nil {
		t.Errorf("TimeField validator is nil")
	}
	if err.Error() != "token has expired" {
		t.Errorf("Expected error message: %s, got %s", "token has expired", err.Error())
	}
}

// Tests ValidatePayloadClaims with a IdValidator, it is not expected to return an error
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
	if validator == nil {
		t.Errorf("Id validator is nil")
	}
	if err != nil {
		t.Errorf("Expected error no message, got %s", err.Error())
	}
}

// Tests ValidatePayloadClaims with a IdValidator but no sub, it is expected to return an error
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
	if validator == nil {
		t.Errorf("Id validator is nil")
	}
	if err.Error() != "missing id claim" {
		t.Errorf("Expected error message: %s, got %s", "missing id claim", err.Error())
	}
}

// Tests ValidatePayloadClaims with a CustomClaimValidator, it is not expected to return an error
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
		validator = CustomClaimValidator("1", "test")
	}

	// Act
	err = ValidatePayloadClaims(tokenClaims, validator)

	// Assert
	if validator == nil {
		t.Errorf("CustomClaim validator is nil")
	}
	if err != nil {
		t.Errorf("Expected no error message, got %s", err.Error())
	}
}

// Tests ValidatePayloadClaims with a CustomClaimValidator but no custom claim, it is expected to return an error
func TestCustomClaimValidation_NoCustomClaim(t *testing.T) {
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
		validator = CustomClaimValidator("1", "test")
	}

	// Act
	err = ValidatePayloadClaims(tokenClaims, validator)

	// Assert
	if validator == nil {
		t.Errorf("CustomClaim validator is nil")
	}
	if err.Error() != "missing custom claim" {
		t.Errorf("Expected error message: %s, got %s", "missing custom claim", err.Error())
	}
}
