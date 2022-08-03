package jwt

import (
	"errors"
	"sort"
	"time"
)

type JwtPayloadClaimsValidator func(tokenClaims *Claims) error

func IssuerValidator(expectedIss string) JwtPayloadClaimsValidator {
	return func(tokenClaims *Claims) error {
		tokenIss, ok := tokenClaims.String("iss")
		if !ok {
			return errors.New("jwt issuer is missing and is required")
		}

		if tokenIss != expectedIss {
			return errors.New("invalid issuer claim")
		}

		return nil
	}
}

func SubjectValidator(expectedSub string) JwtPayloadClaimsValidator {
	return func(tokenClaims *Claims) error {
		tokenSub, ok := tokenClaims.String("sub")
		if !ok {
			return errors.New("missing subject claim")
		}

		if tokenSub != expectedSub {
			return errors.New("invalid subject claim")
		}

		return nil
	}
}

func AudiencesValidator(expectedAud []string) JwtPayloadClaimsValidator {
	return func(tokenClaims *Claims) error {
		tokenAud := tokenClaims.Audiences
		if len(tokenAud) == 0 {
			return errors.New("missing audience claim")
		}

		if len(tokenAud) != len(expectedAud) {
			return errors.New("invalid audience claim")
		}

		sort.Strings(tokenAud)
		sort.Strings(expectedAud)

		for i := range tokenAud {
			if tokenAud[i] != expectedAud[i] {
				return errors.New("invalid audience claim")
			}
		}

		return nil
	}
}

func TimeFieldValidator(expectedTime time.Time) JwtPayloadClaimsValidator {
	return func(tokenClaims *Claims) error {
		if ok := tokenClaims.Valid(expectedTime); !ok {
			return errors.New("token has expired")
		}

		return nil
	}
}

func IdValidator(expectedId string) JwtPayloadClaimsValidator {
	return func(tokenClaims *Claims) error {
		tokenId, ok := tokenClaims.String("jti")
		if !ok {
			return errors.New("missing id claim")
		}

		if tokenId != expectedId {
			return errors.New("invalid id claim")
		}

		return nil
	}
}

func CustomClaimValidator(expectedValue, customField string) JwtPayloadClaimsValidator {
	return func(tokenClaims *Claims) error {
		fieldValue, ok := tokenClaims.String(customField)
		if !ok {
			return errors.New("missing custom claim")
		}

		if fieldValue != expectedValue {
			return errors.New("invalid custom claim")
		}

		return nil
	}
}

func ValidatePayloadClaims(tokenClaims *Claims, validators ...JwtPayloadClaimsValidator) error {
	var err error

	for _, validator := range validators {
		err = validator(tokenClaims)
	}

	return err
}
