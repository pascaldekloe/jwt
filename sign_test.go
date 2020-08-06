package jwt

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestClaimsSyncNothing(t *testing.T) {
	var c Claims
	if _, err := c.FormatWithoutSign("none"); err != nil {
		t.Fatal("format error:", err)
	}
	if string(c.Raw) != "{}" {
		t.Errorf(`got JSON %q, want "{}"`, c.Raw)
	}
	if c.Set != nil {
		t.Errorf("claims set %#v not nil", c.Set)
	}
}

// Copy Registered into map.
func TestClaimsSync(t *testing.T) {
	offset := time.Unix(1537622794, 0)
	c := Claims{
		// cover all registered fields
		Registered: Registered{
			Issuer:    "a",
			Subject:   "b",
			Audiences: []string{"c"},
			Expires:   NewNumericTime(offset.Add(time.Minute)),
			NotBefore: NewNumericTime(offset.Add(-time.Second)),
			Issued:    NewNumericTime(offset),
			ID:        "d",
		},
		Set: make(map[string]interface{}),
	}

	if _, err := c.FormatWithoutSign("none"); err != nil {
		t.Fatal("format error:", err)
	}
	const want = `{"aud":["c"],"exp":1537622854,"iat":1537622794,"iss":"a","jti":"d","nbf":1537622793,"sub":"b"}`
	if got := string(c.Raw); got != want {
		t.Errorf("got JSON %q, want %q", got, want)
	}
	if len(c.Set) != 7 {
		t.Errorf("got %d entries in claims set %#v, want 7", len(c.Set), c.Set)
	}
}

// Merge Registered into claims set map.
func TestClaimsSyncMerge(t *testing.T) {
	c := Claims{
		Registered: Registered{
			Subject:   "kkazanova",
			Audiences: []string{"KGB", "RU"},
		},
		Set: map[string]interface{}{
			"iss": nil,
			"sub": "karcher",
			"aud": "ISIS",
		},
	}

	if s, ok := c.String("aud"); ok {
		t.Errorf("got audience string %q for 2 element array value", s)
	}

	if _, err := c.FormatWithoutSign("none"); err != nil {
		t.Fatal("format error:", err)
	}
	const want = `{"aud":["KGB","RU"],"iss":null,"sub":"kkazanova"}`
	if got := string(c.Raw); got != want {
		t.Errorf("got JSON %q, want %q", got, want)
	}
}

func TestSignHeaderErrors(t *testing.T) {
	_, err := new(Claims).FormatWithoutSign("none", json.RawMessage("false"))
	if err == nil || !strings.Contains(err.Error(), " not a JSON object") {
		t.Errorf("got error %s, want not a JSON object", err)
	}

	h, err := NewHMAC(HS256, []byte{1, 2, 3})
	if err != nil {
		t.Fatal("NewHMAC error", err)
	}
	_, err = h.Sign(new(Claims), json.RawMessage("{broken}"))
	if !errors.As(err, new(*json.SyntaxError)) {
		t.Errorf("got error %#v, want a json.SyntaxError", err)
	}
}

func TestECDSASign(t *testing.T) {
	const want = "sweet-44 tender-9 hot-juicy porkchops"

	var c Claims
	c.KeyID = want
	token, err := c.ECDSASign("ES384", testKeyEC384)
	if err != nil {
		t.Fatal("sign error:", err)
	}

	got, err := ECDSACheck(token, &testKeyEC384.PublicKey)
	if err != nil {
		t.Fatalf("%q check error: %s", token, err)
	}
	if got.KeyID != want {
		t.Errorf("%q got key ID %q, want %q", token, got.KeyID, want)
	}
}

func TestEdDSASign(t *testing.T) {
	want := []string{"The Idiots"}

	var c Claims
	c.Audiences = want
	token, err := c.EdDSASign(testKeyEd25519Private)
	if err != nil {
		t.Fatal("sign error:", err)
	}

	got, err := EdDSACheck(token, testKeyEd25519Public)
	if err != nil {
		t.Fatalf("%q check error: %s", token, err)
	}
	if !reflect.DeepEqual(got.Audiences, want) {
		t.Errorf("%q got audience %q, want %q", token, got.Audiences, want)
	}
}

func TestHMACSign(t *testing.T) {
	var c Claims
	c.Subject = "the world's greatest secret agent"
	got, err := c.HMACSign("HS512", []byte("guest"))
	if err != nil {
		t.Fatal("sign error", err)
	}

	want := "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ0aGUgd29ybGQncyBncmVhdGVzdCBzZWNyZXQgYWdlbnQifQ.6shd8lGY9wOn9NghWeVAwRFtTE9Y-HtYy3PFxPc2ulahSq2HMOR5b8T0OhUCnZzM0svC6VH3hgh8fACD_30ubQ"
	if s := string(got); s != want {
		t.Errorf("got %q, want %q", s, want)
	}
}

func TestHMACSignReuse(t *testing.T) {
	var c Claims
	c.Subject = "the world's greatest secret agent"
	h, err := NewHMAC("HS512", []byte("guest"))
	if err != nil {
		t.Fatal("NewHMAC error", err)
	}
	got, err := h.Sign(&c)
	if err != nil {
		t.Fatal("sign error", err)
	}

	want := "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ0aGUgd29ybGQncyBncmVhdGVzdCBzZWNyZXQgYWdlbnQifQ.6shd8lGY9wOn9NghWeVAwRFtTE9Y-HtYy3PFxPc2ulahSq2HMOR5b8T0OhUCnZzM0svC6VH3hgh8fACD_30ubQ"
	if s := string(got); s != want {
		t.Errorf("got %q, want %q", s, want)
	}
}

// Full-cycle happy flow.
func TestRSA(t *testing.T) {
	var c Claims
	c.Issuer = "Malory"
	c.Set = map[string]interface{}{"dossier": nil}

	for alg := range RSAAlgs {
		token, err := c.RSASign(alg, testKeyRSA2048)
		if err != nil {
			t.Errorf("sign %q error: %s", alg, err)
			continue
		}

		got, err := RSACheck(token, &testKeyRSA2048.PublicKey)
		if err != nil {
			t.Errorf("check %q error: %s", alg, err)
			continue
		}

		if got.Issuer != "Malory" {
			t.Errorf(`%q: got issuer %q, want "Malory"`, alg, got.Issuer)
		}
		if v, ok := got.Set["dossier"]; !ok {
			t.Error("no dossier claim")
		} else if v != nil {
			t.Errorf("got dossier %#v, want nil", v)
		}
	}
}

func TestHMACSignNoSecret(t *testing.T) {
	_, err := new(Claims).HMACSign(HS512, []byte{})
	if err != errNoSecret {
		t.Errorf("got error %v, want %v", err, errNoSecret)
	}
}

func TestSignHashNotLinked(t *testing.T) {
	alg := "HB2b256"
	if _, ok := HMACAlgs[alg]; ok {
		t.Fatalf("non-standard alg %q present", alg)
	}
	HMACAlgs[alg] = crypto.BLAKE2b_256
	defer delete(HMACAlgs, alg)

	_, err := new(Claims).HMACSign(alg, []byte("guest"))
	if err != errHashLink {
		t.Errorf("got error %v, want %v", err, errHashLink)
	}
}

func TestSignAlgError(t *testing.T) {
	const unknownAlg = "doesntexist"
	const want = AlgError(unknownAlg)

	c := new(Claims)
	if _, err := c.ECDSASign(unknownAlg, testKeyEC256); err != want {
		t.Errorf("ECDSA got error %v, want %v", err, want)
	}
	if _, err := c.HMACSign(unknownAlg, []byte("guest")); err != want {
		t.Errorf("HMAC got error %v, want %v", err, want)
	}
	if _, err := c.RSASign(unknownAlg, testKeyRSA1024); err != want {
		t.Errorf("RSA got error %v, want %v", err, want)
	}
}

func TestECDSAKeyBroken(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key.Params().N = new(big.Int)
	_, err = new(Claims).ECDSASign(ES512, key)
	if err == nil || err.Error() != "zero parameter" {
		t.Errorf("got error %q, want zero parameter", err)
	}
}

func TestRSASignKeyTooSmall(t *testing.T) {
	// can't sign 512 bits with a 512-bit RSA key
	key := mustParseRSAKey(`-----BEGIN RSA PRIVATE KEY-----
MIIBPAIBAAJBAIRyPiLmS7ta5bS6eEqUb1IZhxYJ/sB+Hq/uV3xIEcu075uE0mr9
xSUHcztAcHwEYE/JF0Zc5HS++ALadTK2qZUCAwEAAQJARsqdRaAcOG70Oi4034AJ
JDO6zV/YR2Dh3B0jq60FvgAVLYKDJ7klDpeqmLB64q2IXfnoVtJDjXSTpA6qyNvG
/QIhAOWfFSLq07Ock4gjGy7qeT3Tpa/uYmRuqk90jEfn2/oDAiEAk6lYDZ1DdXmY
4cnQu3Q8A/ZHW52uFR76mLi8FihzRocCIQCWGgT+G1WibvM+JfzKEXqKAQWpWQK2
tmTcpcph4t44swIhAIzdu8PZKHbUlvWnqzp5S5vYAgEzrtQ1Zon1inF1C2vXAiEA
uRVZaJLTfpQ+n88IcdG4WPKnRZqxGnrq3DjtIvFrBlM=
-----END RSA PRIVATE KEY-----`)

	_, err := new(Claims).RSASign(RS512, key)
	if err != rsa.ErrMessageTooLong {
		t.Errorf("got error %q, want %q", err, rsa.ErrMessageTooLong)
	}
}

func TestFormatHeader(t *testing.T) {
	/// test all standard algorithms
	algs := map[string]struct{}{
		EdDSA: {},
	}
	for alg := range ECDSAAlgs {
		algs[alg] = struct{}{}
	}
	for alg := range HMACAlgs {
		algs[alg] = struct{}{}
	}
	for alg := range RSAAlgs {
		algs[alg] = struct{}{}
	}
	// … and a non-standard algorithm
	algs["hs1"] = struct{}{}

	for alg := range algs {
		var claims Claims
		token, err := claims.FormatWithoutSign(alg)
		if err != nil {
			t.Errorf("error for %q: %s", alg, err)
			continue
		}
		i := bytes.IndexByte(token, '.')
		if i < 0 {
			t.Errorf("malformed token for %q: %q", alg, token)
			continue
		}
		headerJSON, err := encoding.DecodeString(string(token[:i]))
		if err != nil {
			t.Errorf("malformed header for %q: %s", alg, err)
			continue
		}
		m := make(map[string]interface{})
		if err := json.Unmarshal(headerJSON, &m); err != nil {
			t.Errorf("malformed header for %q: %s", alg, err)
			continue
		}
		if s, ok := m["alg"].(string); !ok || s != alg {
			t.Errorf("got alg %#v for %q", m["alg"], alg)
		}
		if string(headerJSON) != string(claims.RawHeader) {
			t.Errorf("got header %q, while claims RawHeader is set to %q", headerJSON, claims.RawHeader)
		}
	}
}
