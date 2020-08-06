package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

var goldenECDSAs = []struct {
	key    *ecdsa.PublicKey
	token  string
	claims string
}{
	0: {
		key:    &testKeyEC256.PublicKey,
		token:  "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJjdHVudCIsImF1ZCI6WyJib2FyZCJdfQ.zBjKIRdBzKiTUe34edjYRQyPy5-c_UkkBn3rip3GxvHeEhJnoop3TEWCdO4luIeX6Cfj9uJUOqIskra5-CHrXA",
		claims: `{"iss":"ctunt","aud":["board"]}`,
	},
	1: {
		key:    &testKeyEC384.PublicKey,
		token:  "eyJhbGciOiJFUzM4NCJ9.e30.1WD7DU260TLDzwiJQa-ri7FBnXlRsOzEpTKDmMt51dzqDiYguVch7VqNLTVkHCb4oJ-LDJ8-PGaeoo4jcNkGQjGg1HUiHWEZNyUUPRbxnzTKOWD1Z3VAlPDgnhXp1i8t",
		claims: `{}`,
	},
	2: {
		key:    &testKeyEC521.PublicKey,
		token:  "eyJhbGciOiJFUzUxMiJ9.eyJzdWIiOiJha3JpZWdlciIsInByZWZpeCI6IkRyLiJ9.APhisjBsvFDWLojTWUP7uyEiilIOU4KYVEgqFr5GdJbd5ucuejztFUvzRZq8njo2s0jLqwMN6H0IhG9YHDMRKTgQAbEbOT_13tN6Xs4sTtxefuf_jlJTfTLtg9_2A22iGYgSDBTzWpunC-Ofuq4XegptS2NuC6XGTFu41DbQX6EmEb-7",
		claims: `{"sub":"akrieger","prefix":"Dr."}`,
	},
}

func TestECDSACheck(t *testing.T) {
	for i, gold := range goldenECDSAs {
		claims, err := ECDSACheck([]byte(gold.token), gold.key)
		if err != nil {
			t.Errorf("%d: check error: %s", i, err)
			continue
		}
		if string(claims.Raw) != gold.claims {
			t.Errorf("%d: got claims JSON %q, want %q", i, claims.Raw, gold.claims)
		}
	}
}

var goldenEdDSAs = []struct {
	key    ed25519.PublicKey
	token  string
	claims string
}{
	0: {
		key:    testKeyEd25519Public,
		token:  "eyJhbGciOiJFZERTQSJ9.eyAiYXVkIjogIkppbGxldHRlIiwgImp0aSI6ICJjcmlzaXMtdmVzdCIgfQ.HWhMmi3DO74IOYujxYdbSqrNta9IjQsY3QB8JI2vHhwkGTXXwl_gCK93nbROlR4aW37a8EKpBfnqMc7HAhVkBg",
		claims: `{ "aud": "Jillette", "jti": "crisis-vest" }`,
	},
}

func TestEdDSACheck(t *testing.T) {
	for i, gold := range goldenEdDSAs {
		claims, err := EdDSACheck([]byte(gold.token), gold.key)
		if err != nil {
			t.Errorf("%d: check error: %s", i, err)
			continue
		}
		if string(claims.Raw) != gold.claims {
			t.Errorf("%d: got claims JSON %q, want %q", i, claims.Raw, gold.claims)
		}
	}
}

var goldenHMACs = []struct {
	secret []byte
	token  string
	claims string
}{
	0: {
		// SHA-256 example from RFC 7515, appendix A.1.1
		secret: []byte{0x3, 0x23, 0x35, 0x4b, 0x2b, 0xf, 0xa5, 0xbc, 0x83, 0x7e, 0x6, 0x65, 0x77, 0x7b, 0xa6, 0x8f, 0x5a, 0xb3, 0x28, 0xe6, 0xf0, 0x54, 0xc9, 0x28, 0xa9, 0xf, 0x84, 0xb2, 0xd2, 0x50, 0x2e, 0xbf, 0xd3, 0xfb, 0x5a, 0x92, 0xd2, 0x6, 0x47, 0xef, 0x96, 0x8a, 0xb4, 0xc3, 0x77, 0x62, 0x3d, 0x22, 0x3d, 0x2e, 0x21, 0x72, 0x5, 0x2e, 0x4f, 0x8, 0xc0, 0xcd, 0x9a, 0xf5, 0x67, 0xd0, 0x80, 0xa3},
		token:  "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		claims: "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}",
	},
	1: {
		secret: []byte("secret"),
		token:  "eyJhbGciOiJIUzUxMiJ9.eyJpc3MiOiJwcG9vdmV5Iiwic3ViIjoic21hcmNoZXIiLCJhdWQiOiJjb3JlIiwiZXhwIjoyLCJuYmYiOjEsImlhdCI6MCwianRpIjoibm90aGluZyJ9.NUVxGDBgIh3-tFl2XVpufzSH4lDEVM-dGbKxxkL1UlJNbDycQ5PpwkIxBkvzBFL0w_g6Fb3CVRhdjMpdz_pc2A",
		claims: `{"iss":"ppoovey","sub":"smarcher","aud":"core","exp":2,"nbf":1,"iat":0,"jti":"nothing"}`,
	},
}

func TestHMACCheck(t *testing.T) {
	for i, gold := range goldenHMACs {
		claims, err := HMACCheck([]byte(gold.token), gold.secret)
		if err != nil {
			t.Errorf("%d: check error: %s", i, err)
			continue
		}
		if string(claims.Raw) != gold.claims {
			t.Errorf("%d: got claims JSON %q, want %q", i, claims.Raw, gold.claims)
		}

		// extract alg
		var header struct {
			Alg string `json:"alg"`
		}
		if err := json.Unmarshal(claims.RawHeader, &header); err != nil {
			t.Errorf("malformed RawHeader %q: %s", claims.RawHeader, err)
			continue
		}

		h, err := NewHMAC(header.Alg, gold.secret)
		if err != nil {
			t.Errorf("NewHMAC(%q, %q) got error %v", header.Alg, gold.secret, err)
			continue
		}
		claims, err = h.Check([]byte(gold.token))
		if err != nil {
			t.Errorf("%d: reuse check error: %s", i, err)
			continue
		}
		if string(claims.Raw) != gold.claims {
			t.Errorf("%d: reuse got claims JSON %q, want %q", i, claims.Raw, gold.claims)
		}
	}
}

var goldenRSAs = []struct {
	key    *rsa.PublicKey
	token  string
	claims string
}{
	0: {
		key:    &testKeyRSA2048.PublicKey,
		token:  "eyJhbGciOiJSUzI1NiJ9.eyJjb2RlIjoiMDA3In0.q7I3GX8MUwd_Rrs_NiknGp3org30cBDT4JpvQfHx8TAPZNMeQokWb3iZD-Lu0TkQbZiFWdsRrrYVJO-nI15cvkRiSRtzKD0ilaC-i3VmM6cXu2AGSRhhFR4wAaZ5ZNYicooIVf1D1DLP48UZvT-n1ysuMKRRYrnyypcG8xg4o56UEFHrLL1zvuolIsG_sZN0pnVYUEDxLfXJboPSXDYOpyHSJu36Np6s4d8IsUyr3xX-Tu6-Lktu6_5k7NIVtY8yRHThe8x0UL316E_w1Av4nlECTezUS_vSF42w3rQESPXPwaZEFTxm0ciIRn0Wm0GdLHPaKSyZscgGn64eeai57Q",
		claims: `{"code":"007"}`,
	},
	1: {
		key:    &testKeyRSA4096.PublicKey,
		token:  "eyJhbGciOiJQUzM4NCJ9.eyJjb2RlIjoiTUk1In0.SsX-DHgdVT1PXJKC5c_ZmDNcUa3WMtGMGwRTMPJ3cO1z0FK5zoRUDyc47CzCxWjjl-Yqcje7hRtV4gF8j9G_NK3ZDEQLBUMynig1g3V8K_wdqn66Vh0k_aWu9cit34rZPWJEsQ0xIvDzTTUfYH5JibvYqrUk5cc76cOe7h_bgzKvUPrYPcaxLKnH_8-Oc0aLMwgs9UrTJS1F6atWb5yLlnwKce4XqhzsnsX7WJGd8Ngfz_kTRtulRh2oqgh2SHPJ8f5fl049wDVPvtzo8vUphOBc8RwGWd7Ut93tali2N7jOpyoE_DvXLOW9rpjY7JK1uixSd1r25n1eAnqY9yR_mFqUToFTuaSrLGL4VN8drFb2mO7Dtj4uG3yE89tFa0KTYGoPHpUscvq46npdT2iE4jUd641n4h-KmHblVuGHnXEYV0C0MkGHjHS_ygWrNQ58x-6UiHm54NFeGY9c7PWy-28yYM5uKZ5OlFtnVtc5X_yLNkpLligAz_MWG2ueNUAvRJPnVLDa0ZrfvUJ5SdPDP_0y9-gEZ059-xJ21X1F_Mh7Vz8W6XB9zKypY83BH0jxd-3lEh15upq43R08FsecvRCQ9TY7rs1EJjnL6WkWhIWxNY3R9jiGUfFD9gDq5Dnzvy5glDjMqIVFewOhfkj0OacysOkJJeztSRnFBKe7MLQ",
		claims: `{"code":"MI5"}`,
	},
}

func TestRSACheck(t *testing.T) {
	for i, gold := range goldenRSAs {
		claims, err := RSACheck([]byte(gold.token), gold.key)
		if err != nil {
			t.Errorf("%d: check error: %s", i, err)
			continue
		}
		if string(claims.Raw) != gold.claims {
			t.Errorf("%d: got claims JSON %q, want %q", i, claims.Raw, gold.claims)
		}
	}
}

func TestAcceptAudiences(t *testing.T) {
	const token = "eyJhbGciOiJSUzUxMiJ9.eyJhdWQiOlsiT3RoZXIgQmFycnkiLCJEZXNlcnQgRWFnbGUiLG51bGxdfQ.TtztyCP1yhNcr6DfwuHul9pBNlIXiNNvEC-lob4feS6M6TxbBu0gdhM70vtbMX7eMRPvyd1_4upq01hbGKl50WTpFPtEyb-nGG0jBjgin2gLp8rugKSZHepipOVeKcLl7ruwk40AV-wc_8RbApyT2Bsl8p90MW6tMDobAZEEVt4"
	claims, err := ParseWithoutCheck([]byte(token))
	if err != nil {
		t.Fatal("check error:", err)
	}

	// note the null pointer
	const payload = `{"aud":["Other Barry","Desert Eagle",null]}`
	if string(claims.Raw) != payload {
		t.Errorf("got JSON %q, want %q", claims.Raw, payload)
	}

	if !claims.AcceptAudience("Other Barry") {
		t.Error("Other Barry not accepted")
	}
	if !claims.AcceptAudience("Desert Eagle") {
		t.Error("Desert Eagle not accepted")
	}
	if claims.AcceptAudience("") {
		t.Error("no audience accepted")
	}

	if got, want := len(claims.Audiences), 2; got != want {
		t.Errorf(`got %d audiences, want %d`, got, want)
	}
}

func TestCheckAlgError(t *testing.T) {
	const token = "eyJhbGciOiJkb2VzbnRleGlzdCJ9.e30.e30"
	const want = AlgError("doesntexist")

	if _, err := ECDSACheck([]byte(token), &testKeyEC256.PublicKey); err != want {
		t.Errorf("ECDSA got error %v, want %v", err, want)
	}
	if _, err := HMACCheck([]byte(token), []byte("guest")); err != want {
		t.Errorf("HMAC got error %v, want %v", err, want)
	}
	if _, err := RSACheck([]byte(token), &testKeyRSA1024.PublicKey); err != want {
		t.Errorf("RSA got error %v, want %v", err, want)
	}
	if _, err := HMACCheck([]byte(token), []byte("guest")); err != want {
		t.Errorf("NewHMAC got error %v, want %v", err, want)
	}
	h, err := NewHMAC(HS512, []byte("guest"))
	if err != nil {
		t.Fatalf("NewHMAC got error %v", err)
	}
	if _, err := h.Check([]byte(token)); err != want {
		t.Errorf("HMAC reuse got error %v, want %v", err, want)
	}
}

func TestCheckMiss(t *testing.T) {
	_, err := ECDSACheck([]byte(goldenECDSAs[0].token), &testKeyEC521.PublicKey)
	if err != ErrSigMiss {
		t.Errorf("ECDSA check got error %v, want %v", err, ErrSigMiss)
	}

	randEdKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = EdDSACheck([]byte(goldenEdDSAs[0].token), randEdKey)
	if err != ErrSigMiss {
		t.Errorf("ECDSA check got error %v, want %v", err, ErrSigMiss)
	}

	_, err = HMACCheck([]byte(goldenHMACs[0].token), []byte("guest"))
	if err != ErrSigMiss {
		t.Errorf("HMAC check got error %v, want %v", err, ErrSigMiss)
	}

	_, err = RSACheck([]byte(goldenRSAs[0].token), &testKeyRSA4096.PublicKey)
	if err != ErrSigMiss {
		t.Errorf("RSA check got error %v, want %v", err, ErrSigMiss)
	}

	h, err := NewHMAC(HS256, []byte("wrong"))
	if err != nil {
		t.Fatal("NewHMAC error:", err)
	}
	_, err = h.Check([]byte(goldenHMACs[0].token))
	if err != ErrSigMiss {
		t.Errorf("HMAC reuse check got error %v, want %v", err, ErrSigMiss)
	}
}

func TestCheckNoSecret(t *testing.T) {
	_, err := HMACCheck(nil, nil)
	if err != errNoSecret {
		t.Errorf("got error %v, want %v", err, errNoSecret)
	}
}

func TestCheckHashNotLinked(t *testing.T) {
	alg := "HB2b256"
	if _, ok := HMACAlgs[alg]; ok {
		t.Fatalf("non-standard alg %q present", alg)
	}
	HMACAlgs[alg] = crypto.BLAKE2b_256
	defer delete(HMACAlgs, alg)

	_, err := HMACCheck([]byte("eyJhbGciOiJIQjJiMjU2In0.e30.e30"), []byte("guest"))
	if err != errHashLink {
		t.Errorf("got error %v, want %v", err, errHashLink)
	}
}

func TestJOSEExtension(t *testing.T) {
	// “Negative Test Case for "crit" Header Parameter” from RFC 7515, appendix E.
	const testToken = "eyJhbGciOiJub25lIiwNCiAiY3JpdCI6WyJodHRwOi8vZXhhbXBsZS5jb20vVU5ERUZJTkVEIl0sDQogImh0dHA6Ly9leGFtcGxlLmNvbS9VTkRFRklORUQiOnRydWUNCn0.RkFJTA."
	errTest := errors.New("test error")

	_, err := ParseWithoutCheck([]byte(testToken))
	const want = "jwt: unsupported critical extension in JOSE header: [\"http://example.com/UNDEFINED\"]"
	if err == nil || err.Error() != want {
		t.Errorf("got error %q, want %q", err, want)
	}

	bu := EvalCrit
	defer func() {
		EvalCrit = bu // restore
	}()
	// extend
	EvalCrit = func(token []byte, crit []string, header json.RawMessage) error {
		if string(token) != testToken {
			t.Errorf("got token %q, want %q", token, testToken)
		}

		const wantHeader = "{\"alg\":\"none\",\r\n \"crit\":[\"http://example.com/UNDEFINED\"],\r\n \"http://example.com/UNDEFINED\":true\r\n}"
		if string(header) != wantHeader {
			t.Errorf("got header %q, want %q", header, wantHeader)
		}

		const wantCrit = "http://example.com/UNDEFINED"
		if len(crit) != 1 || crit[0] != wantCrit {
			t.Errorf("got crit %q, want %q", crit, wantCrit)
		}

		return errTest
	}
	_, err = ParseWithoutCheck([]byte(testToken))
	if err != errTest {
		t.Errorf("got error %q, want %q", err, errTest)
	}

	token, err := new(Claims).HMACSign(HS256, []byte("secret"),
		json.RawMessage(`{ "crit": [] }`))
	if err != nil {
		t.Fatal("compose token with empty crit array:", err)
	}
	if _, err := HMACCheck(token, []byte("wrong")); err != errCritEmpty {
		t.Errorf("got error %q, want %q", err, errCritEmpty)
	}
}

func TestCheckPart(t *testing.T) {
	_, err := ECDSACheck([]byte("eyJhbGciOiJFUzI1NiJ9"), &testKeyEC256.PublicKey)
	if err != errNoPayload {
		t.Errorf("header only got error %v, want %v", err, errNoPayload)
	}
	_, err = RSACheck([]byte("eyJhbGciOiJub25lIn0"), &testKeyRSA1024.PublicKey)
	if err != errNoPayload {
		t.Errorf("unsecured header only got error %v, want %v", err, errNoPayload)
	}

	_, err = ECDSACheck([]byte("eyJhbGciOiJFUzI1NiJ9.e30"), &testKeyEC384.PublicKey)
	if err != ErrSigMiss {
		t.Errorf("no signature got error %v, want %v", err, ErrSigMiss)
	}
	// none alg needs leading dot (for some reason)
	_, err = HMACCheck([]byte("eyJhbGciOiJub25lIn0.e30"), []byte("guest"))
	if want := AlgError("none"); err != want {
		t.Errorf("unsecured one dot got error %v", err)
	}
}

func TestCheckBrokenBase64(t *testing.T) {
	h, err := NewHMAC(HS256, []byte("guest"))
	if err != nil {
		t.Fatal(err)
	}

	want := "jwt: malformed JOSE header: "
	_, err = h.Check([]byte("*yJhbGciOiJIUzI1NiJ9.e30.4E_Bsx-pJi3kOW9wVXN8CgbATwP09D9V5gxh9-9zSZ0"))
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("corrupt base64 in header got error %v, want %s…", err, want)
	}

	want = "jwt: malformed payload: "
	_, err = h.Check([]byte("eyJhbGciOiJIUzI1NiJ9.#.yuPeHF3zFJaCselXdCR23yxl5Don3rD3ABnzcO_460M"))
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("corrupt base64 in payload got error %v, want %s…", err, want)
	}

	want = "jwt: malformed signature: "
	_, err = ECDSACheck([]byte("eyJhbGciOiJFUzI1NiJ9.e30.*"), nil)
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("corrupt base64 in ECDSA signature got error %v, want %s…", err, want)
	}
	_, err = HMACCheck([]byte("eyJhbGciOiJIUzI1NiJ9.e30.*"), []byte("guest"))
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("corrupt base64 in HMAC signature got error %v, want %s…", err, want)
	}
	_, err = RSACheck([]byte("eyJhbGciOiJSUzI1NiJ9.e30.*"), nil)
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("corrupt base64 in RSA signature got error %v, want %s…", err, want)
	}
	_, err = ParseWithoutCheck([]byte("eyJhbGciOiJSUzI1NiJ9.e30.*"))
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("corrupt base64 in skipped signature got error %v, want %s…", err, want)
	}
}

func TestCheckBrokenJSON(t *testing.T) {
	want := "jwt: malformed JOSE header: "
	_, err := EdDSACheck([]byte("YnJva2Vu.e30."), testKeyEd25519Public)
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("corrupt JSON in header got error %v, want %s…", err, want)
	}

	// example from RFC 8037, appendix A.4 (and A.5)
	brokenPayload := "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
	want = "jwt: malformed payload: "
	_, err = EdDSACheck([]byte(brokenPayload), testKeyEd25519Public)
	if err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Errorf("corrupt JSON in payload got error %v, want %s…", err, want)
	}
}
