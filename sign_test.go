package jwt

import (
	"crypto"
	_ "crypto/md5"
	"encoding/json"
	"math"
	"testing"
)

func TestHMACSign(t *testing.T) {
	var c Claims
	c.Subject = "the world's greatest secret agent"
	got, err := c.HMACSign("HS512", []byte("guest"))
	if err != nil {
		t.Fatal(err)
	}

	want := "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ0aGUgd29ybGQncyBncmVhdGVzdCBzZWNyZXQgYWdlbnQifQ.6shd8lGY9wOn9NghWeVAwRFtTE9Y-HtYy3PFxPc2ulahSq2HMOR5b8T0OhUCnZzM0svC6VH3hgh8fACD_30ubQ"
	if s := string(got); s != want {
		t.Errorf("got %q, want %q", s, want)
	}
}

func TestRSASign(t *testing.T) {
	c := &Claims{
		Set: map[string]interface{}{
			"iss": "malory",
		},
	}
	got, err := c.RSASign("RS384", testKeyRSA2048)
	if err != nil {
		t.Fatal(err)
	}

	want := "eyJhbGciOiJSUzM4NCJ9.eyJpc3MiOiJtYWxvcnkifQ.KuGs2gecLlfub_m7PcD_6EzQe35DT7MNZwhi2R9bsPgmloi47r3wRdVXEdtABGQeeUz3dOuPOQ20SuWbDTDetW7u6pRjsvjqN14-XKiWQJkjIO1jKkoAUUeIo3k-V65DB6JJHZpNhe4MTv_3JI52wAMH91zjdhP4Aado8Cd-DVW7pdgrHjjA7jfWyXsHcjQmzvzIdBSLOiNtAQsUAaAXeM9s-YCCH0ODMhYO9GMYk195TktbjVKMovjjTW-yC1SbNVGMD8m9-y2u-xX7Nmd2T6ArO4u0HAE6LYTBzn0sknTz_lU7rt3TCK2dCqDAhTXu2cbjrV3cu-1K_rSxHcRVLg"
	if s := string(got); s != want {
		t.Errorf("got %q, want %q", s, want)
	}
}

func TestSignAlgWrong(t *testing.T) {
	_, err := new(Claims).HMACSign(RS512, nil)
	if err != ErrAlgUnk {
		t.Errorf("RSA alg for HMAC got error %v, want %v", err, ErrAlgUnk)
	}
	_, err = new(Claims).RSASign(HS512, testKeyRSA1024)
	if err != ErrAlgUnk {
		t.Errorf("HMAC alg for RSA got error %v, want %v", err, ErrAlgUnk)
	}
}

func TestSignAlgExtend(t *testing.T) {
	alg := "HMD5"
	if _, ok := HMACAlgs[alg]; ok {
		t.Fatalf("non-standard alg %q present", alg)
	}
	HMACAlgs[alg] = crypto.MD5
	defer delete(HMACAlgs, alg)

	_, err := new(Claims).HMACSign(alg, nil)
	if err != nil {
		t.Fatal("extend sign error:", err)
	}
}

func TestSignHashNotLinked(t *testing.T) {
	alg := "HB2b256"
	if _, ok := HMACAlgs[alg]; ok {
		t.Fatalf("non-standard alg %q present", alg)
	}
	HMACAlgs[alg] = crypto.BLAKE2b_256
	defer delete(HMACAlgs, alg)

	_, err := new(Claims).HMACSign(alg, nil)
	if err != errHashLink {
		t.Errorf("got error %v, want %v", err, errHashLink)
	}
}

func TestSignBrokenClaims(t *testing.T) {
	// JSON does not allow NaN
	n := NumericTime(math.NaN())

	c := new(Claims)
	c.Issued = &n
	_, err := c.HMACSign(HS256, nil)
	if _, ok := err.(*json.UnsupportedValueError); !ok {
		t.Errorf("HMAC got error %#v, want json.UnsupportedValueError", err)
	}

	c = new(Claims)
	c.Set = map[string]interface{}{"iss": n}
	_, err = c.RSASign(RS256, testKeyRSA1024)
	if _, ok := err.(*json.UnsupportedValueError); !ok {
		t.Errorf("RSA got error %#v, want json.UnsupportedValueError", err)
	}
}
