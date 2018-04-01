package jwt

import "testing"

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
