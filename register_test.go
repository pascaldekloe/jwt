package jwt

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
)

// Tests the golden cases.
func TestKeyRegister(t *testing.T) {
	const pem = `All samples from test_keys.go combined:

-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBOm12aaXvqSzysOSGV2yL/xKY3kCtaOfAPY1KQN2sTJoAoGCCqGSM49
AwEHoUQDQgAEX0iTLAcGqlWeGIRtIk0G2PRgpf/6gLxOTyMAdriP4NLRkuu+9Idt
y3qmEizRC0N81j84E213/LuqLqnsrgfyiw==
-----END EC PRIVATE KEY-----

-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDBluSyfK9BEPc9y944ZLahd4xHRVse64iCeEC5gBQ4UM1961bsEthUC
NKXyTGTBuW2gBwYFK4EEACKhZANiAAR3Il6V61OwAnb6oYm4hQ4TVVaGQ2QGzrSi
eYGoRewNhAaZ8wfemWX4fww7yNi6AmUzWV8Su5Qq3dtN3nLpKUEaJrTvfjtowrr/
ZtU1fZxzI/agEpG2+uLFW6JNdYzp67w=
-----END EC PRIVATE KEY-----

-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBH31vhkSH+x+J8C/xf/PRj81u3MCqgiaGdW1S1jcjEuikczbbX689
9ETHGCPtHEWw/Il1RAFaKMvndmfDVd/YapmgBwYFK4EEACOhgYkDgYYABAGNpBDA
Lx6rKQXWdWQR581uw9dTuV8zjmkSpLZ3k0qLHVlOqt00AfEL4NO+E7fxh4SuAZPb
RDMu2lx4lWOM2EyFvgFIyu8xlA9lEg5GKq+A7+y5r99RLughiDd52vGnudMspHEy
x6IpwXzTZR/T8TkluL3jDWtVNFxGBf/aEErnpeLfRQ==
-----END EC PRIVATE KEY-----

-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g
-----END PRIVATE KEY-----
        
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=
-----END PUBLIC KEY-----

-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDCzQ4MMppUkCXTi/BjPWO2gLnaVmPhyMdo7rnccfoBnH5lCTdY
x2aK2vNkVVLi4w8zITBXAXwKB7O5iQaaXImnUD2KPReRKbyGbvkGwQGpU1UsZjzZ
uPFfbDtdWr+d2CxQUdPjKu886Lad4BsJFWSJYt06K1byYCGAYyN5hosmOQIDAQAB
AoGAO5EIYqJ2nrUVXALGlxIGk5/5NNKF6FzE3UlifA4+LI/19l9DFVqj+IHLOzr8
BXT5COF1LqW9kDOauXk1E66ISJ/vAFYvS+hIugKDqUhpBTpgPa2nyJGOjUHScvIP
sVdo1unpYU40bvhhy7HD4kwQvohYq9w5KW732jpqPJK5TKECQQD3XpZGlXAJ+O/5
p97Xwt6Rz7peG1Aqx3TlzVUvOPCXT8rnycEub0j52sYZUwg3dtf763R385pJmBJs
TJc2oN9PAkEAyZjyDqGUM6IJy7O55Ylsy3dxply7NIym+BM4p8MiEwzHZb5dXgX3
pxuPlLX3DojlGWNcLB5+gw1ZSq9Y5dz/9wJBAOQoQtUBemBIUhbj5d795sl4Xn30
FUIPy9s1Qy+WBhqZxx148gxBKn8BcRvkgLyfieDasAb/Ebx1XfCzx/jj8nMCQBNr
WT3RkL4ciMcHjAuxXjqHSfpVim74cYkKCPYYFOsy2u5RFRtehcmiHQWdNaw/wZnd
eV6CnXswSP6pv219CWcCQBv3wKhme0RkuPuyG4MUFFeHxOcilasHx/nWiz8U90Tm
hP30X1iUlekEFj/2oneT6qWqtH4nVX18/WehPQoDoLg=
-----END RSA PRIVATE KEY-----

-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA8NBRypbuyT1o2p7Ze94kmZTrwu2TsqZ1u7BOcY97xn6cc7/e
c9aZI+S4Ure57XNvKQAZlULWjWhEfY8vhP1m2hDzVCV0DnNRCPmMJxx212b2iTmA
1IsMmRYFHOYgVVUdx5QzS1xIQMZgyLP++CBkYJXZZCC1MBqyW93BkBcNzt0+70ZT
mMpXOYKoq/pFcxVMllKY41JCcDqpKcJnSmWyS+DQX5X4CcNecXxCMoL7WGeMVrng
7NTFJmv4Iyh19/WRERqQUqlPPQoWd0Wrw/Ih+p38PlxvdxxcGIgG8gZC1eZ441MR
4KeHEnx7nQ08TtzdsTULYlx3kM173h1yI+HuBwIDAQABAoIBAQCyX5w2E9aL+ZDR
Xxh5R/KUUFrR6Giey+4pOE7ijwV/4gjBND3yT+LfU2u02aI+4GJWXFyW0wtZcwJI
fucT+x9UJ3oVuihdC83ad/34en0M0JeMzas/xD9wpX7kCRGqI4ILcxsLly9ty4Ol
Jq6V3Gh9ooGESTXsi9nRclEOCgWQU6F8BeDGbI19aqkFi67wZqvOYrlUXfznRwQQ
iaffaeh+wH5qp79dd+MoSPJLmhuhNH6Q/T70tVqTvlslufcro1/7YYuq9X2/IO+u
O1Nd1/nyT46xYQ16HqLdH2KPN2jsmbWFCMM4leTbyk18ldDnU3LG7BMwwoW7vemE
gU8KuX4BAoGBAP4zMVT+M1421fXUTyxK1ViQprdqT5zksFwK0cMdy1upE0EFqUrr
TtN5mao+7rGFp7R/0xuVSwYs+LX7jsrRPXn5JgB2JdPg9UakdKkULAfGVCLJouXm
/32C9YlFuqPjJWxr5Ndb1aqvPNfIvsfmys1O+GJ39x9R+iFezvuKN2BvAoGBAPKE
3E9fSWjXg9N+y2QazeU6wJjJYhIGtceuTwPPW1n3IfOzgB1QHXZhH7YM07OoI2jF
NFBM99ygjdfRbKCosEQoUQCF78avHYJJDhdPhjAWiaIZg7X4gfgWqEMJ0SWXyCAM
cxQ0XEC0AHocWNipWv8zVFEC62K3omMXS/9leefpAoGAB/eGxkkpRvyk/A1pZdP6
l8oAz6LPV/V66YeVR245n2fPKKyKv8RcNhiLjmBmjr3HocqXzTeCoHDsYpe9w/GG
4bnDTSRmzxsv1MT2uw3cy2mV3XlAV8BDpaVjGKhMzzIhTCKdi3pfWfggCgtKn21G
UeT1t/BWmG6zTjRwfEW6spUCgYAUsXF69E53O6xr523DZOYcoR696rELiLcKCr2D
PbY1vviOqspLtgJNj4v9JKsLsVUUI3+LOoYLtUdlGuGB8+LWbfo7aTJEabzC2Sjy
pD526/Vid3rdlA7C9Gv3DGdkJcdVtLo9Bxq4CqPfx3ttQUYacG7JWs5q5fBdNCev
6yCzwQKBgHZRiC82Bzd10OgIL4WadlNphmMnGgROgNhwBu2bd5loPc+26omBAVtC
mQ9Ug7u6QOshlvxmqrgRFlWkLAwozqvS6RC4yru8FRqYnmtW7QgxO1pOj9VEzHSw
iugbqlkWvaTnn5JZoHZ+60PZc8Z4UJvzi0/h9ksnWhp5l6u1KBmc
-----END RSA PRIVATE KEY-----

-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----

… plus certificate sample:

-----BEGIN CERTIFICATE-----
MIIDJjCCAg6gAwIBAgIIWnmqQk9sgXYwDQYJKoZIhvcNAQEFBQAwNjE0MDIGA1UE
AxMrZmVkZXJhdGVkLXNpZ25vbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTAe
Fw0xODExMDkxNDQ5MTJaFw0xODExMjYwMzA0MTJaMDYxNDAyBgNVBAMTK2ZlZGVy
YXRlZC1zaWdub24uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCdGvVFEQk4EdcdmjaM2kmQ1cTV9oYfU3ZP
/U5vW4XziT2ms2F1XnZ766XmnNphNpZA1AU0ep8Nr5wEQSHXK3C5TlSOkcboNMIt
tZ3PmG7RiOND4smR7/w5PEU8OGJORDrtkd3/VAbBxfGO+xT+DmbzzjdWvRyzMStF
1jVhyVNQyrcdc8M0icy+yX0Ak/jDxEatSxk/RMmTgUszqq47qKCL4KXsLIexnztj
fALmlA8AqXomajjtENg35SNEE9645mKR9FoGqN6YxtG3zSas5LSWIiTZUqRbIkSR
UHTtGexUOm1CVlz+d4dEMpR1VTG/TaFrqH6ofLxhLJAerXQ0B4abAgMBAAGjODA2
MAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsG
AQUFBwMCMA0GCSqGSIb3DQEBBQUAA4IBAQCM/qA3dh9rikZC4gHNs34MnjFtgrst
vP/UsBl6or3pu4ILDC4YrQ2WwZ5ONQoS9tLLGCebOXfAhYtkdImivdYjM0ntEfer
CIynd/kXVTJMrSFPBk0ybu76ZflYZjLZq6HN2Y2f2y1meNQmbIM+Ohn5D6hdOgzp
O+ukTX5hVA8ADGFaHULfK1xvGl+zIi93jYySO/g3ktUU85R/LTHD3vImiQVOkaIO
9QoqLa5QG0bBfcspZm8Fqq0NXyR2ZE1iztNHiElfWnxGIUiDdKMZpFwPOaRR3IWn
EUTC5n7n+Qeyo3rL3iLhC/jn3rouX1FA5J7baL17KzDSiF5eQVlLOIfy
-----END CERTIFICATE-----
`

	var keys KeyRegister
	n, err := keys.LoadPEM([]byte(pem), nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != 9 {
		t.Errorf("extracted %d keys, want 7", n)
	}

	// add the HMAC keys
	if h, err := NewHMAC(HS256, goldenHMACs[0].secret); err != nil {
		t.Error("NewHMAC error:", err)
	} else {
		keys.HMACs = append(keys.HMACs, h)
	}
	for _, gold := range goldenHMACs[1:] {
		keys.Secrets = append(keys.Secrets, gold.secret)
	}

	for i, gold := range goldenHMACs {
		claims, err := keys.Check([]byte(gold.token))
		if err != nil {
			t.Errorf("HMAC %d: check error: %s", i, err)
			continue
		}
		if !bytes.Equal([]byte(claims.Raw), []byte(gold.claims)) {
			t.Errorf("HMAC %d: got claims JSON %q, want %q", i, claims.Raw, gold.claims)
		}
	}

	for i, gold := range goldenECDSAs {
		claims, err := keys.Check([]byte(gold.token))
		if err != nil {
			t.Errorf("ECDSA %d: check error: %s", i, err)
			continue
		}
		if !bytes.Equal([]byte(claims.Raw), []byte(gold.claims)) {
			t.Errorf("ECDSA %d: got claims JSON %q, want %q", i, claims.Raw, gold.claims)
		}
	}

	for i, gold := range goldenEdDSAs {
		claims, err := keys.Check([]byte(gold.token))
		if err != nil {
			t.Errorf("EdDSA %d: check error: %s", i, err)
			continue
		}
		if !bytes.Equal([]byte(claims.Raw), []byte(gold.claims)) {
			t.Errorf("EdDSA %d: got claims JSON %q, want %q", i, claims.Raw, gold.claims)
		}
	}

	for i, gold := range goldenRSAs {
		claims, err := keys.Check([]byte(gold.token))
		if err != nil {
			t.Errorf("RSA %d: check error: %s", i, err)
			continue
		}
		if !bytes.Equal([]byte(claims.Raw), []byte(gold.claims)) {
			t.Errorf("RSA %d: got claims JSON %q, want %q", i, claims.Raw, gold.claims)
		}
	}
}

func TestKeyRegisterCheckBroken(t *testing.T) {
	_, err := new(KeyRegister).Check([]byte("broken"))
	if !errors.As(err, new(*json.SyntaxError)) {
		t.Errorf("got error %#v, want a json.SyntaxError", err)
	}
}

func TestKeyRegisterLoadPublicKeys(t *testing.T) {
	const pem = `Public Keys
RSA:
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCzQ4MMppUkCXTi/BjPWO2gLna
VmPhyMdo7rnccfoBnH5lCTdYx2aK2vNkVVLi4w8zITBXAXwKB7O5iQaaXImnUD2K
PReRKbyGbvkGwQGpU1UsZjzZuPFfbDtdWr+d2CxQUdPjKu886Lad4BsJFWSJYt06
K1byYCGAYyN5hosmOQIDAQAB
-----END PUBLIC KEY-----

EC:
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEX0iTLAcGqlWeGIRtIk0G2PRgpf/6
gLxOTyMAdriP4NLRkuu+9Idty3qmEizRC0N81j84E213/LuqLqnsrgfyiw==
-----END PUBLIC KEY-----
`

	var keys KeyRegister
	n, err := keys.LoadPEM([]byte(pem), nil)
	if err != nil {
		t.Fatal("load error:", err)
	}
	if n != 2 {
		t.Errorf("loaded %d keys, want 2", n)
	}
	if len(keys.ECDSAs) != 1 {
		t.Errorf("got %d ECDSA keys, want 1", len(keys.ECDSAs))
	}
	if len(keys.RSAs) != 1 {
		t.Errorf("got %d RSA keys, want 1", len(keys.RSAs))
	}
}

func TestKeyRegisterLoadUnkownType(t *testing.T) {
	n, err := new(KeyRegister).LoadPEM([]byte(`
-----BEGIN SPECIAL KEY-----
BLACKTi000000000000000000000000000000000000000000000000000000000
-----END SPECIAL KEY-----
`), nil)
	if n != 0 {
		t.Errorf("loaded %d keys, want 0", n)
	}
	if want := `jwt: unknown PEM type "SPECIAL KEY"`; err == nil || err.Error() != want {
		t.Errorf("got error %q, want %q", err, want)
	}
}

func TestKeyRegisterLoadPassNotNeeded(t *testing.T) {
	n, err := new(KeyRegister).LoadPEM([]byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEX0iTLAcGqlWeGIRtIk0G2PRgpf/6
gLxOTyMAdriP4NLRkuu+9Idty3qmEizRC0N81j84E213/LuqLqnsrgfyiw==
-----END PUBLIC KEY-----`), []byte{1, 2, 3, 4})
	if n != 0 {
		t.Errorf("loaded %d keys, want 0", n)
	}
	if err != errUnencryptedPEM {
		t.Errorf("got error %q, want %q", err, errUnencryptedPEM)
	}
}

func TestKeyRegisterLoadPassMiss(t *testing.T) {
	const pem = `-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,65789712555A3E9FECD1D5E235B97B0C

o0Dz8S6QjGVq59yQdlakuKkoO0jKDN0PDu2L05ZLXwBQSGdIbRXtAOBRCNEME0V1
IF9pM6uRU7tqFoVneNTHD3XySJG8AHrTPSKC3Xw31pjEolMfoNDBAu1bYR6XxM2X
oDu2UNVB9vd/3b4bwTH9q5ISWdCVhS/ky0lC9lHXman/F/7MsemiVVCQ4XTIi9CR
nitMxJuXvkNBMtsyv+inmFMegKU6dj1DU93B9JpsFRRvy3TCfj9kRjhKWEpyindo
yaZMH3EGOA3ALW5kWyr+XegyYznQbVdDlo/ikO9BAywBOx+DdRG4xYxRdxYt8/HH
qXwPAGQe2veMlR7Iq3GjwHLebyuVc+iHbC7feRmNBpAT1RR7J+RIGlDPOBMUpuDT
A8HbNzPkoXPGh9vMsREXtR5aPCaZISdcm8DTlNiZCPaX5VHL4SRJ5XjI2rnahaOE
rhCFy0mxqQaKnEI9kCWWFmhX/MqzzfiW3yg0qFIAVLDQZZMFJr3jMHIvkxPk09rP
nQIjMRBalFXmSiksx8UEhAzyriqiXwwgEI0gJVHcs3EIQGD5jNqvIYTX67/rqSF2
OXoYuq0MHrAJgEfDncXvZFFMuAS/5KMvzSXfWr5/L0ncCU9UykjdPrFvetG/7IXQ
BT1TX4pOeW15a6fg6KwSZ5KPrt3o8qtRfW4Ov49hPD2EhnCTMbkCRBbW8F13+9YF
xzvC4Vm1r/Oa4TTUbf5tVto7ua/lZvwnu5DIWn2zy5ZUPrtn22r1ymVui7Iuhl0b
SRcADdHh3NgrjDjalhLDB95ho5omG39l7qBKBTlBAYJhDuAk9rIk1FCfCB8upztt
-----END RSA PRIVATE KEY-----`

	n, err := new(KeyRegister).LoadPEM([]byte(pem), nil)
	if n != 0 {
		t.Errorf("loaded %d keys, want 0", n)
	}
	if err != x509.IncorrectPasswordError {
		t.Errorf("got error %q, want %q", err, x509.IncorrectPasswordError)
	}
}

func TestKeyRegisterLoadBroken(t *testing.T) {
	pems := []string{`-----BEGIN EC PRIVATE KEY-----
SRcADdHh3NgrjDjalhLDB95ho5omG39l7qBKBTlBAYJhDuAk9rIk1FCfCB8upztt
-----END EC PRIVATE KEY-----`, `-----BEGIN RSA PRIVATE KEY-----
SRcADdHh3NgrjDjalhLDB95ho5omG39l7qBKBTlBAYJhDuAk9rIk1FCfCB8upztt
-----END RSA PRIVATE KEY-----`, `-----BEGIN PUBLIC KEY-----
SRcADdHh3NgrjDjalhLDB95ho5omG39l7qBKBTlBAYJhDuAk9rIk1FCfCB8upztt
-----END PUBLIC KEY-----`, `-----BEGIN CERTIFICATE-----
MIIDJjCCAg6gAwIBAgIIWnmqQk9sgXYwDQYJKoZIhvcNAQEFBQAwNjE0MDIGA1UE
-----END CERTIFICATE-----`}

	for _, pem := range pems {
		n, err := new(KeyRegister).LoadPEM([]byte(pem), nil)
		if n != 0 || err == nil {
			t.Errorf("loaded %d keys with error %v", n, err)
		}
	}
}

func TestKeyRegisterLoadUnsupported(t *testing.T) {
	pems := []string{`-----BEGIN CERTIFICATE-----
MIICpzCCAhACAg4AMA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG
A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE
MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl
YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIw
ODIyMDcyNjQzWhcNMTcwODIxMDcyNjQzWjBKMQswCQYDVQQGEwJKUDEOMAwGA1UE
CAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs
ZS5jb20wgfAwgagGByqGSM44BAEwgZwCQQDKVt7ZYtFRCzrm2/NTjl45YtMgVctQ
pLadAowFRydY13uhGw+JXyM+qmngfQkXImQpoYdIe+A8DWG2vaO3wKQ3AhUAxx6d
eaDs+XNHcbsiVQ1osvxrG8sCQHQYZDlSy/A5AFXrWXUNlTJbNhWDnitiG/95qYCe
FGnwYPp/WyhX+/lbDmQujkrbd4wYStudZM0cc4iDAWeOHQ0DQwACQDtK/S6POMQE
8aI+skBdNQn+Ch76kNDhztC/suOr9FbCSxnZ/CfhSgE1phOJyEkdR2jgErl3uh51
lo+7to76LLUwDQYJKoZIhvcNAQEFBQADgYEAnrmxZ3HB0LmVoFYdBJWxNBkRaFyn
jBmRsSJp2xvFg2nyAF77AOqBuFOFqOxg04eDxH8TGLQOWjqdyCFCY79AQlmkdB+8
Z5SWqPEwLJHVLd91O9avQwwRQT5TAxGXFkHTlQxOoaGfTsVQFqSDnlYC4mFjspA7
W+K8+llxOFmtVzU=
-----END CERTIFICATE-----`, `-----BEGIN PUBLIC KEY-----
MIIBtjCCASsGByqGSM44BAEwggEeAoGBAKJ49sDmljGvdKlxuUP9cemh23dXxPQ4
UJoBucpqn24uv//Ot86UOWqQL/BizfkTVLv8rruy2eqRJ0Ys9gO0Tw3HX7qZKPdy
aIjT90vVyb8Yi2VCtNv0aFsJI/pDvHM8oAEoNu7yBdOEgFAgFo5NYiqR0KJJw5iX
ekUhKBFOyRhjAhUAuo4P2LcnJDI9dHgJ9BWmgXeSUoECgYBYs2ne8gwAAMnChq4u
nW7G5PaiMLf2gOsRpYnM9oQAIu2UNKe3+Bz8RHBARXuu6h6X38RwQcCIFvb5Cnj6
ir0BUYJgm+IXUWj16GksOhzBTTUsNolVPi+qQhYslRqxahmm4W7Qs/TQJEYPMfQe
9g6FNHbjeMSOqr/7V/G2w3AhUAOBhAACgYAm4plkBKnp1BQ8bCyjDVjMB4wBNJUI
r8MMB4MpPBd2mtsm6KdoRQknwSQVnZd/R+G3hZ3R7Eh6+C1+Vq32T6PqrRPYRim6
T31LD06+mXbG9Cd9IYG05/LuyCBHOorcbSgKW2G+JhV2L75ajLniQdg1ZOrZuBlg
qsa4IOtmJV3zuw==
-----END PUBLIC KEY-----`, `-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgVcB/UNPxalR9zDYAjQIf
jojUDiQuGnSJrFEEzZPT/92hRANCAASc7UJtgnF/abqWM60T3XNJEzBv5ez9TdwK
H0M6xpM2q+53wmsN/eYLdgtjgBd3DBmHtPilCkiFICXyaA8z9LkJ
-----END PRIVATE KEY-----`,
	}

	for _, pem := range pems {
		n, err := new(KeyRegister).LoadPEM([]byte(pem), nil)
		if n != 0 || err == nil {
			t.Errorf("loaded %d keys with error %v", n, err)
		}
	}
}

func TestKeyRegisterCheckMiss(t *testing.T) {
	const pem = `Unrelated Keys
ECDSA:
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIrYSSNQFaA2Hwf1duRSxKtLYX5CB04fSeQ6tF1aY/PuoAoGCCqGSM49
AwEHoUQDQgAEPR3tU2Fta9ktY+6P9G0cWO+0kETA6SFs38GecTyudlHz6xvCdz8q
EKTcWGekdmdDPsHloRNtsiCa697B2O9IFA==
-----END EC PRIVATE KEY-----

RSA:
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDLLMaHgwltt+N/Vv41M035p6Pe
K0g/a3eOdBTJEZZqR7eqaWWQah12Cb+XvEJslbuzb2awZgNu/Nos/z9BiMkkwEaa
P9j/1Whc92wzd4Osod3U6Tw9g+C1LuHuHOoLJhj5nUQQcP8UQk6jzKPwr4L4uKAc
3d3GsjDJRmzl2OA8WwIDAQAB
-----END PUBLIC KEY-----
`

	var keys KeyRegister
	n, err := keys.LoadPEM([]byte(pem), nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("got %d keys, want 2", n)
	}

	keys.Secrets = append(keys.Secrets, []byte{1, 2})

	// check unsupported algorithm
	const encryptedToken = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.QR1Owv2ug2WyPBnbQrRARTeEk9kDO2w8qDcjiHnSJflSdv1iNqhWXaKH4MqAkQtMoNfABIPJaZm0HaA415sv3aeuBWnD8J-Ui7Ah6cWafs3ZwwFKDFUUsWHSK-IPKxLGTkND09XyjORj_CHAgOPJ-Sd8ONQRnJvWn_hXV1BNMHzUjPyYwEsRhDhzjAD26imasOTsgruobpYGoQcXUwFDn7moXPRfDE8-NoQX7N7ZYMmpUDkR-Cx9obNGwJQ3nM52YCitxoQVPzjbl7WBuB7AohdBoZOdZ24WlN1lVIeh8v1K4krB8xgKvRU8kgFrEn_a1rZgN5TiysnmzTROF869lQ.AxY8DCtDaGlsbGljb3RoZQ.MKOle7UQrG6nSxTLX6Mqwt0orbHvAKeWnDYvpIAeZ72deHxz3roJDXQyhxx0wKaMHDjUEOKIwrtkHthpqEanSBNYHZgmNOV7sln1Eu9g3J8.fiK51VwhsxJ-siBMR-YFiA"
	_, err = keys.Check([]byte(encryptedToken))
	if want := AlgError("RSA1_5"); err != want {
		t.Errorf("encrypted token got error %v, want %v", err, want)
	}

	// check golden cases
	for i, gold := range goldenHMACs {
		_, err := keys.Check([]byte(gold.token))
		if err != ErrSigMiss {
			t.Errorf("HMAC %d: got error %q, want %q", i, err, ErrSigMiss)
		}
	}
	for i, gold := range goldenECDSAs {
		_, err := keys.Check([]byte(gold.token))
		if err != ErrSigMiss {
			t.Errorf("ECDSA %d: got error %q, want %q", i, err, ErrSigMiss)
		}
	}
	for i, gold := range goldenRSAs {
		_, err := keys.Check([]byte(gold.token))
		if err != ErrSigMiss {
			t.Errorf("RSA %d: got error %q, want %q", i, err, ErrSigMiss)
		}
	}

	// check unlinked
	HMACAlgs["HM4"] = crypto.MD4
	ECDSAAlgs["EM4"] = crypto.MD4
	RSAAlgs["RM4"] = crypto.MD4
	RSAAlgs["PM4"] = crypto.MD4
	defer delete(HMACAlgs, "HM4")
	defer delete(ECDSAAlgs, "EM4")
	defer delete(RSAAlgs, "RM4")
	defer delete(RSAAlgs, "PM4")
	for _, header := range []string{"eyJhbGciOiJFTTQifQ", "eyJhbGciOiJITTQifQ", "eyJhbGciOiJSTTQifQ"} {
		_, err := keys.Check([]byte(header + ".e30."))
		if err != errHashLink {
			t.Errorf("header %s got error %q, want %q", header, err, errHashLink)
		}
	}
}

func TestKeyIDMiss(t *testing.T) {
	var keys KeyRegister
	// two keys per type
	keys.ECDSAs = append(keys.ECDSAs, &testKeyEC256.PublicKey, &testKeyEC384.PublicKey)
	randEdKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys.EdDSAs = append(keys.EdDSAs, testKeyEd25519Public, randEdKey)
	keys.RSAs = append(keys.RSAs, &testKeyRSA1024.PublicKey, &testKeyRSA2048.PublicKey)
	h1, err := NewHMAC(HS256, []byte("secret 1"))
	if err != nil {
		t.Fatal(err)
	}
	h2, err := NewHMAC(HS256, []byte("secret 2"))
	if err != nil {
		t.Fatal(err)
	}
	keys.HMACs = append(keys.HMACs, h1, h2)
	keys.Secrets = append(keys.Secrets, []byte("secret 3"), []byte("secret 4"))

	// identifier mapping
	keys.ECDSAIDs = append(keys.ECDSAIDs, "first", "second")
	keys.EdDSAIDs = append(keys.EdDSAIDs, "first", "second")
	keys.RSAIDs = append(keys.RSAIDs, "first", "second")
	keys.HMACIDs = append(keys.HMACIDs, "first", "second")
	keys.SecretIDs = append(keys.SecretIDs, "first", "second")

	// match second key–sign with first key
	c := Claims{KeyID: "second"}
	var tokens [5][]byte
	tokens[0], _ = c.ECDSASign(ES256, testKeyEC256)
	tokens[1], _ = c.EdDSASign(testKeyEd25519Private)
	tokens[2], _ = c.RSASign(RS256, testKeyRSA1024)
	tokens[3], _ = c.HMACSign(HS256, []byte("secret 1"))
	tokens[4], _ = c.HMACSign(HS256, []byte("secret 3"))

	for i, token := range tokens {
		_, err := keys.Check(token)
		if err != ErrSigMiss {
			t.Errorf("%d [%s]: got error: %v", i, token, err)
		}
	}
}

var GoldenJWKs = []struct {
	Count  int
	Serial string
	PEM    string
}{
	// RFC 7517, appendix A.1
	{
		Count: 2,
		Serial: `{
			"keys": [{
				"kty":"EC",
				"crv":"P-256",
				"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
				"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
				"use":"enc",
				"kid":"1"
			}, {
				"kty":"RSA",
				"n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
				"e":"AQAB",
				"alg":"RS256",
				"kid":"2011-04-29"
			}]
		}`,
		PEM: `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMKBCTNIcKUSDii11ySs3526iDZ8A
iTo7Tu6KPAqv7D7gS2XpJFbZiItSs3m9+9Ue6GnvHw/GW2ZZaVtszggXIw==
-----END PUBLIC KEY-----
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0vx7agoebGcQSuuPiLJX
ZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tS
oc/BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ/2W+5JsGY4Hc5n9yBXArwl93lqt
7/RN5w6Cf0h4QyQ5v+65YGjQR0/FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0
zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt+bFTWhAI4vMQFh6WeZu0f
M4lFd2NcRwr3XPksINHaQ+G/xBniIqbw0Ls1jF44+csFCur+kEgU8awapJzKnqDK
gwIDAQAB
-----END PUBLIC KEY-----
`,
	},

	// RFC 7517, appendix A.2
	{
		Count: 2,
		Serial: `{
			"keys": [{
				"kty":"EC",
				"crv":"P-256",
				"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
				"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
				"d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
				"use":"enc",
				"kid":"1"
			}, {
				"kty":"RSA",
				"n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
				"e":"AQAB",
				"d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
				"p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
				"q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
				"dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
				"dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
				"qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
				"alg":"RS256",
				"kid":"2011-04-29"
			}]
		}`,
		PEM: `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMKBCTNIcKUSDii11ySs3526iDZ8A
iTo7Tu6KPAqv7D7gS2XpJFbZiItSs3m9+9Ue6GnvHw/GW2ZZaVtszggXIw==
-----END PUBLIC KEY-----
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0vx7agoebGcQSuuPiLJX
ZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tS
oc/BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ/2W+5JsGY4Hc5n9yBXArwl93lqt
7/RN5w6Cf0h4QyQ5v+65YGjQR0/FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0
zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt+bFTWhAI4vMQFh6WeZu0f
M4lFd2NcRwr3XPksINHaQ+G/xBniIqbw0Ls1jF44+csFCur+kEgU8awapJzKnqDK
gwIDAQAB
-----END PUBLIC KEY-----
`,
	},

	// RFC 7517, appendix A.3
	{
		Count: 2,
		Serial: `{
			"keys": [{
				"kty":"oct",
				"alg":"A128KW",
				"k":"GawgguFyGrWKav7AX4VKUg"
			}, {
				"kty":"oct",
				"k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
				"kid":"HMAC key used in JWS spec Appendix A.1 example"
			}]
		}`,
		PEM: "",
	},

	// RFC 7517, appendix B
	{
		Count: 1,
		Serial: `{
			"kty":"RSA",
			"use":"sig",
			"kid":"1b94c",
			"n":"vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08PLbK_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Qu2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4aYWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wgzjYQDwHMTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-meMvVfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ",
			"e":"AQAB",
			"x5c": ["MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA=="]
		}`,
		PEM: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvrjOfz9Ccdgx5nQudyhd
oR17V+IubWMeOZCwX/jj0hgAsz2J/pqYW08PLbK/PdiVGKPrqzmDIsLI7sA25VEn
HU1uCLNwBuUiCO11/+7dYbsr4iJmG0Qu2j8DsVyT1azpJC/NG84Ty5KKthuCaPod
7iI7w0LK9orSMhBEwwZDCxTWq4aYWAchc8t+emd9qOvWtVMDC2BXksRngh6X5bUY
Ly6AyHKvj+nUy1wgzjYQDwHMTplCoLtU+o+8SNnZ1tmRoGE9uJkBLdh5gFENabWn
U5m1ZqZPdwS+qo+meMvVfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ/jBPD5eunqsIo1
vQIDAQAB
-----END PUBLIC KEY-----
`,
	},

	// RFC 7517, appendix C
	{
		Count: 1,
		Serial: `{
			"kty":"RSA",
			"kid":"juliet@capulet.lit",
			"use":"enc",
			"n":"t6Q8PWSi1dkJj9hTP8hNYFlvadM7DflW9mWepOJhJ66w7nyoK1gPNqFMSQRyO125Gp-TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR0-Iqom-QFcNP8Sjg086MwoqQU_LYywlAGZ21WSdS_PERyGFiNnj3QQlO8Yns5jCtLCRwLHL0Pb1fEv45AuRIuUfVcPySBWYnDyGxvjYGDSM-AqWS9zIQ2ZilgT-GqUmipg0XOC0Cc20rgLe2ymLHjpHciCKVAbY5-L32-lSeZO-Os6U15_aXrk9Gw8cPUaX1_I8sLGuSiVdt3C_Fn2PZ3Z8i744FPFGGcG1qs2Wz-Q",
			"e":"AQAB",
			"d":"GRtbIQmhOZtyszfgKdg4u_N-R_mZGU_9k7JQ_jn1DnfTuMdSNprTeaSTyWfSNkuaAwnOEbIQVy1IQbWVV25NY3ybc_IhUJtfri7bAXYEReWaCl3hdlPKXy9UvqPYGR0kIXTQRqns-dVJ7jahlI7LyckrpTmrM8dWBo4_PMaenNnPiQgO0xnuToxutRZJfJvG4Ox4ka3GORQd9CsCZ2vsUDmsXOfUENOyMqADC6p1M3h33tsurY15k9qMSpG9OX_IJAXmxzAh_tWiZOwk2K4yxH9tS3Lq1yX8C1EWmeRDkK2ahecG85-oLKQt5VEpWHKmjOi_gJSdSgqcN96X52esAQ",
			"p":"2rnSOV4hKSN8sS4CgcQHFbs08XboFDqKum3sc4h3GRxrTmQdl1ZK9uw-PIHfQP0FkxXVrx-WE-ZEbrqivH_2iCLUS7wAl6XvARt1KkIaUxPPSYB9yk31s0Q8UK96E3_OrADAYtAJs-M3JxCLfNgqh56HDnETTQhH3rCT5T3yJws",
			"q":"1u_RiFDP7LBYh3N4GXLT9OpSKYP0uQZyiaZwBtOCBNJgQxaj10RWjsZu0c6Iedis4S7B_coSKB0Kj9PaPaBzg-IySRvvcQuPamQu66riMhjVtG6TlV8CLCYKrYl52ziqK0E_ym2QnkwsUX7eYTB7LbAHRK9GqocDE5B0f808I4s",
			"dp":"KkMTWqBUefVwZ2_Dbj1pPQqyHSHjj90L5x_MOzqYAJMcLMZtbUtwKqvVDq3tbEo3ZIcohbDtt6SbfmWzggabpQxNxuBpoOOf_a_HgMXK_lhqigI4y_kqS1wY52IwjUn5rgRrJ-yYo1h41KR-vz2pYhEAeYrhttWtxVqLCRViD6c",
			"dq":"AvfS0-gRxvn0bwJoMSnFxYcK1WnuEjQFluMGfwGitQBWtfZ1Er7t1xDkbN9GQTB9yqpDoYaN06H7CFtrkxhJIBQaj6nkF5KKS3TQtQ5qCzkOkmxIe3KRbBymXxkb5qwUpX5ELD5xFc6FeiafWYY63TmmEAu_lRFCOJ3xDea-ots",
			"qi":"lSQi-w9CpyUReMErP1RsBLk7wNtOvs5EQpPqmuMvqW57NBUczScEoPwmUqqabu9V0-Py4dQ57_bapoKRu1R90bvuFnU63SHWEFglZQvJDMeAvmj4sm-Fp0oYu_neotgQ0hzbI5gry7ajdYy9-2lNx_76aBZoOUu9HCJ-UsfSOI8"
		}`,
		PEM: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt6Q8PWSi1dkJj9hTP8hN
YFlvadM7DflW9mWepOJhJ66w7nyoK1gPNqFMSQRyO125Gp+TEkodhWr0iujjHVx7
BcV0llS4w5ACGgPrcAd6ZcSR0+Iqom+QFcNP8Sjg086MwoqQU/LYywlAGZ21WSdS
/PERyGFiNnj3QQlO8Yns5jCtLCRwLHL0Pb1fEv45AuRIuUfVcPySBWYnDyGxvjYG
DSM+AqWS9zIQ2ZilgT+GqUmipg0XOC0Cc20rgLe2ymLHjpHciCKVAbY5+L32+lSe
ZO+Os6U15/aXrk9Gw8cPUaX1/I8sLGuSiVdt3C/Fn2PZ3Z8i744FPFGGcG1qs2Wz
+QIDAQAB
-----END PUBLIC KEY-----
`,
	},
	// RFC 8037, appendix A.1
	{
		Count: 1,
		Serial: `{"kty":"OKP","crv":"Ed25519",
   "d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
   "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`,
		PEM: `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=
-----END PUBLIC KEY-----
`,
	},
}

func TestKeyRegisterPEMErrors(t *testing.T) {
	var keys KeyRegister

	keys.ECDSAs = []*ecdsa.PublicKey{{
		Curve: UnsupportedCurve{},
		X:     big.NewInt(1),
		Y:     big.NewInt(2),
	}}
	if text, err := keys.PEM(); err == nil {
		t.Errorf("no error for broken ECDSA key: %q", text)
	}
	keys.ECDSAs = nil

	keys.RSAs = []*rsa.PublicKey{{}}
	if text, err := keys.PEM(); err == nil {
		t.Errorf("no error for broken RSA key: %q", text)
	}
	keys.RSAs = nil
}

// UnsupportedCurve implements ellipticCurve.
type UnsupportedCurve struct{}

func (UnsupportedCurve) Params() *elliptic.CurveParams {
	return &elliptic.CurveParams{
		P:       big.NewInt(1),
		N:       big.NewInt(1),
		B:       big.NewInt(1),
		Gx:      big.NewInt(1),
		Gy:      big.NewInt(1),
		BitSize: 100,
		Name:    "unsupported",
	}
}
func (UnsupportedCurve) IsOnCurve(x, y *big.Int) bool                         { return false }
func (UnsupportedCurve) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int)          { return }
func (UnsupportedCurve) Double(x1, y1 *big.Int) (x, y *big.Int)               { return }
func (UnsupportedCurve) ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int) { return }
func (UnsupportedCurve) ScalarBaseMult(k []byte) (x, y *big.Int)              { return }

func TestKeyRegisterLoadJWKs(t *testing.T) {
	for _, gold := range GoldenJWKs {
		keys := new(KeyRegister)
		n, err := keys.LoadJWK([]byte(gold.Serial))
		if n != gold.Count || err != nil {
			t.Errorf("got (%d, %#v) for serial %s", n, err, gold.Serial)
			continue
		}

		pem, err := keys.PEM()
		if err != nil {
			t.Error("PEM encoding error:", err)
			continue
		}
		if string(pem) != gold.PEM {
			t.Errorf("got PEM %q,\nwant %q", pem, gold.PEM)
		}
	}
}

var GoldenJWKErrors = []struct {
	JWK string
	Err error
}{
	{`broken`, nil},
	{`{}`, errJWKNoKty},
	{`{"keys": [{}]}`, errJWKNoKty},
	{`{"kty": "bad"}`,
		errors.New(`jwt: JWK with unsupported key type "bad"`)},
	{`{"kty": "EC", "crv": "bad"}`,
		errors.New(`jwt: JWK with unsupported elliptic curve "bad"`)},
	{`{"kty": "RSA"}`, errJWKParam},
	{`{"kty": "RSA", "n": "123"}`, errJWKParam},
	{`{"kty": "RSA", "n": "123", "e": "🙃"}`,
		errors.New(`jwt: JWK with malformed key–parameter field: illegal base64 data at input byte 0`)},
	{`{"kty": "EC", "crv": "P-521"}`, errJWKParam},
	{`{"kty": "EC", "crv": "P-521", "x": "123", "y": "🙃"}`,
		errors.New(`jwt: JWK with malformed key–parameter field: illegal base64 data at input byte 0`)},
	{`{"kty": "oct"}`, errJWKParam},
	{`{"kty": "OKP", "crv": "Ed25519"}`, errJWKParam},
	{`{"kty": "OKP", "crv": "bad"}`,
		errors.New(`jwt: JWK with unsupported elliptic curve "bad"`)},
	{`{"kty":"EC", "crv":"P-384",
		"x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
		"y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
}`, errJWKCurveSize},
	{`{"kty":"EC", "crv":"P-256",
		"x":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
		"y":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4"
}`, errJWKCurveMiss},
}

func TestKeyRegisterLoadJWKErrors(t *testing.T) {
	for _, gold := range GoldenJWKErrors {
		n, err := new(KeyRegister).LoadJWK([]byte(gold.JWK))
		if n != 0 {
			t.Errorf("loaded %d keys for %q, want 0", n, gold.JWK)
		}
		if err == nil {
			t.Errorf("no error for %q", gold.JWK)
			continue
		}
		if gold.Err != nil && err.Error() != gold.Err.Error() {
			t.Errorf("want error %q for %q, got %q", gold.Err, gold.JWK, err)
		}
	}
}
