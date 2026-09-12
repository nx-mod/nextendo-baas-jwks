// baas-jwks: serves the public JWK Set at the BAAS id_token's `jku` URL AND mints the
// BAAS id_token / access_token at the real Nintendo BAAS token endpoint
// (POST /1.0.0/application/token) so a real CFW Switch (no Nintendo) can complete the
// Splatoon 2 account-link. The emulator DNS-mitm redirects the baas host
// (e.g. <hex>.baas.nintendo.com / m-lp1.baas.nintendo.com) to our server and the
// system-ssl cert-bypass trusts our cert, so the Switch's fetch + token POST land here.
// The id_token/access_token are RS256-signed with the SAME fixed RSA private key whose
// public half is published in the JWKS (kid must match the token header). Every request
// is logged (SNI/host/path/body) so we learn the exact BAAS protocol the console speaks.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func b64urlJSON(v any) string {
	b, _ := json.Marshal(v)
	return b64url(b)
}

func loadPrivateKey(path string) *rsa.PrivateKey {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("[baas-jwks] read signing key %s: %v", path, err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		log.Fatalf("[baas-jwks] no PEM block in %s", path)
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rk, ok := k.(*rsa.PrivateKey); ok {
			return rk
		}
	}
	if rk, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return rk
	}
	log.Fatalf("[baas-jwks] cannot parse RSA private key in %s", path)
	return nil
}

func main() {
	cert := getenv("CERT_FILE", "/certs/cert.pem")
	key := getenv("KEY_FILE", "/certs/key.pem")
	addr := getenv("BAAS_PORT", ":443")
	keyPath := getenv("BAAS_SIGNING_KEY", "/app/baas_signing_key.pem")
	// kid = key identifier — MUST match the `kid` field in the BAAS id_token that
	// Splatoon 2 verifies. A mismatch → the Switch fetches the JWKS but cannot find the
	// right key by kid → token verification fails → error 2124-3121 on new account login.
	kid := getenv("BAAS_KID", "nextendo-baas-key-1")
	// iss/aud/jku must be the canonical BAAS issuer host. The console fetches the JWKS
	// from <iss>/1.0.0/certificates (this is a DIFFERENT host than the token endpoint
	// m-lp1.baas.nintendo.com) — so that host MUST be DNS-redirected to this server,
	// otherwise the Switch fetches real Nintendo's JWKS (no matching kid) → 2124-3121.
	issuer := getenv("BAAS_ISSUER", "https://e0d67c509fb203858ebcb2fe3f88c2aa.baas.nintendo.com")
	kidBaasID := getenv("BAAS_ID_KID", "00000000-0000-0000-0000-000000000002")
	kidBaasAccess := getenv("BAAS_ACCESS_KID", "00000000-0000-0000-0000-000000000003")
	jwksPath := getenv("BAAS_JWKS_PATH", "/1.0.0/certificates")

	priv := loadPrivateKey(keyPath)
	pub := &priv.PublicKey
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	nB64, eB64 := b64url(pub.N.Bytes()), b64url(eBytes)
	mkKey := func(k string) map[string]any {
		return map[string]any{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": k, "n": nB64, "e": eB64}
	}
	jwks := map[string]any{"keys": []map[string]any{
		mkKey(kid), mkKey(kidBaasID), mkKey(kidBaasAccess),
	}}
	jwksJSON, _ := json.Marshal(jwks)

	// mintToken signs an RS256 JWT (id_token or access_token) with the BAAS key. The
	// provided claims map is serialized as the payload; iss/jku must be derived from the
	// baas host the console actually contacted so the jku it fetches lands back on this server.
	mintToken := func(typ string, claims map[string]any) string {
		header := b64urlJSON(map[string]any{"alg": "RS256", "kid": kid, "typ": typ})
		payload := b64urlJSON(claims)
		sum := sha256.Sum256([]byte(header + "." + payload))
		sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
		if err != nil {
			log.Printf("[baas-jwks] sign error: %v", err)
			return ""
		}
		return header + "." + payload + "." + b64url(sig)
	}

	// newJTI returns a random UUID-ish token id.
	newJTI := func() string {
		b := make([]byte, 16)
		rand.Read(b)
		return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
	}

	// decodeAssertion parses the Nintendo-account id_token (the `assertion` the console
	// POSTs) and returns its claims. Signature verification against the dauth `jku` is
	// intentionally skipped in this fully self-hosted setup — the assertion originates from
	// our own account server, so we trust it and just extract the real `sub`/`aud`.
	decodeAssertion := func(assertion string) (map[string]json.RawMessage, bool) {
		parts := strings.Split(assertion, ".")
		if len(parts) != 3 {
			return nil, false
		}
		pb, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, false
		}
		var claims map[string]json.RawMessage
		if err := json.Unmarshal(pb, &claims); err != nil {
			return nil, false
		}
		return claims, true
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		sni := ""
		if r.TLS != nil {
			sni = r.TLS.ServerName
		}
		log.Printf("[baas-jwks] >>> SNI=%q %s %s%s", sni, r.Method, r.Host, r.URL.Path)

		isJWKS := r.URL.Path == jwksPath || r.URL.Path == "/1.0.0/certificates" || r.URL.Path == "/1.0.0/internal_certificates"
		isToken := strings.Contains(r.URL.Path, "application/token") ||
			strings.HasSuffix(r.URL.Path, "/token") || r.URL.Path == "/token"

		if isJWKS {
			w.Header().Set("Content-Type", "application/json")
			w.Write(jwksJSON)
			log.Printf("[baas-jwks]     served JWKS (kid=%s)", kid)
			return
		}
		if isToken {
			body, _ := io.ReadAll(r.Body)
			log.Printf("[baas-jwks]     TOKEN body=%q", string(body))
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ParseForm()
			assertion := r.FormValue("assertion")

			// Bind the BAAS id_token subject to the REAL Nintendo account id the console
			// proved via the assertion. A wrong `sub` (e.g. a placeholder) makes the console
			// reject the token → error 2124-3121 on account link.
			sub := "nextendo"
			var nintendo json.RawMessage
			if assertion != "" {
				if claims, ok := decodeAssertion(assertion); ok {
					if v, ok := claims["sub"]; ok {
						var s string
						if json.Unmarshal(v, &s) == nil && s != "" {
							sub = s
						}
					}
					if v, ok := claims["nintendo"]; ok {
						nintendo = v
					}
				}
			}
			// iss/aud/jku MUST be the canonical BAAS issuer host (e0d67c…baas.nintendo.com),
			// not the token-endpoint host. The Switch fetches the JWKS from <iss>/1.0.0/certificates
			// (a different host, DNS-redirected to us) to verify the token signature.
			iss := issuer
			aud := issuer
			now := time.Now().Unix()
			idClaims := map[string]any{
				"iss": iss,
				"sub": sub,
				"aud": aud,
				"jku": iss + "/1.0.0/certificates",
				"iat": now,
				"exp": now + 3600,
				"jti": newJTI(),
			}
			if len(nintendo) > 0 {
				idClaims["nintendo"] = nintendo
			}
			accessClaims := map[string]any{
				"iss": iss,
				"sub": sub,
				"aud": aud,
				"jku": iss + "/1.0.0/internal_certificates",
				"iat": now,
				"exp": now + 3600,
				"jti": newJTI(),
			}
			idToken := mintToken("id_token", idClaims)
			accessToken := mintToken("access_token", accessClaims)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": accessToken,
				"id_token":     idToken,
				"token_type":   "Bearer",
				"expires_in":   3600,
				"scope":        "openid",
			})
			log.Printf("[baas-jwks]     minted id_token (sub=%s aud=%s iss=%s)", sub, aud, iss)
			log.Printf("[baas-jwks]     DEBUG id_token=%s", idToken)
			log.Printf("[baas-jwks]     DEBUG access_token=%s", accessToken)
			return
		}
		// Unknown BAAS endpoint — log it so we discover what else S2 needs, return empty 404.
		w.WriteHeader(http.StatusNotFound)
	})

	log.Printf("[baas-jwks] serving JWKS + token endpoint (kid=%s) at %s on %s (signing key=%s)", kid, jwksPath, addr, keyPath)
	log.Fatal((&http.Server{Addr: addr, Handler: mux}).ListenAndServeTLS(cert, key))
}
