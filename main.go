// baas-jwks: serves the public JWK Set at the BAAS id_token's `jku` URL so that Splatoon 2
// (which, unlike MK8, LOCALLY verifies the id_token Ryujinx mints) can fetch the matching
// public key and validate the RS256 signature. The emulator DNS-mitm redirects the baas host
// (e.g. <hex>.baas.nintendo.com) to our server and the system-ssl cert-bypass trusts our cert,
// so S2's fetch of `<iss>/1.0.0/certificates` lands here. The JWK is derived from the SAME
// fixed RSA private key that Ryujinx's ManagerServer.GenerateIdToken() now signs with (kid
// must match the token header). Every other path is logged + 404'd so we learn what else S2
// asks the BAAS host for (token endpoints, NSA, etc.).
package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"net/http"
	"os"
)

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func loadPublicKey(path string) *rsa.PublicKey {
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
			return &rk.PublicKey
		}
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return &k.PublicKey
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
	// Ryujinx-Nextendo signs (ManagerServer.cs hardcodes "nextendo-baas-key-1").
	// A mismatch → the Switch fetches the JWKS but cannot find the right key by kid
	// → token verification fails → error 2124-3121 on new account login.
	kid := getenv("BAAS_KID", "nextendo-baas-key-1")
	jwksPath := getenv("BAAS_JWKS_PATH", "/1.0.0/certificates")
	// Kids DISTINCTS par émetteur pour l'import Switch (la console lie kid<->issuer et rejette
	// à l'import si un même kid sert accounts ET baas). On publie la MÊME clé RSA sous plusieurs
	// kids : baas-key-1 (Splatoon 2/Ryujinx), + les kids baas du vrai flux Switch.
	kidBaasID := getenv("BAAS_ID_KID", "00000000-0000-0000-0000-000000000002")
	kidBaasAccess := getenv("BAAS_ACCESS_KID", "00000000-0000-0000-0000-000000000003")

	pub := loadPublicKey(keyPath)
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	nB64, eB64 := b64url(pub.N.Bytes()), b64url(eBytes)
	mkKey := func(k string) map[string]any {
		return map[string]any{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": k, "n": nB64, "e": eB64}
	}
	jwks := map[string]any{"keys": []map[string]any{
		mkKey(kid), mkKey(kidBaasID), mkKey(kidBaasAccess),
	}}
	jwksJSON, _ := json.Marshal(jwks)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		sni := ""
		if r.TLS != nil {
			sni = r.TLS.ServerName
		}
		log.Printf("[baas-jwks] >>> SNI=%q %s %s%s", sni, r.Method, r.Host, r.URL.Path)
		// /1.0.0/internal_certificates = le jku des accessToken BAAS (login + application/token).
		// SANS lui la Switch ne peut pas vérifier l'accessToken -> 2124-3180 (cause racine).
		if r.URL.Path == jwksPath || r.URL.Path == "/1.0.0/certificates" || r.URL.Path == "/1.0.0/internal_certificates" {
			w.Header().Set("Content-Type", "application/json")
			w.Write(jwksJSON)
			log.Printf("[baas-jwks]     served JWKS (kid=%s)", kid)
			return
		}
		// Unknown BAAS endpoint — log it so we discover what else S2 needs, return empty 404.
		w.WriteHeader(http.StatusNotFound)
	})

	log.Printf("[baas-jwks] serving JWKS (kid=%s) at %s on %s (signing key=%s)", kid, jwksPath, addr, keyPath)
	log.Fatal((&http.Server{Addr: addr, Handler: mux}).ListenAndServeTLS(cert, key))
}
