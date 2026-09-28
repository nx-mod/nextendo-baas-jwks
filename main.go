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
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/jpeg"
	_ "image/png"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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

// The Nextendo secret (hex, NEXTENDO_SECRET_FILE), shared with nextendo-account and the game servers: it
// signs the "nx2." identity in a login's idToken, as nextendo-account's signNexToken does.
var nextendoSecret = func() []byte {
	b, err := os.ReadFile(getenv("NEXTENDO_SECRET_FILE", "nextendo_secret.key"))
	if err != nil {
		return nil
	}
	dec, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(dec) < 16 {
		return nil
	}
	return dec
}()

func signNex(pid uint64, name string) string {
	if len(nextendoSecret) == 0 {
		return ""
	}
	payload := fmt.Sprintf("%d.%s.%d", pid, name, time.Now().Add(30*24*time.Hour).Unix())
	mac := hmac.New(sha256.New, nextendoSecret)
	mac.Write([]byte("nex:" + payload))
	return "nx2." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// BaaS users: a device account (what a console logs in with) belongs to a user (its NSA id, which the
// console stored when it registered and checks against every login reply). Kept in BAAS_USERS_FILE:
//
//	{"<device account id>": {"user": "<user id>", "na": "<Nintendo Account id>", "password": "..."}}
//
// A console registered elsewhere (production) is added by hand with the ids its old login replies show.
type baasUser struct {
	User     string `json:"user"`
	NA       string `json:"na,omitempty"`
	Password string `json:"password,omitempty"`
	Country  string `json:"country,omitempty"` // naCountry from the console's last login
}

// accountProfile is what a user reply needs from the Nextendo account (nextendo-account /internal/identity).
type accountProfile struct {
	FriendCode     string `json:"friendCode"`
	Avatar         string `json:"avatar"` // base64 image, "" if none
	ImageUpdatedAt int64  `json:"imageUpdatedAt"`
}

func profileFor(pid uint64) accountProfile {
	var p accountProfile
	if pid == 0 {
		return p
	}
	req, _ := http.NewRequest("GET", getenv("BAAS_ACCOUNT_URL", "http://127.0.0.1:8080")+"/internal/identity?pid="+strconv.FormatUint(pid, 10), nil)
	req.Header.Set("X-Internal-Key", os.Getenv("NEXTENDO_INTERNAL_KEY"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return p
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		json.NewDecoder(resp.Body).Decode(&p)
	}
	return p
}

// The host production serves user thumbnails from (thumbnailUrl / thumbnail2Url); DNS-redirected here.
const cdnImage = "https://cdn-image-e0d67c509fb203858ebcb2fe3f88c2aa.baas.nintendo.com"

// completeUser fills what production always sends for a user and a console checks once a Nintendo Account is
// linked: the country, a real friend code, and thumbnails (served by this server, from the account's avatar).
func completeUser(u map[string]any, userID string, pid uint64, country string) {
	if country == "" {
		country = "US"
	}
	u["country"] = country
	p := profileFor(pid)
	const created = int64(1550779720)
	fc := strings.TrimPrefix(p.FriendCode, "SW-")
	if fc == "" {
		n, _ := strconv.ParseUint(userID, 16, 64)
		d := fmt.Sprintf("%012d", n%1_000_000_000_000)
		fc = d[0:4] + "-" + d[4:8] + "-" + d[8:12]
	}
	if links, ok := u["links"].(map[string]any); ok {
		links["friendCode"] = map[string]any{"createdAt": created, "id": fc, "regenerable": true,
			"regenerableAt": created + 30*24*3600, "updatedAt": created}
	}
	uploaded := p.ImageUpdatedAt
	if uploaded == 0 {
		uploaded = created
	}
	u["thumbnailUrl"] = cdnImage + "/1/" + userID
	u["thumbnail2Url"] = cdnImage + "/2/" + userID
	u["thumbnailUploadedAt"] = uploaded
}

// thumbnail answers GET /1/<user> and /2/<user> (cdn-image host): the account's avatar as a JPEG, or a
// plain Nextendo-red square when it has none.
func imagesDir() string { return getenv("BAAS_IMAGES_DIR", "images") }

func thumbnail(w http.ResponseWriter, userID string) {
	if b, err := os.ReadFile(filepath.Join(imagesDir(), userID+".jpg")); err == nil { // uploaded by the console
		w.Header().Set("Content-Type", "image/jpeg")
		w.Write(b)
		return
	}
	pid, _ := nextendoAccountFor(userID)
	var img image.Image
	if raw, err := base64.StdEncoding.DecodeString(profileFor(pid).Avatar); err == nil && len(raw) > 0 {
		img, _, _ = image.Decode(bytes.NewReader(raw))
	}
	if img == nil {
		m := image.NewRGBA(image.Rect(0, 0, 256, 256))
		draw.Draw(m, m.Bounds(), &image.Uniform{color.RGBA{230, 0, 18, 255}}, image.Point{}, draw.Src)
		img = m
	}
	w.Header().Set("Content-Type", "image/jpeg")
	jpeg.Encode(w, img, &jpeg.Options{Quality: 90})
}

var (
	baasUsersMu sync.Mutex
	baasUsers   = map[string]baasUser{}
)

func baasUsersPath() string { return getenv("BAAS_USERS_FILE", "baas_users.json") }

func loadBaasUsers() {
	b, err := os.ReadFile(baasUsersPath())
	if err == nil {
		json.Unmarshal(b, &baasUsers)
	}
	log.Printf("[baas-jwks] %d BaaS users (%s)", len(baasUsers), baasUsersPath())
}

func saveBaasUsersLocked() {
	b, _ := json.MarshalIndent(baasUsers, "", "  ")
	os.WriteFile(baasUsersPath(), b, 0o600)
}

// baasUserInfo is a user in production's shape (login and registration replies).
func baasUserInfo(userID, deviceID, naID, nickname string, now int64) map[string]any {
	links := map[string]any{
		"friendCode": map[string]any{"id": "", "regenerable": false, "regenerableAt": 0, "createdAt": now, "updatedAt": now},
	}
	if naID != "" {
		links["nintendoAccount"] = map[string]any{"id": naID, "createdAt": 1550779713, "updatedAt": 1550779713}
	}
	perm := map[string]any{"friendRequestReception": true, "friends": "EVERYONE", "presence": "FRIENDS",
		"personalAnalytics": true, "personalNotification": true,
		"presenceUpdatedAt": now, "personalAnalyticsUpdatedAt": now, "personalNotificationUpdatedAt": now}
	extras := map[string]any{"self": map[string]any{"playLog": ""}, "favoriteFriends": map[string]any{"playLog": ""},
		"friends": map[string]any{"playLog": ""}, "foaf": map[string]any{"playLog": ""}, "everyone": map[string]any{"playLog": ""}}
	return map[string]any{
		"id": userID, "etag": fmt.Sprintf("\"%s\"", randHex(8)), "nickname": nickname, "nicknameUpdatedAt": now,
		"country": "", "birthday": "0000-00-00", "thumbnailUrl": "", "thumbnail2Url": "", "thumbnailUploadedAt": 0,
		"deviceAccounts": []map[string]any{{"id": deviceID}}, "links": links, "permissions": perm, "extras": extras,
		"deleted": false, "blocksUpdatedAt": now, "friendsUpdatedAt": now, "createdAt": now, "updatedAt": now,
	}
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// nextendoAccountFor maps a BaaS user id (16 hex digits) to its Nextendo account through nextendo-account's
// /api/nsa, which takes the id in decimal. 0 if there is none.
func nextendoAccountFor(userID string) (uint64, string) {
	n, err := strconv.ParseUint(userID, 16, 64)
	if err != nil {
		return 0, ""
	}
	resp, err := http.Get(getenv("BAAS_ACCOUNT_URL", "http://127.0.0.1:8080") + "/api/nsa?id=" + strconv.FormatUint(n, 10))
	if err != nil {
		log.Printf("[baas-jwks] /api/nsa: %v", err)
		return 0, ""
	}
	defer resp.Body.Close()
	var out struct {
		PID  uint64 `json:"pid"`
		Name string `json:"name"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&out) != nil {
		log.Printf("[baas-jwks] /api/nsa for %s: status %d", userID, resp.StatusCode)
		return 0, ""
	}
	return out.PID, out.Name
}

// penne (push notifications) and vermillion (device) calls the account sysmodule makes around a login, in
// production's shapes (baas-proxy log). A 404 on notification_tokens stops linking an existing user with
// 2124-5404. Login tickets and frontlines stay unanswered (404) unless BAAS_PENNE_FRONTLINE=1: with a
// ticket the console opens the frontline push stream (fro-*.penne, POST /), which is not served; answered
// at once it reconnects every two seconds, and held open it hung System Settings.
var penneFrontlineOn = os.Getenv("BAAS_PENNE_FRONTLINE") == "1"
var penneConnParams = map[string]any{
	"awake":      map[string]any{"count": 2, "disable": false, "idle": 60, "interval": 10},
	"ignore_rst": true, "retry_count": 2, "rtt_max": 1000,
	"sleep":    map[string]any{"count": 1440, "disable": true, "idle": 60, "interval": 10},
	"wait_sec": 3600, "wowl_timeout": 200,
}

const penneFrontline = "fro-1.hac.lp1.penne.srv.nintendo.net"

// accounts/config as production sends it: base64 of
// {"version":{"major":1,"minor":1,"micro":0},"online_license":{"is_available":true},"activity":{...},...}.
const vermillionConfig = "eyJ2ZXJzaW9uIjp7Im1ham9yIjoxLCJtaW5vciI6MSwibWljcm8iOjB9LCJvbmxpbmVfbGljZW5zZSI6eyJpc19hdmFpbGFibGUiOnRydWV9LCJhY3Rpdml0eSI6eyJoYXNfcmVjZWl2ZWRfZ3VpZGFuY2UiOnRydWUsImhhc19pbnNlcnRlZCI6dHJ1ZSwiaGFzX3RyYW5zZmVycmVkX3RvX3ZwaHltIjp0cnVlfSwiZGlzYWJsZWRfY29udGVudCI6eyJjb250ZW50X21ldGFfaWRzIjpbXX0sImhpZGRlbl9rZXkiOnsiYXBwbGljYXRpb25faWRzIjpbXX19"

func pennePresence(w http.ResponseWriter, r *http.Request) bool {
	host, p := strings.ToLower(r.Host), r.URL.Path
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	reply := func(code int, v any) bool {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		if v != nil {
			_ = json.NewEncoder(w).Encode(v)
		}
		return true
	}
	stable := func(kind, id string, n int) []byte { // the same value every time for the same id
		sum := sha256.Sum256([]byte(kind + ":" + id))
		return sum[:n]
	}
	now := time.Now().Unix()
	switch {
	case strings.Contains(host, "penne") && r.Method == http.MethodPost && p == "/v1/login_tickets" && penneFrontlineOn:
		return reply(http.StatusOK, map[string]any{"expires_at": now + 4*24*3600, "frontline_fqdn": penneFrontline,
			"issued_at": now, "persistent_connection_params_simple": penneConnParams, "ticket": randHex(32)})
	case strings.Contains(host, "penne") && r.Method == http.MethodGet && p == "/v1/frontlines" && penneFrontlineOn:
		return reply(http.StatusOK, map[string]any{"current_time": now, "frontline_fqdn": penneFrontline,
			"persistent_connection_params_simple": penneConnParams})
	case strings.Contains(host, "penne") && r.Method == http.MethodPost && strings.HasPrefix(p, "/v1/accounts/") && strings.HasSuffix(p, "/links"):
		// Linking an existing user registers its NSA with penne right after notification_tokens, sending
		// {"penne_id","password","nsa_id_token"}. A 404 ends in 2154-5404 and an empty 204 in 2154-7023, so
		// it wants a JSON body; production's is not captured, so this echoes the link. Only the field names
		// are logged: the body carries the console's penne password.
		var in map[string]any
		json.NewDecoder(r.Body).Decode(&in)
		keys := make([]string, 0, len(in))
		for k := range in {
			keys = append(keys, k)
		}
		log.Printf("[baas-jwks]     penne links fields=%v", keys)
		nsaID := ""
		if tok, _ := in["nsa_id_token"].(string); tok != "" {
			if parts := strings.Split(tok, "."); len(parts) == 3 {
				if raw, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
					var c struct {
						Sub string `json:"sub"`
					}
					json.Unmarshal(raw, &c)
					nsaID = c.Sub
				}
			}
		}
		return reply(http.StatusOK, map[string]any{"nsa_id": nsaID, "penne_id": in["penne_id"], "created_at": now})
	case strings.Contains(host, "penne") && r.Method == http.MethodPost && strings.HasPrefix(p, "/v1/accounts/") && strings.HasSuffix(p, "/notification_tokens"):
		return reply(http.StatusOK, map[string]any{"notification_token": "00" + hex.EncodeToString(stable("npt", p, 17))})
	case strings.Contains(host, "vermillion") && r.Method == http.MethodPost && p == "/v1/devices/initialize":
		return reply(http.StatusNoContent, nil)
	case strings.Contains(host, "vermillion") && r.Method == http.MethodGet && p == "/v1/devices/vermillion-device-id":
		return reply(http.StatusOK, map[string]any{"vermillionDeviceId": base64.StdEncoding.EncodeToString(stable("vdid", r.Header.Get("Authorization"), 16))})
	case strings.Contains(host, "vermillion") && r.Method == http.MethodGet && p == "/v1/accounts/config":
		return reply(http.StatusOK, map[string]any{"payload": vermillionConfig})
	}
	return false
}

// bindBaasUser asks nextendo-account (local open mode) to make userID the NSA id of the account with this PID.
func bindBaasUser(pid uint64, userID string) {
	body, _ := json.Marshal(map[string]any{"pid": pid, "baas": userID})
	req, _ := http.NewRequest("POST", getenv("BAAS_ACCOUNT_URL", "http://127.0.0.1:8080")+"/internal/baas-link", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Key", os.Getenv("NEXTENDO_INTERNAL_KEY"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("[baas-jwks] /internal/baas-link: %v", err)
		return
	}
	resp.Body.Close()
	log.Printf("[baas-jwks]     PID %d now owns BaaS user %s (status %d)", pid, userID, resp.StatusCode)
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

	loadBaasUsers()
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
		// Production's header: typ is always "JWT", and id and access tokens name different keys (both are
		// in the JWKS). The token kind is the "typ" claim.
		k := kidBaasID
		if typ == "token" || typ == "access_token" {
			k = kidBaasAccess
		}
		header := b64urlJSON(map[string]any{"alg": "RS256", "jku": claims["jku"], "kid": k, "typ": "JWT"})
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

		// POST /1.0.0/login (and /1.0.0/federation, the same plus a Nintendo Account id token): the user's
		// session, and the idToken a game hands to its own servers. The console logs in with the device
		// account it registered; that id is used as the user id, mapped to a Nextendo account through
		// nextendo-account's /api/nsa (which creates one in local open mode). The idToken carries the
		// signed "nnex" identity the Nextendo game servers read (Diablo III's gates.go).
		// What the account and friends sysmodules call after login, in production's shapes (taken from the
		// baas-proxy log of a console on real Nextendo): the user itself, the devices snapshot, and lists.
		w.Header().Set("Cache-Control", "no-store, no-cache")
		emptyList := map[string]any{"count": 0, "etag": "", "items": []any{}, "itemsPerPage": 0}
		p := r.URL.Path
		if pennePresence(w, r) {
			return
		}
		if r.Method == http.MethodPost && p == "/1.0.0/devices/snapshot" {
			var in struct {
				UserIDs []string `json:"userIds"`
			}
			body, _ := io.ReadAll(r.Body)
			json.Unmarshal(body, &in)
			if in.UserIDs == nil {
				in.UserIDs = []string{}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"deletedUserIds": []string{}, "persistentUserIds": in.UserIDs})
			return
		}
		if seg := strings.Split(strings.Trim(p, "/"), "/"); len(seg) >= 3 && seg[1] == "users" && len(seg[2]) == 16 {
			userID := strings.ToLower(seg[2])
			if len(seg) == 3 && seg[0] == "1.0.0" && (r.Method == http.MethodGet || r.Method == http.MethodPatch) {
				deviceID, naID, country := "", "", ""
				baasUsersMu.Lock()
				for d, u := range baasUsers {
					if u.User == userID {
						deviceID, naID, country = d, u.NA, u.Country
					}
				}
				baasUsersMu.Unlock()
				pid, name := nextendoAccountFor(userID)
				u := baasUserInfo(userID, deviceID, naID, name, time.Now().Unix())
				completeUser(u, userID, pid, country)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(u)
				return
			}
			// DELETE /1.0.0/users/<user>/device_accounts/<id>: the console drops a device account, e.g. the one of
			// the temporary user it registered before importing a Nintendo Account. Only removed while it still
			// belongs to that user (federation may have moved it to the imported one).
			if len(seg) == 5 && seg[3] == "device_accounts" && r.Method == http.MethodDelete {
				dev := strings.ToLower(seg[4])
				baasUsersMu.Lock()
				if u, ok := baasUsers[dev]; ok && u.User == userID {
					delete(baasUsers, dev)
					saveBaasUsersLocked()
				}
				baasUsersMu.Unlock()
				w.WriteHeader(http.StatusNoContent)
				return
			}
			// POST /1.0.0/users/<user>/device_accounts: a new device account for an existing user (this console
			// joining a user imported from a Nintendo Account); the password is shown once, as at registration.
			if len(seg) == 4 && seg[3] == "device_accounts" && r.Method == http.MethodPost {
				dev, pw := randHex(8), randHex(20)
				naID := ""
				baasUsersMu.Lock()
				for _, u := range baasUsers {
					if u.User == userID && u.NA != "" {
						naID = u.NA
					}
				}
				baasUsers[dev] = baasUser{User: userID, Password: pw, NA: naID}
				saveBaasUsersLocked()
				baasUsersMu.Unlock()
				now := time.Now().Unix()
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]any{"id": dev, "password": pw, "createdAt": now, "updatedAt": now})
				log.Printf("[baas-jwks]     device account %s added to user %s", dev, userID)
				return
			}
			if r.Method == http.MethodGet { // blocks, friends, friend_requests/inbox, ...: nothing yet
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(emptyList)
				return
			}
		}
		// PUT /1.0.0/push_channels/<user>/<device account> {"service","deviceToken","deviceAttributes"}: the
		// console registers its push channel after penne links, while linking an existing user (a 404 gave
		// 2154-7062). Not captured from production; stored nowhere, echoed back as the resource.
		if seg := strings.Split(strings.Trim(p, "/"), "/"); r.Method == http.MethodPut && len(seg) == 4 && seg[0] == "1.0.0" && seg[1] == "push_channels" {
			var in map[string]any
			json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in)
			if in == nil {
				in = map[string]any{}
			}
			now := time.Now().Unix()
			in["userId"], in["deviceAccountId"], in["createdAt"], in["updatedAt"] = seg[2], seg[3], now, now
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(in)
			return
		}
		// POST /1.0.0/image_upload {"rawContent": base64 JPEG, "ownerId": user, "allowTransform"}: the console
		// uploads the user's profile picture; a 404 ends linking a Nintendo Account in 2124-7962. Kept in
		// BAAS_IMAGES_DIR as <user>.jpg and served as the user's thumbnails. Production's reply is not
		// captured: the thumbnails' URLs.
		if r.Method == http.MethodPost && p == "/1.0.0/image_upload" {
			var in struct {
				RawContent string `json:"rawContent"`
				OwnerID    string `json:"ownerId"`
			}
			json.NewDecoder(io.LimitReader(r.Body, 8<<20)).Decode(&in)
			owner := strings.ToLower(in.OwnerID)
			raw, err := base64.StdEncoding.DecodeString(in.RawContent)
			if len(owner) != 16 || err != nil || len(raw) == 0 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			os.MkdirAll(imagesDir(), 0o755)
			os.WriteFile(filepath.Join(imagesDir(), owner+".jpg"), raw, 0o644)
			log.Printf("[baas-jwks]     profile image for user %s (%d bytes)", owner, len(raw))
			// The reply is the stored image, in the shape NintendoClients' wiki documents (BAAS Server,
			// POST /1.0.0/image_upload); a user object or bare thumbnail URLs gave 2124-3121. The console
			// then sets the user's thumbnailUrl to content.url.
			width, height := 256, 256
			if cfg, _, err := image.DecodeConfig(bytes.NewReader(raw)); err == nil {
				width, height = cfg.Width, cfg.Height
			}
			imgID, now := randHex(16), time.Now().Unix()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": imgID, "ownerId": owner, "owner": map[string]any{"id": owner}, "state": "STORED",
				"content": map[string]any{"id": imgID, "width": width, "height": height, "format": "jpg",
					"url": cdnImage + "/1/" + owner, "urlExpiresAt": 2147483647},
				"createdAt": now, "updatedAt": now,
			})
			return
		}
		// Thumbnails (cdn-image host): /1/<user> and /2/<user>, see completeUser.
		if seg := strings.Split(strings.Trim(p, "/"), "/"); r.Method == http.MethodGet && len(seg) == 2 && (seg[0] == "1" || seg[0] == "2") && len(seg[1]) == 16 {
			thumbnail(w, strings.ToLower(seg[1]))
			return
		}
		if r.Method == http.MethodGet && p == "/1.0.0/users" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(emptyList)
			return
		}

		// POST /1.0.0/users: a console registers a new user; it gets a device account with a password,
		// which it keeps and logs in with from then on (201, user info with the password shown once).
		if r.Method == http.MethodPost && r.URL.Path == "/1.0.0/users" {
			deviceID, userID, pw := randHex(8), randHex(8), randHex(20)
			baasUsersMu.Lock()
			baasUsers[deviceID] = baasUser{User: userID, Password: pw}
			saveBaasUsersLocked()
			baasUsersMu.Unlock()
			u := baasUserInfo(userID, deviceID, "", "", time.Now().Unix())
			u["deviceAccounts"] = []map[string]any{{"id": deviceID, "password": pw}}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(u)
			log.Printf("[baas-jwks]     registered user %s (device account %s)", userID, deviceID)
			return
		}

		if r.Method == http.MethodPost && (r.URL.Path == "/1.0.0/login" || r.URL.Path == "/1.0.0/federation") {
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			log.Printf("[baas-jwks]     LOGIN %s id=%s appAuthNToken=%v naCountry=%s", r.URL.Path, form.Get("id"), form.Get("appAuthNToken") != "", form.Get("naCountry"))
			deviceID := strings.ToLower(form.Get("id"))
			baasUsersMu.Lock()
			bu, known := baasUsers[deviceID]
			baasUsersMu.Unlock()
			if len(deviceID) != 16 || !known {
				// Not registered here: real BaaS answers 401 invalid_grant, and the console registers again.
				log.Printf("[baas-jwks]     login: device account %q unknown (add it to %s, or let the console register)", deviceID, baasUsersPath())
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]any{"errorCode": "invalid_grant", "type": "https://e0d67c509fb203858ebcb2fe3f88c2aa.baas.nintendo.com/errors/invalid_grant", "title": "Invalid grant", "status": 401})
				return
			}
			userID := bu.User
			if c := form.Get("naCountry"); c != "" && c != bu.Country {
				baasUsersMu.Lock()
				bu.Country = c
				baasUsers[deviceID] = bu
				saveBaasUsersLocked()
				baasUsersMu.Unlock()
			}
			// Federation (link or import a Nintendo Account): the console keeps the user it registered (it
			// refuses a reply naming another user: 2124-0292), now linked to the Nintendo Account. nnaccount's
			// id_token names the Nextendo account (sub = Nintendo Account id, nintendo.ai = that account's
			// current BaaS user id), and nextendo-account (local open mode) makes this user its NSA id, so
			// /api/nsa, the game servers and nnex all resolve it to the account that signed in.
			if r.URL.Path == "/1.0.0/federation" {
				naID, ai := "", ""
				if claims, ok := decodeAssertion(form.Get("idToken")); ok {
					json.Unmarshal(claims["sub"], &naID)
					var nin struct {
						AI string `json:"ai"`
					}
					json.Unmarshal(claims["nintendo"], &nin)
					ai = strings.ToLower(nin.AI)
				}
				if naID != "" {
					baasUsersMu.Lock()
					bu.NA = naID
					baasUsers[deviceID] = bu
					saveBaasUsersLocked()
					baasUsersMu.Unlock()
				}
				if len(ai) == 16 && ai != userID {
					if pid, _ := nextendoAccountFor(ai); pid != 0 {
						bindBaasUser(pid, userID)
					}
				}
				log.Printf("[baas-jwks]     federation: Nintendo Account %s linked to user %s (Nextendo account of BaaS user %s)", naID, userID, ai)
			}
			pid, name := nextendoAccountFor(userID)
			now := time.Now().Unix()
			const gameAud = "ed9e2f05d286f7b8" // the aud production puts in login tokens
			idClaims := map[string]any{
				"iss": issuer, "sub": userID, "aud": gameAud, "jku": issuer + "/1.0.0/certificates",
				"typ": "id_token", "bs:did": deviceID, "iat": now, "exp": now + 10800, "jti": newJTI(),
			}
			if pid != 0 {
				if nnex := signNex(pid, name); nnex != "" {
					idClaims["nnex"] = nnex
				}
			}
			accessClaims := map[string]any{
				"iss": issuer, "sub": userID, "aud": gameAud, "jku": issuer + "/1.0.0/internal_certificates",
				"typ": "token", "bs:did": deviceID, "bs:grt": 2, "iat": now, "exp": now + 10800, "jti": newJTI(),
			}
			if name == "" {
				name = "Player"
			}
			user := baasUserInfo(userID, deviceID, bu.NA, name, now)
			completeUser(user, userID, pid, bu.Country)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store, no-cache")
			// Production's shape: exactly these five keys.
			_ = json.NewEncoder(w).Encode(map[string]any{
				"expiresIn": 10800, "user": user,
				"idToken": mintToken("id_token", idClaims), "accessToken": mintToken("token", accessClaims),
				"tokenType": "Bearer",
			})
			log.Printf("[baas-jwks]     login ok: user %s -> Nextendo PID %d (%s)", userID, pid, name)
			return
		}

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
			w.Header().Set("Cache-Control", "no-store, no-cache")
			// Real BaaS answers in camelCase (expiresIn, accessToken, tokenType). A console reads only
			// those: with snake_case alone it reported 2124-3121 ("BaaS server returned invalid
			// response but http status indicates success"). The snake_case copies stay for older clients.
			_ = json.NewEncoder(w).Encode(map[string]any{
				"expiresIn":    10800,
				"accessToken":  accessToken,
				"tokenType":    "Bearer",
				"idToken":      idToken,
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
		// Unknown endpoint: 404, logging the field names of a JSON body (not the values: they can be
		// passwords or tokens) so the next missing call shows its shape.
		var in map[string]any
		json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in)
		keys := make([]string, 0, len(in))
		for k := range in {
			keys = append(keys, k)
		}
		log.Printf("[baas-jwks]     NOT HANDLED -> 404, body fields=%v", keys)
		w.WriteHeader(http.StatusNotFound)
	})

	log.Printf("[baas-jwks] serving JWKS + token endpoint (kid=%s) at %s on %s (signing key=%s)", kid, jwksPath, addr, keyPath)
	log.Fatal((&http.Server{Addr: addr, Handler: mux}).ListenAndServeTLS(cert, key))
}
