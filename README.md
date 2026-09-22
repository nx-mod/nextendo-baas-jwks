<h1 align="center">baas-jwks</h1>

<p align="center"><b>Serves the JWK Set that lets a client verify a BAAS <code>id_token</code> signature.</b></p>

<p align="center">
  <img src="https://img.shields.io/badge/license-PolyForm%20Shield%201.0.0-orange" alt="License">
  <img src="https://img.shields.io/badge/go-1.21%2B-00ADD8" alt="Go">
</p>

---

Part of the [Nextendo Network](https://nextendo.network) stack. Some titles locally verify the
account (BAAS) `id_token` before allowing online entry: they fetch the JSON Web Key Set from the
token's `jku` URL and check the RS256 signature against the matching public key.

**baas-jwks** answers that fetch. It publishes the **public** JWK derived from the RSA key the client
signs its `id_token` with (the `kid` matches the token header). It ships **no private key**: the
signing key is supplied to the signer separately, at runtime. Every other path is logged and 404'd.

Configuration is through environment variables; no secrets or infrastructure addresses are baked in.

## License

Released under the **[PolyForm Shield License 1.0.0](LICENSE.md)**, source-available.
