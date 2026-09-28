# nextendo-baas-jwks (nx-mod testing)

nx-mod's `testing` fork of [baas-jwks](https://github.com/NextendoNetwork/baas-jwks): Serves the JWK Set for BAAS id_token verification. Part of the Nextendo Network stack.
Part of [nextendo-testing](https://github.com/nx-mod/nextendo-testing): the whole Nextendo Network, run on a LAN. Upstream's README is kept as [README.upstream.md](README.upstream.md).

## nx-mod changes

- Signs with an RSA key from disk and publishes its JWK.
- **BaaS for a real console:** camelCase token replies (without them the console shows 2124-3121), `/1.0.0/users` registration, device-account `/1.0.0/login` and `/federation` mapped to the console's user (`BAAS_USERS_FILE`), `users/<id>`, `devices/snapshot`, empty friends/blocks lists; the login idToken carries the signed Nextendo identity (`nnex`) the game servers check.

## Credits

baas-jwks is the work of the **Nextendo Network team** — https://nextendo.network. nx-mod only adds the changes above, for LAN testing. Nextendo is awesome.
