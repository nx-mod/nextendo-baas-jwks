# Fixed — baas-jwks

- **Linking an offline user failed** (2154-5404/7023/7062, 2124-7962, 2124-3121), one step at a time: federation keeps the
  console's user and links it; penne `notification_tokens` and `links`; `push_channels`; `image_upload` in the
  documented shape; thumbnails served.
- **Import**: federation answers as production does (the Nintendo Account's user, the temporary device account moved).
- **Linked user replies**: country, friend code and thumbnails as production sends them; login reply without `summary`.
- **Token headers**: `typ: JWT`, separate id/access key ids, as production.
- **Test Connection**: connection-test API (`/v1/ip`, `/v1/time`) in production's JSON.
- **Users with a Nintendo Account couldn't be opened or deleted**: NSO membership (`capi.lp1.op2`) answered.
- **vermillion calls 404**: `devices/initialize`, `vermillion-device-id`, `accounts/config`.
- **Push (penne) frontline**: a console now holds a session: HandoverResult, record sync, an Ack per topic
  subscription, Ping/Pong keepalive (was: a 404 reconnect loop, then a hang when held open with nothing sent).
- **User PATCH ignored**: `/nickname`, `/extras/self/nxAccount`, `/thumbnailUrl`... are kept
  (`baas_user_patches.json`) and in every user reply; `thumbnailUploadedAt` follows the uploaded image.
- **Device tokens in the log**: `/token` requests are logged by field name only.
- **Unknown requests**: logged with their body's field names (never values).

## Credits

- [kinnay/NintendoClients wiki](https://github.com/kinnay/NintendoClients/wiki) — BaaS (`image_upload`), connection test, NSO.
- The whole Nextendo Network team — https://nextendo.network. Nextendo is awesome.
