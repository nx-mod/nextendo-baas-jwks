# TODO — baas-jwks

## In progress

- **Linking an offline user, 2124-3121 after `PATCH users/<id>`**: PATCHes are now kept and echoed; retest.
- **penne frontline capture**: login tickets and frontlines are on (`BAAS_PENNE_FRONTLINE=1`); the frontline stream
  (`fro-*.penne`, HTTP/2 `POST /`) is recorded to `BAAS_FRONTLINE_DIR` (headers + 15 s of body), then closed.

## Penne (push, firmware 18+; replaces NPNS)

1. **Frontline protocol**: read it from the capture; if needed, reverse the npns sysmodule (as bcat was).
2. **Push**: the message that makes a console fetch now; bcat-nx sends it when a news file changes.
3. **penne-nx**: move penne out of baas-jwks into its own server and repo (`nextendo-penne-nx`).
- Known and answered: `notification_tokens`, `links`, `push_channels` (BaaS), `login_tickets`, `frontlines`.
- Unknown: `immigrate`, `penne_ids`; `DELETE accounts/<id>` and `DELETE .../links` not answered yet.

## Left

- **Import a new account** on a console: answered as production does; untested with a brand-new account.
- **Consoles linked on production**: their device accounts must be added to `baas_users.json` by hand; automate.
- **Guessed replies** (penne `links`, `push_channels`): pass on 22.5.0, no capture to confirm.

## Credits

- [kinnay/NintendoClients wiki](https://github.com/kinnay/NintendoClients/wiki) — BaaS, penne, NSO references.
- The whole Nextendo Network team — https://nextendo.network. Nextendo is awesome.
