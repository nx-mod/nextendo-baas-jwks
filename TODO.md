# TODO — baas-jwks

## In progress

- **Linking an offline user, 2124-3121 after `PATCH users/<id>`**: PATCHes are now kept and echoed; retest.
- **penne frontline capture**: login tickets and frontlines are on (`BAAS_PENNE_FRONTLINE=1`); the frontline stream
  (`fro-*.penne`, HTTP/2 `POST /`) is recorded to `BAAS_FRONTLINE_DIR` (headers + 15 s of body), then closed.

## Penne (push, firmware 18+; replaces NPNS)

1. **Frontline protocol**: being reversed from the npns sysmodule (22.5.0). Known so far:
   - Request (captured): HTTP/2 `POST /`, `Content-Type: application/x-www-form-urlencoded`, `X-Protocol-Version: 4`,
     `X-Hug: true`, `X-Network-Type`, `X-Power-State`, `X-System-Version`, `Authorization` (the login ticket);
     empty body: the console only listens.
   - `GET /v1/frontlines` carries the last attempt's outcome as request headers (`X-NPC`, `X-Login-Try`,
     `X-Fro-Result`, `X-Tolerant`); its reply's `current_time` must be within 3 minutes of the console's clock.
   - Commands it expects down the stream, in order: `HandoverResult`, then `LeafHash`/`RootHash` (a record-set
     sync), then steady state `PutRecord`/`DeleteRecord` (records such as `topic.subscription`). Errors:
     `ProtocolVersionError`, `TwinRecordParseError`.
   - Wire encoding: FlatBuffers, one table per message with a union `command`. Union types (22.5.0):
     1 MessageRequest, 2 PublishRequest, 3 KickRequest, 4 PutRecord, 5 DeleteRecord, 6 RootHash, 7 LeafHash,
     8 SyncComplete, 9 Ack, 10 HandoverRequest, 11 HandoverResponse, 12 HandoverResult, 13 Reset, 14 PowerState,
     15 DebugDisconnect, 16 Ping, 17 Pong, 18 DebugUpdateRecord, 19 DebugDeleteRecord, 20 Idle, 21 PutRequest,
     22 DeleteRequest, 23 SubscribeTopic, 24 Nack, 25 SubscriptionList, 26 ResendRequest, 27 DAPresence,
     28 SubscriptionListRequest, 29 MyAccountMessageRequest, 30 ReloadLink, 31 SubscriptionUpdated, 32 Hi,
     33 Onset, 34 PresenceNotifyRequest, 35 DenySubscribe, 36 TopicRead, 37 CrewNotifyRequest.
   - Steady state accepts 4, 5, 9, 13, 16, 17, 20, 24, 25, 31, 32.
   - Framing: each message is a 4-byte little-endian length (non-zero, within the buffer) then a FlatBuffer.
   - Root table: 0 command type (ubyte), 1 command (union), 2 string, 3 u64, 4 u64.
   - Tables read so far (from the verifier, 0x4f754e2080): Hi and SyncComplete empty; HandoverResult {0: byte};
     Ping {0,1,2: u64}; Pong {0: u64}; Idle {0: u16}. The other 32 are in the same function.
   - A news push carries JSON bcat reads: `type`, `topic_id`, `wait_range`, `ha_wait_range_min/max`, `news_id`,
     `notification_type`, `url`, `one2one`.
   - Upstream (splatoon-3 `gateway.go`) only holds the stream open and sends nothing: no protocol to reuse.
   - Opening sequence (npns 22.5.0, session state at +8):
     1. Connect (0x4f754d9250, state 14 -> 7): `POST https://<frontline_fqdn>/`, `Authorization: Bearer <ticket>`,
        `X-Power-State` awake|sleep, `X-Hug` true|false, `X-Protocol-Version: 4`, `X-System-Version`,
        `X-Network-Type`. `X-Hug: true` = this connection is a handover (what our capture showed).
     2. First message (0x4f754d9730, state 7): within 70 s the server must send `HandoverResult` (12) or
        `Reset` (13). HandoverResult field 0 (byte): 0 or absent = success; non-zero = failed handover
        (0x4f754da010). Anything else: "HandoverResult expected".
     3. Record sync (0x4f754da2f0, states 7/8): `RootHash` (6) / `LeafHash` (7) with 20-byte hashes (SHA-1
        size), `Reset` accepted; then `PutRecord`/`DeleteRecord` (0x4f754dbf20), `SyncComplete`, steady state (8).
   - Next: RootHash/LeafHash/PutRecord layouts and how the console's own hash is built, then a server that sends
     HandoverResult + a matching sync and holds the stream with Ping/Pong.
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
