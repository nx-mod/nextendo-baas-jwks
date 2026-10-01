# TODO — baas-jwks

## In progress

- **Linking an offline user, 2124-3121 after `PATCH users/<id>`**: PATCHes are now kept and echoed; retest.
- **penne frontline: ON, a session holds** (`BAAS_PENNE_FRONTLINE=1`): handshake, record sync, topic subscriptions
  and keepalive work against a console on 22.5.0. Not done: pushing a notification (below).

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
   - Live exchange with a console (2026-09-30), server replies in brackets:
     [HandoverResult] -> console `RootHash`: envelope string "NX", two timestamps (now, now + 1 h), and four
     record sets with a SHA-1 each: `c-appearance`, `c-friends`, `c-settings`, `c-storage`.
     [RootHash with an EMPTY list] -> console `SyncComplete`, then `SubscribeTopic` {1: flag = 1, 2: empty list,
     3: topic} (seen: `nx_data_010064800f66a000`, `nx_notice`): accepted, no Reset. This is the working path.
     [RootHash echoing the four sets] -> console `LeafHash` {0: "c-appearance", 1: no leaves}, then it expects
     PutRecord/DeleteRecord; a SyncComplete there -> `Reset` {0: 401, 1: 1, 2: "PutRecord/DeleteRecord expected,
     but "SyncComplete"(8) received."} and an immediate reconnect loop (rate-limit any experiment).
     [Ack {0: topic}] after SubscribeTopic -> **npns aborted** (crash above). The console waits 10 s for the
     answer (0x4f754dd590: pending key at +0x9370 = the topic, kind at +0x93a0, flag +0x9368); the Ack handler
     (0x4f754deab0) asserts on state, the pending flag and the key, then acts by kind. Which check failed is
     unknown: read the crash report's PC before trying any reply again.
   - Crash report read (PC in the Ack handler, 0x4f754debc8): the failed check is the key comparison. Pending
     keys by request kind (the senders at 0x4f754dd590..0x4f754de5b0): kinds 0 and 1 = the record's own name,
     kind 2 = the literal `topic.subscription`, kinds 3-7 = a 16-hex-digit id (kind 6: two, `a/b`), kind 10 =
     another stored string. **Not confirmed:** which kind sends message type 23 (SubscribeTopic); kind 2 is the
     likely one. No reply is sent until that is confirmed; an Ack with a wrong key always aborts npns.
   - A Reset from the console carries the reason as text: the best debugging aid in this protocol.
   - **Working session (2026-09-30):** [HandoverResult] -> RootHash; [RootHash, no sets] -> SyncComplete, then one
     SubscribeTopic per topic (`nx_data_<title>`, `nx_news`, `nx_notice`, `nx_news_nextendo`), each answered
     [Ack {0: "topic.subscription"}] (confirmed: four in a row accepted, so that is the key and SubscribeTopic is
     request kind 2). Keepalive: [Ping {0: u64}] every 30 s -> console Pong {0: the same value}; npns asserts on
     a second Ping before the Pong (0x4f754df880), so one at a time. Without traffic the console reconnects
     after about 4.5 minutes; `GET /v1/frontlines` then reports `X-Fro-Result: 000-0000`.
   - A server Pong is only valid as the answer to a Ping the console sent (0x4f754df9e0 asserts otherwise).
   - Next: how a notification reaches the console (steady state accepts PutRecord, DeleteRecord, Ack, Reset,
     Ping, Pong, Idle, Nack, SubscriptionList, SubscriptionUpdated, Hi), so bcat fetches a topic at once.
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
