# CrowdSec bot filtering

Blocks bot/scanner IPs (CVE probing, path traversal probing, bad user
agents, community blocklist, etc.) at the application layer, independent of
whatever reverse proxy sits in front (Coolify's Traefik, etc.).

CrowdSec itself runs as a **separate Coolify resource** (own repo:
[Antiscammer-Dev-team/Crowdsec](https://github.com/Antiscammer-Dev-team/Crowdsec),
same pattern as the Prometheus/Grafana resources) with its own memory
limit — it does not share a filesystem or volume with this app. The two
only talk over the internal `coolify` Docker network, reaching the CrowdSec
container at the fixed name `antiscammerbot-crowdsec` (pinned via `hostname:`
+ a network alias in that repo's `docker-compose.yml`, so it never depends
on the container's actual internal IP):

- The app streams every request as an Apache-combined-format line over
  **syslog** to CrowdSec (`CROWDSEC_SYSLOG_HOST`/`CROWDSEC_SYSLOG_PORT`),
  since that's the format its `crowdsecurity/apache2-logs` parser
  understands, and syslog is a push that works across separate containers
  without a shared volume.
- The app polls CrowdSec's Local API (LAPI) decisions stream
  ([crowdsec_bouncer.py](../crowdsec_bouncer.py)) and rejects requests from
  banned IPs with `403` before any other work happens (auth checks, rate
  limiting, DB calls).

Disabled by default — nothing changes until the env vars below are set.

## Setup

See the [Crowdsec repo](https://github.com/Antiscammer-Dev-team/Crowdsec)'s
own README for deploying that resource. On this app's side, set:

| Var | Default | Purpose |
|-----|---------|---------|
| `CROWDSEC_LAPI_URL` | unset (disabled) | Base URL of the CrowdSec resource's LAPI, e.g. `http://antiscammerbot-crowdsec:8080` |
| `CROWDSEC_BOUNCER_KEY` | unset (disabled) | Bouncer key registered on that LAPI (`BOUNCER_KEY_antiscammerapp` on the CrowdSec resource) |
| `CROWDSEC_POLL_INTERVAL_SEC` | `15` | How often the app refreshes the decisions cache |
| `CROWDSEC_SYSLOG_HOST` | unset (no log sent) | Hostname/alias of the CrowdSec resource, e.g. `antiscammerbot-crowdsec` |
| `CROWDSEC_SYSLOG_PORT` | `9514` | Port CrowdSec's syslog acquisition listens on |
| `CROWDSEC_SYSLOG_PROTO` | `udp` | `udp` or `tcp` |

`CROWDSEC_LAPI_URL`/`CROWDSEC_BOUNCER_KEY` control the ban-check (enforcement).
`CROWDSEC_SYSLOG_HOST` controls whether logs are sent for CrowdSec to score
in the first place. You need both configured for the feature to do anything
useful — LAPI alone with no syslog means CrowdSec never sees this app's
traffic (only the community blocklist would ever ban anyone), and syslog
alone with no LAPI means CrowdSec bans IPs but this app never checks them.

If `CROWDSEC_LAPI_URL` or `CROWDSEC_BOUNCER_KEY` is unset, the bouncer is a
no-op — `crowdsec_bouncer.is_banned()` always returns `False` and no
background polling starts. If `CROWDSEC_SYSLOG_HOST` is unset, no access log
is ever emitted.

## Metrics

Exposed on `/metrics` alongside the existing app metrics:

- `antiscammer_crowdsec_blocked_total` — requests rejected because CrowdSec
  flagged the IP.
- `antiscammer_crowdsec_poll_failures_total` — failed attempts to refresh
  decisions from the LAPI (fails open — last known list keeps being used).
- `antiscammer_crowdsec_banned_entries` — current size of the banned
  IP/range cache.

## Not covered

Running behind Coolify's Traefik without deploying the `antiscammerbot-crowdsec`
resource still works — the bouncer just stays disabled. If you want CrowdSec
to also see traffic Traefik handles directly (e.g. before it reaches the
app, for things like WebSocket floods), that needs a separate Traefik
bouncer plugin configured in Coolify's proxy, which is outside both repos.
