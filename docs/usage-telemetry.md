# Optional usage-pattern telemetry

The existing text call log is unchanged. Structured telemetry is disabled until
`ODOO_MCP_TELEMETRY_ENABLED=1` is explicitly configured. Required configuration:

* `ODOO_MCP_TELEMETRY_DIR`: dedicated absolute, service-writable event directory.
* `ODOO_MCP_TELEMETRY_KEY_FILE`: readable secret containing at least 32 random
  bytes. Provision out of band, never pass key material on the command line.
* `ODOO_MCP_TELEMETRY_INSTANCE`: stable label such as `staging` or `prod`.
* `ODOO_MCP_TELEMETRY_MAX_BYTES`: directory capacity, default 268435456 bytes;
  configurable from 1 MiB to 4 GiB.
* `ODOO_MCP_TELEMETRY_MODELS`: optional comma-separated approved technical model
  names (whitespace ignored). All other caller-supplied model strings become
  `other`; tools without a model parameter record null.

Keep the directory private (0750) and files group-readable (0640) only for the
unprivileged audit service. Different instances should use different directories
and keys. Key rotation deliberately breaks correlation and error-fingerprint
continuity. Root-installed runtimes must be installed from reviewed sources.
Parent directories must not be writable by unrelated users or replaced with
symlinks. Provision the permissions explicitly and use service umask 0027;
Python creation modes alone cannot override a stricter umask.

## Event contract (schema 1)

`events-YYYY-MM-DD.jsonl` contains one completed event per call, UTC timestamps:
`schema_version`, `event_id`, `instance`, `tool`, `tool_version`, `code_version`, `start_at`,
`end_at`, `duration_ms`, `status`, `record_count`, `result_bytes`, `error_class`,
`error_code`, `error_fingerprint`, `model`, `argument_shape`, `correlation_id`,
`correlation_quality`, `session_id`. Status is
success/error/rejected/unknown/cancelled. `rejected` means the tool deliberately
refused the request — a verdict on the caller's payload, not a fault — and is
recorded only when the tool marks its answer with `outcome: "rejected"`. An
exception, or a failure without that marker, stays `error`. Rejections keep
`error_class`, `error_code` and `error_fingerprint` so the cause stays
analyzable; analyzers must count them apart from faults and must not read them
as an outage. `error_code` is the tool's own `reason_code` when it publishes a
bounded one (`[a-z][a-z0-9_]{0,39}`), otherwise a coarse keyword classification.
No raw arguments, record IDs, responses, usernames, tokens or errors are stored.
Argument shape records only approved parameter names, types and size buckets;
same shape does **not** establish equal arguments.
Daily files use the UTC completion date. For overlap analysis use the explicit
`start_at`/`end_at` interval; monotonic duration is supplementary and can differ
if the wall clock is adjusted.

The optional custom `X-Nesa-Workflow-Id` header is HMAC-pseudonymized and scoped
to the authenticated principal and instance. Quality is `workflow`, else
`session` when a technical `Mcp-Session-Id` is available, else `none`. Technical
sessions are also separately pseudonymized. Workflow IDs must identify a real
bounded run; callers must not use a user ID as the workflow ID. Headers are
untrusted claims, not verified causality. Independent/overlapping intervals
must not be turned into causal pairs by an analyzer.

The installed MCP 1.x SDK exposes HTTP headers through FastMCP request context.
Its session header follows the [2025-11-25 transport specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports).
The [2026-07-28 protocol](https://blog.modelcontextprotocol.io/posts/2026-07-28/)
removes protocol sessions; workflow correlation is intentionally independent of
that optional fallback. This change does not upgrade the installed protocol.

Error codes are a fixed coarse taxonomy. Fingerprints use HMAC of bounded,
normalized error text (quoted values, numeric IDs, URLs, emails removed).
They distinguish recurring templates within a category, without storing text.
Normalization is heuristic: equal hashes do not prove identical root cause,
and other changing values can split a recurring issue into multiple hashes.

`tools-<tool_version>.json` contains one trusted tool definition: name,
description and input schema. Default/example values and schema
extensions are excluded. All registered definitions are exported at lifespan
startup; a changed description or schema produces a new tool version. Code-only
changes alter the event's separate `code_version` without duplicating definitions.
The analyzer should match each event to its recorded tool version. Unknown tool
names intentionally become `unknown` without a definition, since persisting
arbitrary caller names could retain personal or secret data.

## Operational limitations

Persistence uses a daemon writer with a 1024-entry queue and 16 KiB event bound.
No event write blocks a tool call. Initial configuration/source hashing happens
once at startup/first use. Queue overflow, full directory, permissions or disk
failure drop events and emit at most one payload-free warning per minute.
Invalid configuration disables telemetry instead of disabling tools.
Unpublished definitions retry at most once per hour each, so a per-call session
lifespan cannot flood the queue during a disk outage. Storage usage is rescanned
once per minute and adjusted immediately for this writer's own writes.

Only completed calls are logged. Process kills lose in-flight calls and may lose
queued events. This is usage sampling, not a transaction ledger; report missing
correlation, warning/drop gaps and uncertain coverage. The external audit owns
90-day event retention and 12-month weekly aggregates. The directory capacity
is an independent hard safety limit; if retention fails, collection eventually
stops without stopping MCP. The writer never deletes evidence automatically.
There is also a 1024-file safety bound; operators should prune tool definitions
only after their last referencing retained event/aggregate is gone. Ordinary
code-only deployments do not create new definition files.

Disable telemetry by removing the enabled setting and restarting the approved
instance. Existing data remains available for its configured retention period.
