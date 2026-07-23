# NESA Patches

Diese Patches transformieren den Upstream `tuanle96/mcp-odoo` Server zu
einem NESA-konformen MCP-Endpoint. Inkrementelle Applikation — nicht alle
Patches sind bereits gelandet.

## Status (Stand 2026-07-23)

| # | Patch | Status | Commit |
| - | ----- | ------ | ------ |
| 1 | DB-Allowlist | **APPLIED** | `6cc3f28` |
| 2 | Per-User-XML-RPC-Passthrough (X-Odoo-Api-Key) | **APPLIED + hardened** | `12a0eeb` + aktueller Security-Fix |
| 3 | DATEV/Payroll-Block (Constraint-Seite, Odoo) | applied in `nesa_mcp_bridge` (`nesa.mcp.allowed_method._check_datev_blocklist`) | — |
| 4 | `doc/`-Endpoint via `nesa.mcp.doc.helper` | partial — Helper-Model existiert in `nesa_mcp_bridge`, Fork-Seite nicht verdrahtet | — |

## Patch-Beschreibungen

1. **DB-Allowlist** — `src/odoo_mcp/_nesa_db_allowlist.py` +
   `side_effect_method_allowed()`-Hook in `server.py`. Additiv zur
   Upstream-CSV-Env (`ODOO_MCP_ALLOWED_SIDE_EFFECT_METHODS`); aktiviert
   wenn `ODOO_MCP_METHOD_ALLOWLIST_MODEL` auf das Odoo-Model zeigt
   (typischerweise `nesa.mcp.allowed_method`). DB-Seite ist verwaltbar
   per Odoo-Backend ohne systemd-Bounce. Failure-soft: bei XML-RPC-Fehler
   bleibt der letzte erfolgreiche Cache aktiv (mit Warn-Log). State via
   `runtime_security_report()` exponiert.

2. **Per-User-XML-RPC-Passthrough** (APPLIED) — der Client sendet
   `X-Odoo-User` + `X-Odoo-Api-Key`; alle Calls laufen damit unter den ACLs
   und Record Rules dieses Users. Der Cache ist nach Login + Key-Fingerprint
   getrennt, Auth-Fehler fallen nie auf das Servicekonto zurück, und
   `Mcp-Session-Id` ist an denselben Credential-Fingerprint gebunden. Für
   Netzwerktransporte ist strict per Default aktiv; produktive Units setzen
   `ODOO_MCP_REQUIRE_PER_USER=1` zusätzlich explizit und prüfbar.

### Verbindlicher Reverse-Proxy-Sicherheitsvertrag

Eine öffentliche Capability-URL ist nur unter diesen gemeinsam notwendigen
Voraussetzungen zulässig:

- Der Sidecar bindet ausschließlich an Loopback (`127.0.0.1`); Port 3018/3019
  wird weder durch Firewall noch Reverse Proxy generisch veröffentlicht.
- Nginx veröffentlicht genau eine nicht erratbare, exakte Location je Benutzer,
  z. B. `/mcp/cap/<256-bit-zufallstoken>`, und schreibt sie upstream zu `/mcp`
  um. Login oder Odoo-API-Key stehen niemals im öffentlichen Pfad.
- Die exakte Location verwirft eingehende `Authorization`, `Cookie`, `Origin`,
  `Referer`, `Forwarded`, `X-Odoo-User` und `X-Odoo-Api-Key`. Anschließend setzt
  Nginx `X-Odoo-User` und `X-Odoo-Api-Key` auf die serverseitig hinterlegten,
  festen Werte genau dieses Capability-Links. Externe Clients können damit
  keine Garbage-Credentials zum Sidecar durchreichen.
- Alle übrigen `/mcp`- und `/mcp/…`-Pfade liefern ohne Redirect exakt HTTP 404.
  Für Capability-Pfade sind Access- und Error-Logging deaktiviert, damit das
  Token weder im Request- noch im Redirect-Log landet.
- OAuth-/OIDC-Discovery und übliche OAuth-Endpunkte liefern auf HTTP und HTTPS
  direkt HTTP 404, ohne `Location` und ohne `WWW-Authenticate`. Die gemeinsame
  nginx-Quelle liegt in
  `nesa_patches/nginx/mcp-negative-routes.conf` und wird root-owned nach
  `/etc/nginx/snippets/mcp-negative-routes.conf` installiert.
- Der Sidecar authentifiziert ausschließlich seinen konfigurierten
  Streamable-HTTP-Pfad. Jeder andere Loopback-Pfad liefert bereits vor dem
  Per-User-Auth-Wrapper HTTP 404; insbesondere signalisiert ein OAuth-Probe
  damit nie fälschlich OAuth-Unterstützung.
- Netzwerk-Units setzen `ODOO_MCP_REQUIRE_PER_USER=1` explizit. Der API-Key ist
  ein dedizierter, einzeln widerrufbarer Odoo-RPC-Key des gebundenen Benutzers.

Minimaler Kern der exakten Nginx-Location (Platzhalter nie einchecken):

```nginx
location = /mcp/cap/<OPAQUE_TOKEN> {
    access_log off;
    error_log /dev/null crit;
    rewrite ^ /mcp? break;
    proxy_pass http://127.0.0.1:<SIDECAR_PORT>;
    proxy_set_header Host "127.0.0.1:<SIDECAR_PORT>";
    proxy_set_header Authorization "";
    proxy_set_header Cookie "";
    proxy_set_header Origin "";
    proxy_set_header X-Odoo-User "<ODOO_LOGIN>";
    proxy_set_header X-Odoo-Api-Key "<DEDICATED_RPC_KEY>";
}
```

3. **DATEV/Payroll-Block** — wird auf Odoo-Seite im Constraint des
   Models `nesa.mcp.allowed_method._check_datev_blocklist`
   ([`Nesa/nesa_mcp_bridge/models/nesa_mcp_allowed_method.py`](../../staging-odoo.nesa.de/extra-addons/odoo_cloudpepper_nesa.git-69cf9ddc32ac8/Nesa/nesa_mcp_bridge/models/nesa_mcp_allowed_method.py))
   enforced. Auch wenn der Admin einen Eintrag anlegt, weigert sich die
   DB ihn zu speichern. Fork-Seite braucht hier nichts.

4. **`doc/`-Endpoint** (partial) — Helper-Model `nesa.mcp.doc.helper`
   liefert pro `(model, method)` den Original-Docstring aus dem
   Odoo-Model. Fork-Seite müsste in `tools/list` einen XML-RPC-Call
   gegen diesen Helper machen — derzeit nicht verdrahtet.

## Build-Steps (Soll-Zustand nach PR 1)

```bash
# 1) Setup
bash /var/odoo/_Skripte/mcp_fork_setup.sh

# 2) Methods provisionieren in Odoo
#    Einstellungen -> NESA MCP -> Allowed Methods -> initial seed
#    (siehe nesa_mcp_bridge data/mcp_allowlist.xml)

# 3) User-Keys generieren  (erfordert Patch 2)
#    Settings -> Users -> Action: "Rotate MCP API Key"

# 4) systemd-Unit konfigurieren
#    Environment=ODOO_MCP_REQUIRE_PER_USER=1
#    Environment=ODOO_MCP_METHOD_ALLOWLIST_MODEL=nesa.mcp.allowed_method
#    Environment=ODOO_MCP_METHOD_ALLOWLIST_TTL=60  (optional)
#    Environment=MCP_SESSION_IDLE_TIMEOUT=1800  (optional)

# 5) Service starten
systemctl start nesa-mcp.service

# 6) Health-Check (Odoo Backend)
#    Einstellungen -> NESA MCP -> Servers -> Health check
#    Prüfe: runtime_security_report().nesa_per_user_auth.strict_mode=true
#    Prüfe: runtime_security_report().nesa_db_allowlist.enabled=true
```

## Sync mit Upstream

```bash
cd /var/odoo/mcp-odoo
sudo -u odoo git fetch upstream
sudo -u odoo git merge upstream/main  # ggf. Konflikte lösen
```
