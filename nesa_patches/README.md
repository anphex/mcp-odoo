# NESA Patches

Diese Patches transformieren den Upstream `tuanle96/mcp-odoo` Server zu
einem NESA-konformen MCP-Endpoint. Inkrementelle Applikation — nicht alle
Patches sind bereits gelandet.

## Status (Stand 2026-08-10)

| # | Patch | Status | Commit |
| - | ----- | ------ | ------ |
| 1 | DB-Allowlist | **APPLIED** | `6cc3f28` |
| 2 | Per-User-XML-RPC-Passthrough (X-Odoo-Api-Key) | **APPLIED + hardened** | `12a0eeb` + aktueller Security-Fix |
| 3 | DATEV/Payroll-Block (Constraint-Seite, Odoo) | applied in `nesa_mcp_bridge` (`nesa.mcp.allowed_method._check_datev_blocklist`) | — |
| 4 | `doc/`-Endpoint via `nesa.mcp.doc.helper` | partial — Helper-Model existiert in `nesa_mcp_bridge`, Fork-Seite nicht verdrahtet | — |
| 5 | Native Odoo-ACL-Parität für Per-User-Calls | **APPLIED** | Feature-Branch `feature/mcp-ui-parity` |
| 6 | Agenten-Backlog 2026-08-22 (A1–A10, B1–B9) | **APPLIED** | siehe unten |

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

5. **Native ACL-Parität** — mit `ODOO_MCP_NATIVE_ACL_PARITY=1` entfällt die
   zweite positive Methodenliste für öffentliche Odoo-Business-Methoden. Der
   Modus wird nur aktiv, wenn strikte Per-User-Authentifizierung aktiv ist;
   jeder Call läuft damit weiterhin unter den ACLs, Record Rules und
   Business-Validierungen des konkreten Odoo-Users. Direkte CRUD-Calls und
   generische Schreibhelfer wie `web_save`, `name_create`, `copy`, `load` und
   Übersetzungsupdates bleiben auf dem validierten Drei-Stufen-Write-Pfad.
   Wenige nicht delegierbare Grenzen werden als
   negative Policy via `ODOO_MCP_DENIED_METHOD_PREFIXES` vor allen Modi
   geprüft; MCP-/Agent-Kontrollmodelle sind zusätzlich fest im Code gesperrt.
   Diese Mutation-Policy ist keine zweite positive Berechtigungsschicht und
   verändert keine Leserechte. Jeder ausgeführte Mutationscall schreibt einen
   Audit-Logeintrag mit Login, Model und Methode, niemals mit dem API-Key.

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
#    Environment=ODOO_MCP_NATIVE_ACL_PARITY=1
#    Environment=ODOO_MCP_DENIED_METHOD_PREFIXES=account.move.,account.payment.,hr.payslip.,hr.payroll.,account.general.ledger.report.handler.l10n_de_datev,account.general.ledger.report.handler.l10_de_datev,nesa.datev.lohnreport.,ir.config_parameter.,ir.cron.,ir.actions.server.,nesa.agent.definition.,nesa.agent.tool.,nesa.mcp.approval.token.,nesa.mcp.allowed_method.
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

## Patch 6 — Agenten-Backlog 2026-08-22 (APPLIED)

Umsetzung des Befund-Backlogs aus der Agenten-Session vom 2026-08-21. Zwei
Leitgedanken: (1) Der Server darf nie eine Aussage über die Bridge als Aussage
über die Geschäftsdaten formulieren, (2) jede Antwort, die der Agent nicht
interpretieren kann, ist Kontextverschwendung.

### Reibungsabbau (Teil A)

| # | Änderung | Ort |
| - | -------- | --- |
| A1 | `create`/`write` laufen auf **transienten** Modellen direkt durch `execute_method`; erkannt über `ir.model.transient` (nicht über Namensmuster), Ergebnis pro Lifespan gecacht. `unlink` und alle write-äquivalenten Aliase bleiben auf der Approval-Kette — auch auf transienten Modellen. Hard-Deny wird jetzt **vor** allen anderen Gates geprüft. | `server.py execute_method`, `model_is_transient` |
| A2 | `preview_write` gibt **keinen** Token mehr aus (`approval` → `payload`, plus `next_step`). Nur `validate_write` prägt Tokens, weil nur dort gegen live `fields_get` validiert wird. Ablehnungen tragen `reason_code` + `remedy` (`token_missing`, `token_unknown`, `token_expired`, `token_already_consumed`, `token_foreign_user`, `payload_mismatch`, `token_store_unreachable`). | `agent_tools.build_write_preview_report`, `server.py execute_approved_write` |
| A3 | `search_records` liefert zusätzlich `total_count` (echtes `search_count`), `has_more`, `next_offset`. `count` bleibt die Seitengröße. Schlägt der Zähl-Query fehl, ist `total_count=null` und `has_more` nie fälschlich `false`. | `server.py search_records` |
| A4 | Ohne `order` wird `id desc` erzwungen und als `order_used`/`order_defaulted` zurückgemeldet. | `server.py search_records` |
| A5 | `scan_addons_source` antwortet `success:false` mit `error_type=not_configured` bzw. `not_readable` statt eines leeren Erfolgs. Setzt `ODOO_ADDONS_PATHS` in den Units voraus. | `server.py scan_addons_source` |
| A6 | `OdooClient.search_read`/`read_records` verschlucken Fehler nicht mehr (vorher: leere Liste = „keine Treffer“). Fehlerantworten tragen `error_type` (`transport`/`odoo_error`/`request`) und `retryable`; Transportfehler werden genau einmal wiederholt, fachliche nie. Odoo-Tracebacks werden auf ihre Ursachenzeile eingedampft. | `odoo_client.py`, `server.py classify_call_error`/`call_with_transport_retry`/`compact_error_message` |
| A8 | Gibt eine Methode ein `act_window` auf **denselben** Datensatz zurück, werden dessen x2many-Felder gezählt und als `result_counts` angehängt. | `server.py _act_window_result_counts` |
| A9 | `diagnose_access` liefert standardmäßig nur die entscheidungsrelevanten Gruppen mit Klarnamen (`decisive_groups`) plus Zähler; die vollen ACL-/Rule-/Gruppen-Dumps stehen hinter `verbose=true`. Messung Staging: 9676 → 2813 Zeichen. | `server.py diagnose_access` |
| A10 | `fields=["*"]` liefert alle Felder **außer** Binärfeldern und meldet die Ausnahme in `excluded_binary_fields`. Explizit benannte Binärfelder funktionieren weiter. Die Smart-Auswahl schloss Binärfelder schon vorher aus. | `server.py resolve_read_fields` |

### Neue Fähigkeiten (Teil B)

`get_document_text`, `read_attachment`, `create_attachment_download`,
`render_report`, `list_allowed_methods`, `chatter_read`, `get_record_url`,
`read_records`, `price_preview`.

Vier davon brauchen eine Odoo-Gegenseite, weil sie Pillow/wkhtmltopdf oder
private ORM-Einstiegspunkte benötigen, die RPC nicht ausliefert:
`nesa.mcp.doc.helper` und `nesa.mcp.download.token` im Modul
`nesa_mcp_bridge` (ab 18.0.1.5.0), inklusive Controller
`/nesa/mcp/download/<token>` und GC-Cron. Beide Modelle stehen in
`NON_DELEGABLE_METHOD_PREFIXES`, damit ein Agent die Obergrenzen der Tools
(TTL, Kantenlänge, Textfenster) nicht per `execute_method` umgehen kann.

### Zusätzlich benötigte Unit-Umgebung

```
Environment=ODOO_ADDONS_PATHS=/var/odoo/<instanz>/extra-addons/<repo>/Nesa
```

Der Service-User `mcp` braucht dafür Lesezugriff auf dieses Verzeichnis
(POSIX-ACL, nur `r-x`). Ohne die Variable bleibt `scan_addons_source`
abgeschaltet und sagt das auch.

## Sync mit Upstream

```bash
cd /var/odoo/mcp-odoo
sudo -u odoo git fetch upstream
sudo -u odoo git merge upstream/main  # ggf. Konflikte lösen
```
