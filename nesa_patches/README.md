# NESA Patches

Diese Patches transformieren den Upstream `tuanle96/mcp-odoo` Server zu
einem NESA-konformen MCP-Endpoint. Inkrementelle Applikation — nicht alle
Patches sind bereits gelandet.

## Status (Stand 2026-05-19)

| # | Patch | Status | Commit |
| - | ----- | ------ | ------ |
| 1 | DB-Allowlist | **APPLIED** | `6cc3f28` |
| 2 | Per-User-XML-RPC-Passthrough (X-Odoo-Api-Key) | TODO | — |
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

2. **Per-User-XML-RPC-Passthrough** (TODO) — der MCP-Server haelt KEIN
   Master-Konto. Stattdessen schickt der Client einen `X-Odoo-Api-Key`
   Header, den der Server gegen den `res.users.api_key`-Service
   authentifiziert. So laufen alle Calls als der eingeloggte User mit
   korrekten ACLs. Erfordert Umbau in `odoo_client.py` +
   `http_server.py` / `mcp_handlers.py`.

3. **DATEV/Payroll-Block** — wird auf Odoo-Seite im Constraint des
   Models `nesa.mcp.allowed_method._check_datev_blocklist`
   ([`Nesa/nesa_mcp_bridge/models/nesa_mcp_allowed_method.py`](../../staging-odoo.nesa.de/extra-addons/odoo_cloudpepper_nesa.git-69cf9ddc32ac8/Nesa/nesa_mcp_bridge/models/nesa_mcp_allowed_method.py))
   enforced. Auch wenn der Admin einen Eintrag anlegt, weigert sich die
   DB ihn zu speichern. Fork-Seite braucht hier nichts.

4. **`doc/`-Endpoint** (partial) — Helper-Model `nesa.mcp.doc.helper`
   liefert pro `(model, method)` den Original-Docstring aus dem
   Odoo-Model. Fork-Seite muesste in `tools/list` einen XML-RPC-Call
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
#    Environment=ODOO_MCP_METHOD_ALLOWLIST_MODEL=nesa.mcp.allowed_method
#    Environment=ODOO_MCP_METHOD_ALLOWLIST_TTL=60  (optional)

# 5) Service starten
systemctl start nesa-mcp.service

# 6) Health-Check (Odoo Backend)
#    Einstellungen -> NESA MCP -> Servers -> Health check
#    Pruefe: runtime_security_report().nesa_db_allowlist.enabled=true
```

## Sync mit Upstream

```bash
cd /var/odoo/mcp-odoo
sudo -u odoo git fetch upstream
sudo -u odoo git merge upstream/main  # ggf. Konflikte loesen
```
