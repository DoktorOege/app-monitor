# App-Monitor

Zeigt auf einen Blick, ob Michaels Apps laufen und ob ein Gratis-Kontingent knapp wird.

**App:** https://doktoroege.github.io/app-monitor/

- Prüft jede Stunde automatisch (GitHub Actions, `check.mjs`) und schreibt das Ergebnis in `status.json`.
- Welche Apps geprüft werden, steht in `apps.json`. Apps ohne `url` gelten als nicht online und werden ausgelassen (z. B. Meppen Basketball, bis sie bei Cloudflare läuft).
- Pro App wird der Verbrauch je Anbieter angezeigt: Cloudflare (Aufrufe, KV-Speicher), Firebase (Firestore lesen/speichern/löschen), GitHub (Speicherplatz der Seite).
- Gelb ab 70 %, Rot ab 90 %. Push-Meldungen kommen über die App **ntfy**. Rot sofort, Gelb höchstens einmal am Tag und nicht nachts (22–7 Uhr).

## Geheime Schlüssel (Settings → Secrets and variables → Actions)

| Name | Wofür |
|---|---|
| `NTFY_TOPIC` | Name des Push-Kanals in der ntfy-App |
| `CF_API_TOKEN` | Cloudflare-Token mit Berechtigung „Account Analytics: Read“ |
| `CF_ACCOUNT_ID` | Cloudflare-Konto-ID |
| `GCP_SA_KEY` | Google-Dienstkonto-Schlüssel (JSON) mit Rolle „Monitoring-Betrachter“ im Projekt weed-online-kma |

Fehlt ein Schlüssel, läuft der Monitor trotzdem – der jeweilige Verbrauch wird dann nur nicht angezeigt.

Test-Meldung: Actions → „Apps prüfen“ → „Run workflow“ → Haken bei „Test-Meldung“.
