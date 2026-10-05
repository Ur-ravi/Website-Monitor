# Website Monitor v4 → v5

## v5 additions (multi-level health detection)
- Statuses: up / slow / warning / suspicious / down. HTTP 200 alone is never treated as healthy.
- Content validation: expected title/keywords, blank-page and PHP fatal-output detection.
- File integrity monitoring with trusted SHA-256 baselines (read-only; files are never executed).
- Weighted compromise indicators (defacement markers, obfuscated code, hidden iframes, external redirects) with a combined risk score.
- State-change email alerts (security / down / warning / recovered) — no repeated notifications for unchanged incidents.

## Major changes (v4)
- Check All runs sequentially in the browser, one website per request, eliminating the long controller request that caused Hostinger 504 Gateway Timeout errors.
- Progress modal shows live percentage, current item and per-site result.
- Single-site Recheck is AJAX based.
- Search has a loading/progress overlay.
- Technology counters: OJS, PHP, React.
- Security Review counter for header-only issues.
- Security checks include suspicious response/file patterns, common HTTP security headers, HSTS, mixed content and server-version disclosure.
- Security score and response headers are stored for diagnostics.

## Existing database
Import `database/upgrade_to_v4.sql` (v3→v4) and then `database/upgrade_to_v5.sql` (v4→v5) once, then run `php artisan optimize:clear`. Both scripts are idempotent.

## Fresh database
Use `database/website_monitor_hostinger.sql`.

## 504 behavior
The Check All button intentionally does not make one PHP request for all websites. It performs one AJAX request per website, sequentially. If one site hangs, its request times out in about 8 seconds and the next website continues.
