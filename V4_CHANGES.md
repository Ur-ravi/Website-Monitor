# v4 changes

- Check All now runs from the browser one website at a time via AJAX, preventing a single long PHP request from producing a 504 Gateway Timeout.
- Progress modal shows percentage and current website.
- Search shows a loading overlay while the server prepares results.
- Dedicated OJS, PHP and React counts.
- Security scan now also checks common security headers, HSTS on HTTPS, mixed-content scripts/iframes and server-version disclosure.
- Security score (0-100) and headers are stored.
- Single website Recheck uses AJAX.
- HTTP timeout reduced to 8 seconds per website with 3 second connection timeout.

## Existing installation
Import database/upgrade_to_v4.sql in phpMyAdmin, then run `php artisan optimize:clear`.

## Important
The Check All button is intentionally sequential. This reduces Hostinger resource spikes and prevents a long controller request from timing out. The scheduler continues to run checks automatically in the background.
