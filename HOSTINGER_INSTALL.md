# Website Monitor v3 — Hostinger Installation

## Requirements
- Laravel 13
- PHP 8.3+
- MySQL 8+ recommended
- cURL, OpenSSL, Mbstring, XML/DOM and PDO MySQL PHP extensions

## 1. Upload
Keep the Laravel application outside `public_html` when possible:

/home/USERNAME/website-monitor/
/home/USERNAME/public_html/

Set the domain document root to:

`/home/USERNAME/website-monitor/public`

If your Hostinger plan does not allow changing the document root, copy the contents of `public/` to `public_html/` and adjust `public_html/index.php` to point to the application directory.

## 2. Database
For a fresh installation, import:

`database/website_monitor_hostinger.sql`

For your EXISTING Website Monitor database, use:

`database/upgrade_to_v3.sql`

The upgrade script does not delete existing website records.

## 3. Environment
The package contains a production `.env` configured for the database supplied by the project owner. For security, change the database password in Hostinger if it has been exposed.

Set:

APP_ENV=production
APP_DEBUG=false
APP_URL=https://web.edutechy.in

## 4. Install / clear cache
From the Laravel project directory:

`composer install --no-dev --optimize-autoloader`

`php artisan optimize:clear`

`php artisan optimize`

## 5. Permissions

`chmod -R 775 storage bootstrap/cache`

## 6. Cron
Add this Hostinger cron job:

`* * * * * /usr/bin/php /home/USERNAME/website-monitor/artisan schedule:run >> /dev/null 2>&1`

The application schedules:
- HTTP/DNS monitoring every 5 minutes
- Server file security scan every hour for websites with `document_root` configured

## 7. Alerts
Email alerts are disabled by default. To enable them, configure Laravel SMTP/Mail settings and set:

`MONITOR_ALERT_EMAIL=your@email.com`
`MONITOR_ALERT_ON_RECOVERY=true`

Alerts are sent after a second consecutive DOWN/WARNING check, on recovery, and on a new suspicious security finding.

## 8. Security scan
There are two layers:
1. External response scan: checks returned HTML/JS every monitoring cycle for heuristic suspicious indicators.
2. Local file scan: scans the configured Hostinger document root. It is heuristic and is not proof of malware. Review findings before deleting/changing files.

Do not configure the document root to `/home/USERNAME` or another unrelated directory. Use the actual website public directory.

## 9. Admin
Fresh install:
- ID: admin@edutechy.in
- Temporary password: ChangeMe@12345

Change it from Admin → Admin Account immediately.
