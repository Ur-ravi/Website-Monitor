# Website Monitor — Laravel 13

A simple self-hosted uptime dashboard for OJS, PHP, CodeIgniter, Laravel, Next.js and other public websites.

## Requirements

- Laravel 13
- PHP 8.3+ (PHP 8.4/8.5 recommended)
- MySQL
- cURL PHP extension
- PDO MySQL
- Composer
- A cron job for automatic checks

Laravel 13 requires PHP >= 8.3. MySQL is supported by Laravel; configure it through `.env`.

## 1. Create the database 


Create a MySQL database and user in Hostinger. Example:

- Database: `website_monitor`
- User: `website_monitor`
- Password: strong unique password

## 2. Upload project

Upload this project to a directory outside the public web root if your hosting setup permits. The domain/subdomain document root should point to the project's `public` directory.

Do NOT point the domain to the Laravel project root.

## 3. Configure `.env`

Copy `.env.example` to `.env` and set:

```env
APP_NAME="Website Monitor"
APP_ENV=production
APP_DEBUG=false
APP_URL=https://monitor.example.com

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=website_monitor
DB_USERNAME=website_monitor
DB_PASSWORD=YOUR_DATABASE_PASSWORD

ADMIN_NAME="Administrator"
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD="CHANGE_THIS_TO_A_LONG_RANDOM_PASSWORD"
```

Generate the application key:

```bash
php artisan key:generate
```

## 4. Install dependencies and migrate

```bash
composer install --no-dev --optimize-autoloader
php artisan migrate --seed
php artisan storage:link
php artisan optimize
```

The seed creates the admin account from `ADMIN_EMAIL` and `ADMIN_PASSWORD`.

## 5. Login

Open:

`https://monitor.example.com/login`

Use the admin credentials from `.env`.

## 6. Import websites

The dashboard accepts either:

### Simple CSV

```csv
url
https://example.com
https://example.org
https://example.net
```

### Full CSV

```csv
name,url,technology
Journal 1,https://journal1.com,OJS
Website 2,https://example.com,Laravel
Website 3,https://example.org,Next.js
```

Existing URLs are updated rather than duplicated.

## 7. Automatic monitoring

The application schedules `websites:check` every 5 minutes.

On Hostinger, add a cron job that runs Laravel's scheduler every minute. Typical command:

```bash
cd /home/USERNAME/path-to-website-monitor && php artisan schedule:run >> /dev/null 2>&1
```

If Hostinger requires the full PHP binary path, use the PHP 8.4/8.5 binary configured for the domain.

The Laravel scheduler will then execute the monitor every five minutes.

## 8. Manual check

Dashboard: **Check All Websites**

Or for one website: **Websites → Check**.

## Status rules

- 2xx/3xx: UP
- 2xx/3xx with response >= 3000 ms: SLOW
- 401/403: WARNING (server reachable but access restricted)
- Other HTTP errors: DOWN
- Connection/timeout errors: DOWN

## Production security

- Use HTTPS.
- Keep `APP_DEBUG=false`.
- Use a long random admin password.
- Restrict dashboard access to trusted administrators.
- Keep Laravel and PHP patched.
- Consider moving the monitoring app to a separate VPS/server later. If the same Hostinger server goes down, an on-server monitor cannot report that outage externally.

## Next upgrades

Recommended production additions:

1. SSL expiry monitoring
2. Domain expiry monitoring
3. Email/WhatsApp/Telegram alerts
4. Uptime percentage for 24h/7d/30d
5. Response-time charts
6. Keyword/content checks
7. `/health` endpoint checks for Laravel/CodeIgniter/OJS applications
8. Separate monitoring worker/server
