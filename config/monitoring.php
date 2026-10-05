<?php

return [
    // HTTP fetch behaviour. HTTP 200 alone is NEVER treated as proof of health.
    'http' => [
        'connect_timeout' => 3,
        'timeout' => 8,
        'max_redirects' => 5,
        // Response bodies are truncated for scanning (oversized-response / decompression-bomb guard).
        'max_response_bytes' => 2 * 1024 * 1024,
        'slow_ms' => 3000,
    ],

    // Homepage content validation.
    'content' => [
        'enabled_by_default' => true,
        // Visible text shorter than this (with HTTP 200) is considered a blank/broken page.
        'min_text_length' => 120,
        // PHP/application error text that may be rendered with HTTP 200.
        'fatal_patterns' => [
            'fatal error:',
            'parse error:',
            'uncaught ',
            'error establishing a database connection',
            'access denied for user',
            'allowed memory size',
        ],
    ],

    // Weighted compromise indicators. A single innocent keyword can never mark a site
    // compromised: the sum of weights decides, with a high threshold for SUSPICIOUS.
    'security' => [
        'suspicious_threshold' => 50, // total risk weight => status SUSPICIOUS
        'elevated_threshold' => 20,   // total risk weight => contributes WARNING/REVIEW
        'defacement_keywords' => [
            'hacked by', 'defaced by', 'owned by', 'pwned by', 'greetz to', 'site hacked',
            'your files have been encrypted', 'restore your files', 'ransom',
        ],
        'spam_keywords' => [
            'free bitcoin', 'crypto giveaway', 'double your money', 'casino', 'viagra',
            'escort service', 'payday loan', 'forex signals', 'clone cards', 'porn video',
        ],
        'shell_names' => ['wso.php', 'filesman', 'c99shell', 'r57shell', 'b374k', 'anonymousfox'],
    ],

    // Email alerting. MONITOR_ALERT_EMAIL / MONITOR_ALERT_ON_RECOVERY are read from the
    // environment here, so they keep working when the config is cached in production.
    'alerts' => [
        'email' => env('MONITOR_ALERT_EMAIL'),
        'on_recovery' => env('MONITOR_ALERT_ON_RECOVERY', true),
    ],

    // File integrity monitoring (read-only: files are hashed and pattern-scanned, never executed).
    'integrity' => [
        'important_files' => ['index.php', 'index.html', '.htaccess', 'wp-config.php', 'composer.json'],
        'max_file_bytes' => 5 * 1024 * 1024,
    ],
];
