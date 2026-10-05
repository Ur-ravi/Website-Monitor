<?php
/**
 * Standalone scenario tests for the multi-level health detection system.
 * Run: php tests/health-scenarios.php
 * (Boots the framework for config(); no database or network required.)
 */
require __DIR__.'/../vendor/autoload.php';

$app = require __DIR__.'/../bootstrap/app.php';
$app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();

use App\Services\WebsiteHealthService;
use App\Services\WebsiteSecurityService;

$health = new WebsiteHealthService();
$security = new WebsiteSecurityService();
$pass = 0;
$fail = 0;

function websiteCfg(array $overrides = []): array
{
    return array_merge([
        'url' => 'https://example.com',
        'expected_title' => null,
        'expected_keywords' => null,
        'expected_http_code' => null,
        'content_check_enabled' => true,
    ], $overrides);
}

function runScenario(string $name, array $input, array $expectedStatuses, ?callable $extra = null): array
{
    global $health, $pass, $fail;
    $result = $health->evaluate($input);
    $ok = in_array($result['status'], $expectedStatuses, true) && ($extra === null || $extra($result));
    if ($ok) {
        $pass++;
        echo "PASS  {$name}  -> {$result['status']} (risk {$result['risk_score']})\n";
    } else {
        $fail++;
        echo "FAIL  {$name}  -> {$result['status']} (expected: ".implode('|', $expectedStatuses).", risk {$result['risk_score']})\n";
    }
    echo "      reasons: ".implode(' | ', array_slice($result['reasons'], 0, 4))."\n";
    return $result;
}

$goodPage = '<!doctype html><html><head><title>My Website - Home</title></head><body><h1>Welcome to My Website</h1><p>We provide quality services since 2001. Contact us for more information about our products and support options.</p></body></html>';

echo "== Test 1: Healthy website ==\n";
runScenario('HTTP 200 + expected title/keywords + clean content', [
    'website' => websiteCfg(['expected_title' => 'My Website', 'expected_keywords' => "Welcome to My Website"]),
    'code' => 200, 'ms' => 200, 'body' => $goodPage, 'error' => null, 'dns_ok' => true,
    'final_url' => 'https://example.com', 'redirect_chain' => [],
    'baseline' => ['hash' => hash('sha256', $goodPage), 'title' => 'My Website - Home'],
    'homepage_hash' => hash('sha256', $goodPage), 'integrity' => ['status' => 'ok', 'files' => [], 'findings' => []],
    'indicators' => [],
], ['up'], function ($r) { return $r['content_ok'] === true && $r['risk_score'] === 0; });

echo "\n== Test 2: Server down (connection timeout/DNS failure) ==\n";
runScenario('Connection error', [
    'website' => websiteCfg(), 'code' => null, 'ms' => 8000, 'body' => '',
    'error' => 'cURL error 28: Connection timed out', 'dns_ok' => true,
    'final_url' => 'https://example.com', 'redirect_chain' => [], 'baseline' => null, 'homepage_hash' => null, 'integrity' => null, 'indicators' => [],
], ['down']);

echo "\n== Test 3: HTTP 500 ==\n";
runScenario('HTTP 500 server error', [
    'website' => websiteCfg(), 'code' => 500, 'ms' => 300, 'body' => '<h1>Server error</h1>', 'error' => null, 'dns_ok' => true,
    'final_url' => 'https://example.com', 'redirect_chain' => [], 'baseline' => null, 'homepage_hash' => null, 'integrity' => null, 'indicators' => [],
], ['down']);

echo "\n== Test 4: HTTP 200 but broken homepage ==\n";
runScenario('HTTP 200 with expected content missing (blank page)', [
    'website' => websiteCfg(['expected_title' => 'My Website', 'expected_keywords' => "Welcome to My Website"]),
    'code' => 200, 'ms' => 200, 'body' => '<!doctype html><html><head></head><body></body></html>', 'error' => null, 'dns_ok' => true,
    'final_url' => 'https://example.com', 'redirect_chain' => [], 'baseline' => null, 'homepage_hash' => null, 'integrity' => null, 'indicators' => [],
], ['warning'], function ($r) { return $r['content_ok'] === false; });

echo "\n== Test 5: index.php changed (integrity, benign content) ==\n";
runScenario('File integrity changed, no malicious patterns', [
    'website' => websiteCfg(), 'code' => 200, 'ms' => 200, 'body' => $goodPage, 'error' => null, 'dns_ok' => true,
    'final_url' => 'https://example.com', 'redirect_chain' => [],
    'baseline' => ['hash' => str_repeat('a', 64), 'title' => 'My Website - Home'], 'homepage_hash' => hash('sha256', $goodPage),
    'integrity' => ['status' => 'changed', 'risk' => 0, 'files' => [['path' => 'index.php', 'state' => 'changed']], 'findings' => [['type' => 'file_integrity', 'file' => 'index.php', 'reason' => 'File changed since the trusted baseline was recorded', 'severity' => 'medium', 'weight' => 10]]],
    'indicators' => [],
], ['warning'], function ($r) { return str_contains(implode(' ', $r['reasons']), 'File integrity changed'); });

echo "\n== Test 6: Suspicious code injection ==\n";
$payload = substr(base64_encode(random_bytes(300)), 0, 360); // one contiguous 360-char base64 blob
$injected = '<html><head><title>My Website</title></head><body>Welcome to My Website normal content<script>eval(base64_decode("' . $payload . '"))</script></body></html>';
// 5 repeats = 360 consecutive base64 chars: triggers both obfuscated_eval (45) and
// large_encoded_payload (30) for a combined risk of 75 >= suspicious threshold (50).
runScenario('Obfuscated eval payload in homepage', [
    'website' => websiteCfg(), 'code' => 200, 'ms' => 200, 'body' => $injected, 'error' => null, 'dns_ok' => true,
    'final_url' => 'https://example.com', 'redirect_chain' => [], 'baseline' => null, 'homepage_hash' => null, 'integrity' => null,
    'indicators' => $security->contentRiskIndicators($injected),
], ['suspicious'], function ($r) { return $r['risk_score'] >= 50; });

echo "\n== Test 7: Defaced homepage ==\n";
$defaced = '<!doctype html><html><head><title>Hacked by Shadow</title></head><body><h1>Hacked by Shadow Crew</h1><p>Greetz to all hackers. Your site is owned. Secure your server next time, admin. This page now contains a lot of text so the blank-page heuristic is not what fires here, only the defacement markers.</p></body></html>';
runScenario('Defacement homepage content', [
    'website' => websiteCfg(), 'code' => 200, 'ms' => 200, 'body' => $defaced, 'error' => null, 'dns_ok' => true,
    'final_url' => 'https://example.com', 'redirect_chain' => [], 'baseline' => null, 'homepage_hash' => null, 'integrity' => null,
    'indicators' => $security->contentRiskIndicators($defaced),
], ['suspicious']);

echo "\n== Test 8: Legitimate website update (must NOT be labelled malware) ==\n";
$updatedPage = str_replace('since 2001', 'since 2026 - new products available in our store', $goodPage);
runScenario('Legitimate homepage update (baseline hash mismatch only)', [
    'website' => websiteCfg(), 'code' => 200, 'ms' => 200, 'body' => $updatedPage, 'error' => null, 'dns_ok' => true,
    'final_url' => 'https://example.com', 'redirect_chain' => [],
    'baseline' => ['hash' => hash('sha256', $goodPage), 'title' => 'My Website - Home'], 'homepage_hash' => hash('sha256', $updatedPage),
    'integrity' => ['status' => 'ok', 'files' => [], 'findings' => []],
    'indicators' => $security->contentRiskIndicators($updatedPage),
], ['up'], function ($r) { return str_contains(implode(' ', $r['reasons']), 'changed since the trusted baseline'); });

echo "\n== Extra scenarios ==\n";
runScenario('Slow but valid response', [
    'website' => websiteCfg(), 'code' => 200, 'ms' => 4200, 'body' => $goodPage, 'error' => null, 'dns_ok' => true,
    'final_url' => 'https://example.com', 'redirect_chain' => [], 'baseline' => null, 'homepage_hash' => null, 'integrity' => null, 'indicators' => [],
], ['slow']);

runScenario('HTTP 401 warning', [
    'website' => websiteCfg(), 'code' => 401, 'ms' => 100, 'body' => 'Unauthorized', 'error' => null, 'dns_ok' => true,
    'final_url' => 'https://example.com', 'redirect_chain' => [], 'baseline' => null, 'homepage_hash' => null, 'integrity' => null, 'indicators' => [],
], ['warning']);

$wpPage = '<html><head><title>My Blog</title></head><body><p>Normal WordPress blog with plenty of readable content so we do not trip the blank-page heuristic at all. Here is some more filler text to be safely above the minimum length.</p><iframe src="https://youtube.com/embed/xyz" width="560" height="315"></iframe><script>document.write("hi");</script></body></html>';
runScenario('Legitimate page with common JS/iframe patterns stays up', [
    'website' => websiteCfg(), 'code' => 200, 'ms' => 150, 'body' => $wpPage, 'error' => null, 'dns_ok' => true,
    'final_url' => 'https://example.com', 'redirect_chain' => [], 'baseline' => null, 'homepage_hash' => null, 'integrity' => null,
    'indicators' => $security->contentRiskIndicators($wpPage),
], ['up']);

runScenario('Redirect to external domain', [
    'website' => websiteCfg(), 'code' => 200, 'ms' => 150, 'body' => $goodPage, 'error' => null, 'dns_ok' => true,
    'final_url' => 'https://evil-example.ru/casino', 'redirect_chain' => ['https://evil-example.ru/casino'],
    'baseline' => null, 'homepage_hash' => null, 'integrity' => null,
    'indicators' => [],
], ['suspicious']);

echo "\n==============================\nPassed: {$pass}, Failed: {$fail}\n";
exit($fail === 0 ? 0 : 1);
