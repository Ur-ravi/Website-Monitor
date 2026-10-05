<?php
namespace App\Services;

/**
 * Multi-level website health resolver.
 *
 * Statuses: up (HEALTHY) | slow | warning (DEGRADED) | suspicious (COMPROMISED) | down
 *
 * HTTP 200 alone is NEVER sufficient for "up": the site is only healthy when the
 * HTTP/connection check, content validation, integrity checks and risk indicators
 * all pass. Every result explains WHY via human-readable reasons.
 */
class WebsiteHealthService
{
    /**
     * @param array $input {
     *   website: array (url, expected_title, expected_keywords, expected_http_code, content_check_enabled),
     *   code: ?int, ms: ?int, body: string, error: ?string, dns_ok: bool,
     *   final_url: ?string, redirect_chain: array,
     *   baseline: ?array (homepage baseline), homepage_hash: ?string,
     *   integrity: ?array (result of WebsiteSecurityService::checkFileIntegrity),
     *   indicators: array (pre-computed weighted indicators for the response body)
     * }
     * @return array{status:string, reasons:string[], indicators:array, checks:array, content_ok:?bool, risk_score:int}
     */
    public function evaluate(array $input): array
    {
        $cfg = config('monitoring');
        $websiteCfg = $input['website'] ?? [];
        $code = $input['code'] ?? null;
        $ms = $input['ms'] ?? null;
        $error = $input['error'] ?? null;
        $body = (string)($input['body'] ?? '');
        $dnsOk = (bool)($input['dns_ok'] ?? true);
        $reasons = [];
        $indicators = array_values($input['indicators'] ?? []);

        $checks = [
            'http' => ['label' => 'HTTP/Connection', 'value' => '—', 'ok' => false],
            'content' => ['label' => 'Content Check', 'value' => '—', 'ok' => null],
            'integrity' => ['label' => 'Integrity Check', 'value' => '—', 'ok' => null],
            'security' => ['label' => 'Security Check', 'value' => '—', 'ok' => null],
        ];

        // ---------- 1. DOWN: unreachable / server failure ----------
        $connectionFailed = $error !== null || $code === null || !$dnsOk;
        $serverDown = $connectionFailed || $code >= 500 || ($code >= 400 && !in_array($code, [401, 403, 429], true));
        if ($serverDown) {
            $checks['http']['value'] = $error !== null ? 'ERROR' : 'HTTP ' . ($code ?? '—');
            $reasons[] = $error !== null
                ? 'Connection failed: ' . mb_substr((string)$error, 0, 200)
                : 'HTTP ' . $code . ' indicates the server or application is not functioning.';
            return $this->result('down', $reasons, $indicators, $checks, null, 0);
        }

        $checks['http']['ok'] = true;
        $checks['http']['value'] = 'HTTP ' . $code;
        $reasons[] = 'HTTP ' . $code;
        $expectedCode = $websiteCfg['expected_http_code'] ?? null;
        $expectedCodeMismatch = $expectedCode !== null && (int)$expectedCode !== (int)$code;
        if ($expectedCodeMismatch) {
            $reasons[] = 'Expected HTTP ' . (int)$expectedCode . ' but received HTTP ' . (int)$code . '.';
        }

        // ---------- 2. Risk indicators (weighted, false-positive resistant) ----------
        $indicators = array_merge($indicators, $this->baselineIndicators($input));
        $indicators = array_merge($indicators, $this->integrityIndicators($input));
        $indicators = array_merge($indicators, $this->redirectIndicators($input));
        $risk = array_sum(array_map(fn($i) => (int)($i['weight'] ?? 0), $indicators));
        $suspiciousThreshold = (int)($cfg['security']['suspicious_threshold'] ?? 50);
        $elevatedThreshold = (int)($cfg['security']['elevated_threshold'] ?? 20);
        $hasHighIndicator = collect($indicators)->contains(fn($i) => ($i['severity'] ?? '') === 'high');
        foreach ($indicators as $indicator) {
            $reasons[] = ($indicator['reason'] ?? 'Suspicious indicator detected') . ' [risk +' . (int)($indicator['weight'] ?? 0) . ']';
        }
        $checks['security']['ok'] = $risk < $elevatedThreshold && !$hasHighIndicator;
        $checks['security']['value'] = $risk > 0 ? 'RISK ' . $risk : 'OK';

        // ---------- 3. Content validation ----------
        $contentOk = null;
        if ((bool)($websiteCfg['content_check_enabled'] ?? true) && $body !== '') {
            $contentOk = $this->validateContent($websiteCfg, $body, $reasons, $checks);
        } elseif ((bool)($websiteCfg['content_check_enabled'] ?? true)) {
            $reasons[] = 'Homepage returned an empty response body.';
            $contentOk = false;
            $checks['content']['ok'] = false;
            $checks['content']['value'] = 'EMPTY';
        } else {
            $checks['content']['value'] = 'Disabled';
        }

        // ---------- 4. Integrity ----------
        $integrity = $input['integrity'] ?? null;
        $integrityChanged = false;
        if (is_array($integrity) && ($integrity['status'] ?? 'not_configured') !== 'not_configured') {
            $integrityStatus = (string)$integrity['status'];
            $checks['integrity']['value'] = strtoupper($integrityStatus);
            $checks['integrity']['ok'] = $integrityStatus === 'ok' ? true : ($integrityStatus === 'baseline_missing' ? null : false);
            if ($integrityStatus === 'changed') {
                $integrityChanged = true;
                $changed = implode(', ', array_map(fn($f) => $f['path'], array_filter($integrity['files'] ?? [], fn($f) => in_array($f['state'] ?? '', ['changed', 'missing'], true))));
                $reasons[] = 'File integrity changed since trusted baseline: ' . $changed . '.';
            } elseif ($integrityStatus === 'baseline_missing') {
                $reasons[] = 'No trusted file baseline yet — capture one to enable integrity alerts.';
            } elseif ($integrityStatus === 'ok') {
                $reasons[] = 'All important files match their trusted baselines.';
            }
        } else {
            $checks['integrity']['value'] = 'Disabled';
        }

        // ---------- 5. Resolve final status (HTTP 200 alone is never "up") ----------
        $status = 'up';
        if ($risk >= $suspiciousThreshold || ($hasHighIndicator && $risk >= $elevatedThreshold)) {
            $status = 'suspicious';
            $reasons[] = 'Combined risk score ' . $risk . ' >= threshold ' . $suspiciousThreshold . ' — possible compromise.';
        } elseif ($contentOk === false || $expectedCodeMismatch || $integrityChanged || $risk >= $elevatedThreshold || in_array($code, [401, 403, 429], true)) {
            $status = 'warning';
        } elseif ($ms !== null && $ms >= (int)($cfg['http']['slow_ms'] ?? 3000)) {
            $status = 'slow';
            $reasons[] = 'Slow response (' . (int)$ms . ' ms).';
        }

        if ($status === 'up') {
            $reasons[] = 'Homepage content matches expectations and no compromise indicators were found.';
        }

        return $this->result($status, $reasons, $indicators, $checks, $contentOk, $risk);
    }

    private function validateContent(array $websiteCfg, string $body, array &$reasons, array &$checks): bool
    {
        $cfg = config('monitoring.content');
        $ok = true;
        $fail = function (string $reason) use (&$ok, &$reasons) {
            $ok = false;
            $reasons[] = $reason;
        };

        $title = $this->extractTitle($body);
        $visible = trim(preg_replace('/\s+/', ' ', strip_tags($body)) ?? '');
        if (mb_strlen($visible) < (int)($cfg['min_text_length'] ?? 120)) {
            $fail('Homepage appears blank or nearly empty (' . mb_strlen($visible) . ' visible characters).');
        }

        foreach ((array)($cfg['fatal_patterns'] ?? []) as $pattern) {
            if ($pattern !== '' && stripos($body, $pattern) !== false) {
                $fail('PHP/application error output detected in the homepage ("' . $pattern . '").');
                break;
            }
        }

        $expectedTitle = trim((string)($websiteCfg['expected_title'] ?? ''));
        if ($expectedTitle !== '') {
            if ($title === '' || stripos($title, $expectedTitle) === false) {
                $fail('Expected title "' . $expectedTitle . '" not found' . ($title !== '' ? ' (actual: "' . mb_substr($title, 0, 120) . '")' : ' (no <title> tag found)') . '.');
            }
        }

        $keywords = $this->keywordList((string)($websiteCfg['expected_keywords'] ?? ''));
        if ($keywords) {
            $missing = array_values(array_filter($keywords, fn($k) => stripos($body, $k) === false));
            if ($missing) {
                $fail('Expected content missing: "' . implode('", "', array_slice($missing, 0, 5)) . '"' . (count($missing) > 5 ? ' and ' . (count($missing) - 5) . ' more' : '') . '.');
            }
        }

        $checks['content']['ok'] = $ok;
        $checks['content']['value'] = $ok ? 'PASS' : 'FAILED';
        if ($ok) $reasons[] = 'Homepage content check passed (title: "' . mb_substr($title, 0, 120) . '").';
        return $ok;
    }

    private function baselineIndicators(array $input): array
    {
        $baseline = $input['baseline'] ?? null;
        $hash = $input['homepage_hash'] ?? null;
        $body = (string)($input['body'] ?? '');
        if (!is_array($baseline) || empty($baseline['hash']) || $hash === null || $body === '') return [];
        $indicators = [];
        if (!hash_equals((string)$baseline['hash'], $hash)) {
            $indicators[] = ['key' => 'homepage_hash_changed', 'reason' => 'Homepage content changed since the trusted baseline was recorded', 'weight' => 10, 'severity' => 'medium'];
            $oldTitle = trim((string)($baseline['title'] ?? ''));
            $newTitle = $this->extractTitle($body);
            if ($oldTitle !== '' && $newTitle !== '' && strcasecmp($oldTitle, $newTitle) !== 0) {
                $indicators[] = ['key' => 'homepage_title_changed', 'reason' => 'Page title changed since baseline ("' . mb_substr($oldTitle, 0, 80) . '" -> "' . mb_substr($newTitle, 0, 80) . '")', 'weight' => 20, 'severity' => 'medium'];
            }
        }
        return $indicators;
    }

    private function integrityIndicators(array $input): array
    {
        $integrity = $input['integrity'] ?? null;
        if (!is_array($integrity)) return [];
        $indicators = [];
        foreach ($integrity['findings'] ?? [] as $finding) {
            if ((int)($finding['weight'] ?? 0) >= 25) {
                $indicators[] = ['key' => $finding['pattern'] ?? 'file_integrity_suspicious', 'reason' => ($finding['file'] ?? 'file') . ': ' . ($finding['reason'] ?? 'suspicious change'), 'weight' => min(45, (int)$finding['weight']), 'severity' => $finding['severity'] ?? 'high'];
            }
        }
        return $indicators;
    }

    private function redirectIndicators(array $input): array
    {
        $original = strtolower((string)parse_url((string)($input['website']['url'] ?? ''), PHP_URL_HOST));
        $final = strtolower((string)parse_url((string)($input['final_url'] ?? ''), PHP_URL_HOST));
        if ($original === '' || $final === '' || $original === $final) return [];
        return [['key' => 'external_redirect', 'reason' => 'Homepage redirects to a different domain: ' . mb_substr((string)$input['final_url'], 0, 160), 'weight' => 25, 'severity' => 'high']];
    }

    public function extractTitle(string $body): string
    {
        if (!preg_match('/<title[^>]*>(.*?)<\/title>/is', $body, $m)) return '';
        return trim(html_entity_decode(preg_replace('/\s+/', ' ', $m[1]) ?? '', ENT_QUOTES));
    }

    public function keywordList(string $raw): array
    {
        $items = preg_split('/[\r\n,]+/', $raw) ?: [];
        return array_values(array_filter(array_map('trim', $items), fn($k) => $k !== ''));
    }

    private function result(string $status, array $reasons, array $indicators, array $checks, ?bool $contentOk, int $risk): array
    {
        return ['status' => $status, 'reasons' => array_values(array_unique($reasons)), 'indicators' => $indicators, 'checks' => $checks, 'content_ok' => $contentOk, 'risk_score' => $risk];
    }
}
