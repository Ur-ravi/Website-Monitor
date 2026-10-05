<?php
namespace App\Services;

use App\Models\Website;
use Illuminate\Support\Facades\File;
use Throwable;

class WebsiteSecurityService
{
    public function scanResponse(string $body): array
    {
        $findings=[];
        $rules=[
            'eval()'=>'PHP/JavaScript eval pattern',
            'base64_decode('=>'PHP base64 decoding pattern',
            'gzinflate('=>'Compressed PHP payload pattern',
            'gzuncompress('=>'Compressed PHP payload pattern',
            'str_rot13('=>'String obfuscation pattern',
            'shell_exec('=>'Shell execution pattern',
            'passthru('=>'Command execution pattern',
            'proc_open('=>'Process execution pattern',
            'popen('=>'Process execution pattern',
            'assert('=>'Dynamic code execution pattern',
            'atob('=>'Base64 JavaScript decoding pattern',
            'document.write('=>'Dynamic document injection pattern',
            'javascript:'=>'JavaScript URL pattern',
            '<iframe'=>'Iframe detected in response',
            'unescape('=>'JavaScript obfuscation pattern',
        ];
        $lower=strtolower($body);
        foreach($rules as $needle=>$reason){
            $count=substr_count($lower,strtolower($needle));
            if($count>0) $findings[]=['type'=>'response','pattern'=>$needle,'reason'=>$reason,'count'=>$count];
        }
        if(preg_match('/(?:atob|base64_decode)\s*\([^)]{100,}/i',$body)) $findings[]=['type'=>'response','pattern'=>'large encoded payload','reason'=>'Large encoded content detected'];
        return $findings;
    }


    public function scanHeaders(array $headers, string $url, string $body = ''): array
    {
        $findings = [];
        $normalized = [];
        foreach ($headers as $key => $value) {
            $normalized[strtolower($key)] = is_array($value) ? implode('; ', $value) : (string)$value;
        }
        $isHttps = str_starts_with(strtolower($url), 'https://');
        $checks = [
            'x-content-type-options' => ['nosniff', 'Missing X-Content-Type-Options: nosniff'],
            'x-frame-options' => ['any', 'Missing X-Frame-Options (clickjacking protection)'],
            'referrer-policy' => ['any', 'Missing Referrer-Policy'],
            'content-security-policy' => ['any', 'Missing Content-Security-Policy'],
        ];
        foreach ($checks as $header => [$expected, $reason]) {
            if (!array_key_exists($header, $normalized)) {
                $findings[]=['type'=>'header','pattern'=>$header,'reason'=>$reason,'severity'=>'low'];
            } elseif ($expected !== 'any' && stripos($normalized[$header], $expected) === false) {
                $findings[]=['type'=>'header','pattern'=>$header,'reason'=>'Security header is present but does not use the recommended value.','severity'=>'low'];
            }
        }
        if ($isHttps && !array_key_exists('strict-transport-security', $normalized)) {
            $findings[]=['type'=>'header','pattern'=>'strict-transport-security','reason'=>'Missing HSTS header on HTTPS website.','severity'=>'medium'];
        }
        if (preg_match('/<script[^>]+src=["\']http:\/\//i', $body)) {
            $findings[]=['type'=>'content','pattern'=>'mixed-content-script','reason'=>'HTTP script resource detected on an HTTPS page.','severity'=>'high'];
        }
        if (preg_match('/<iframe[^>]+src=["\']http:\/\//i', $body)) {
            $findings[]=['type'=>'content','pattern'=>'mixed-content-iframe','reason'=>'HTTP iframe resource detected on an HTTPS page.','severity'=>'high'];
        }
        if (isset($normalized['server']) && preg_match('/(php|apache|nginx)[\/ ]?[0-9]/i', $normalized['server'])) {
            $findings[]=['type'=>'header','pattern'=>'server-version','reason'=>'Server header exposes a software version.','severity'=>'info'];
        }
        return $findings;
    }

    public function scanFiles(Website $website, bool $recentOnly=false): array
    {
        $root=trim((string)$website->document_root);
        if($root==='') return ['status'=>'not_configured','findings'=>[],'scanned'=>0,'message'=>'Document root is not configured for this website.'];
        if(!is_dir($root)) return ['status'=>'error','findings'=>[],'scanned'=>0,'message'=>'Document root does not exist or is not readable.'];
        $findings=[];$scanned=0;$cutoff=$recentOnly && $website->security_checked_at ? $website->security_checked_at->copy()->subHours(2)->timestamp : null;$extensions=['php','phtml','php3','php4','php5','php7','php8','js','html','htm','css','htaccess'];
        try {
            $it=new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS));
            foreach($it as $file){
                if(!$file->isFile() || $file->getSize()>5*1024*1024) continue;
                if($cutoff && $file->getMTime() < $cutoff) continue;
                $ext=strtolower($file->getExtension()); if(!in_array($ext,$extensions,true)) continue;
                $scanned++; $path=$file->getPathname(); $content=@file_get_contents($path); if($content===false) continue;
                $checks=['eval('=>'Dynamic execution','base64_decode('=>'Encoded PHP payload','gzinflate('=>'Compressed payload','shell_exec('=>'Shell execution','passthru('=>'Command execution','proc_open('=>'Process execution','popen('=>'Process execution','assert('=>'Dynamic execution','<iframe'=>'Iframe injection','javascript:'=>'JavaScript URL','document.write('=>'Dynamic document injection'];
                foreach($checks as $needle=>$reason){ if(stripos($content,$needle)!==false) $findings[]=['type'=>'file','file'=>str_replace($root,'',$path),'pattern'=>$needle,'reason'=>$reason,'modified_at'=>date('c',$file->getMTime())]; }
            }
        } catch(Throwable $e){ return ['status'=>'error','findings'=>$findings,'scanned'=>$scanned,'message'=>$e->getMessage()]; }
        return ['status'=>$findings?'suspicious':'clean','findings'=>$findings,'scanned'=>$scanned,'message'=>$findings?'Review detected patterns before deleting anything.':'No configured heuristic indicators found.'];
    }

    /**
     * Weighted compromise indicators for arbitrary untrusted content (HTTP body or file).
     * The SUM of weights decides the outcome - a single innocent keyword can never mark a site compromised.
     *
     * @return array<int, array{key:string, reason:string, weight:int, severity:string}>
     */
    public function contentRiskIndicators(string $content): array
    {
        $indicators = [];
        $push = function (string $key, string $reason, int $weight, string $severity) use (&$indicators) {
            $indicators[] = ['key' => $key, 'reason' => $reason, 'weight' => $weight, 'severity' => $severity];
        };

        // Obfuscated dynamic code execution (strongest signal).
        if (preg_match('/eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|rawurldecode|hex2bin|strrev)\s*\(/i', $content)) {
            $push('obfuscated_eval', 'Obfuscated eval() payload detected (eval + encoding function)', 45, 'high');
        } elseif (preg_match('/\beval\s*\(/i', $content)) {
            $push('eval_usage', 'eval() usage detected in response content', 10, 'medium');
        }

        if (preg_match('/\b(shell_exec|passthru|proc_open|popen)\s*\(/i', $content)) {
            $push('shell_execution', 'Shell/process execution function detected in content', 25, 'high');
        }
        if (preg_match('/\bsystem\s*\(|\bexec\s*\(/i', $content)) {
            $push('command_execution', 'Command execution function detected in content', 20, 'medium');
        }

        // Encoded/obfuscated payloads.
        if (preg_match('/[A-Za-z0-9+\/]{300,}={0,2}/', $content)) {
            $push('large_encoded_payload', 'Large encoded (base64-like) payload embedded in content', 30, 'high');
        }
        if (preg_match('/(?:\\x[0-9a-fA-F]{2}){16,}/', $content)) {
            $push('hex_encoded_payload', 'Hex-encoded payload string detected', 30, 'high');
        }
        if (stripos($content, 'var _0x') !== false || preg_match('/_0x[0-9a-f]{4,}\s*=/i', $content)) {
            $push('obfuscated_javascript', 'Obfuscated JavaScript (hex-variable style) detected', 35, 'high');
        }
        if (preg_match('/document\.write\s*\(\s*unescape\s*\(/i', $content)) {
            $push('obfuscated_write', 'document.write(unescape(...)) injection pattern detected', 25, 'high');
        }

        // Hidden iframe injection.
        if (preg_match('/<iframe[^>]*(width\s*=\s*["\']?0\b|height\s*=\s*["\']?0\b|display\s*:\s*none|visibility\s*:\s*hidden|left\s*:\s*-[0-9]{3,}|top\s*:\s*-[0-9]{3,})/i', $content)) {
            $push('hidden_iframe', 'Hidden iframe injection detected', 30, 'high');
        }

        // Unexpected redirect injection via meta refresh.
        if (preg_match('/<meta[^>]+http-equiv\s*=\s*["\']?refresh["\']?[^>]*url\s*=\s*(https?:)?\/\//i', $content)) {
            $push('meta_redirect', 'Meta-refresh redirect to an external URL detected', 20, 'medium');
        }

        // Defacement markers (single match is a strong signal).
        foreach ((array)config('monitoring.security.defacement_keywords', []) as $keyword) {
            if ($keyword !== '' && stripos($content, $keyword) !== false) {
                $push('defacement_marker', 'Defacement marker detected ("' . $keyword . '")', 45, 'high');
                break;
            }
        }

        // Spam/phishing markers (require >= 2 distinct matches to escalate; 1 match is a low signal).
        $spamHits = [];
        foreach ((array)config('monitoring.security.spam_keywords', []) as $keyword) {
            if ($keyword !== '' && stripos($content, $keyword) !== false) $spamHits[] = $keyword;
        }
        if (count($spamHits) >= 2) {
            $push('spam_content', 'Multiple spam/phishing markers detected ("' . implode('", "', array_slice($spamHits, 0, 3)) . '")', 30, 'high');
        } elseif (count($spamHits) === 1) {
            $push('spam_content_single', 'Spam marker detected ("' . $spamHits[0] . '")', 12, 'medium');
        }

        // Known web-shell file names.
        foreach ((array)config('monitoring.security.shell_names', []) as $name) {
            if ($name !== '' && stripos($content, $name) !== false) {
                $push('webshell_name', 'Known web-shell identifier detected ("' . $name . '")', 50, 'high');
                break;
            }
        }

        // PHP source exposure in an HTML response (server misconfiguration or injected file).
        if (stripos($content, '<?php') !== false && stripos($content, '<html') !== false) {
            $push('php_source_exposure', 'Raw PHP source code exposed in HTML response', 20, 'medium');
        }

        return $indicators;
    }

    /**
     * Read-only file integrity check for important files against stored SHA-256 baselines.
     * Files are hashed and pattern-scanned - NEVER executed.
     */
    public function checkFileIntegrity(Website $website): array
    {
        $root = $this->validatedRoot($website);
        if ($root === null) {
            return ['status' => 'not_configured', 'files' => [], 'findings' => [], 'risk' => 0, 'message' => 'Document root is not configured or is invalid.'];
        }
        $files = (array)config('monitoring.integrity.important_files', []);
        $baselines = \App\Models\WebsiteFileBaseline::where('website_id', $website->id)->get()->keyBy('path');
        $result = ['status' => 'ok', 'files' => [], 'findings' => [], 'risk' => 0, 'root' => $root];
        $hasBaseline = false;

        foreach ($files as $relative) {
            $entry = ['path' => $relative, 'state' => 'absent', 'hash' => null, 'baseline' => null];
            $baseline = $baselines->get($relative);
            if ($baseline) {
                $hasBaseline = true;
                $entry['baseline'] = $baseline->sha256;
            }
            $absolute = $root . DIRECTORY_SEPARATOR . $relative;
            if (!is_file($absolute)) {
                if ($baseline) {
                    $entry['state'] = 'missing';
                    $result['findings'][] = ['type' => 'file_integrity', 'file' => $relative, 'reason' => 'Important file removed from the server', 'severity' => 'high', 'weight' => 40];
                }
                $result['files'][] = $entry;
                continue;
            }
            $content = $this->readFileCapped($absolute);
            if ($content === null) {
                $result['files'][] = $entry;
                continue;
            }
            $entry['hash'] = hash('sha256', $content);
            if (!$baseline) {
                $entry['state'] = 'baseline_missing';
            } elseif (hash_equals($baseline->sha256, $entry['hash'])) {
                $entry['state'] = 'ok';
            } else {
                $entry['state'] = 'changed';
                $riskIndicators = $this->contentRiskIndicators($content);
                $riskSum = array_sum(array_map(fn($i) => (int)$i['weight'], $riskIndicators));
                $result['findings'][] = ['type' => 'file_integrity', 'file' => $relative, 'reason' => 'File changed since the trusted baseline was recorded', 'severity' => $riskSum >= 25 ? 'high' : 'medium', 'weight' => min(40, 10 + $riskSum)];
                foreach ($riskIndicators as $indicator) {
                    $result['findings'][] = ['type' => 'file_integrity', 'file' => $relative, 'reason' => 'Suspicious pattern in changed file: ' . $indicator['reason'], 'pattern' => $indicator['key'], 'severity' => $indicator['severity'], 'weight' => $indicator['weight']];
                }
                $result['risk'] += $riskSum;
            }
            $result['files'][] = $entry;
        }

        $changedCount = count(array_filter($result['files'], fn($f) => in_array($f['state'], ['changed', 'missing'], true)));
        $result['status'] = $changedCount > 0 ? 'changed' : ($hasBaseline ? 'ok' : 'baseline_missing');
        $result['message'] = match ($result['status']) {
            'changed' => 'One or more important files changed since the trusted baseline.',
            'baseline_missing' => 'No trusted baseline recorded yet for the important files.',
            default => 'All important files match their trusted baselines.',
        };
        return $result;
    }

    /** Create/refresh trusted SHA-256 baselines for important files. Returns number of files baselined. */
    public function setFileBaselines(Website $website): int
    {
        $root = $this->validatedRoot($website);
        if ($root === null) return 0;
        $count = 0;
        foreach ((array)config('monitoring.integrity.important_files', []) as $relative) {
            $absolute = $root . DIRECTORY_SEPARATOR . $relative;
            if (!is_file($absolute)) continue;
            $content = $this->readFileCapped($absolute);
            if ($content === null) continue;
            \App\Models\WebsiteFileBaseline::updateOrCreate(
                ['website_id' => $website->id, 'path' => $relative],
                ['sha256' => hash('sha256', $content), 'size' => strlen($content), 'recorded_at' => now()]
            );
            $count++;
        }
        return $count;
    }

    /** Validate the document root to prevent path traversal / unsafe roots. */
    private function validatedRoot(Website $website): ?string
    {
        $root = trim((string)$website->document_root);
        if ($root === '' || str_contains($root, "\0")) return null;
        $real = realpath($root);
        if ($real === false || !is_dir($real)) return null;
        return $real;
    }

    /** Read a file with a hard size cap. Never executes file content. */
    private function readFileCapped(string $path): ?string
    {
        $max = (int)config('monitoring.integrity.max_file_bytes', 5 * 1024 * 1024);
        $size = @filesize($path);
        if ($size === false || $size > $max) return null;
        $content = @file_get_contents($path);
        return $content === false ? null : $content;
    }
}
