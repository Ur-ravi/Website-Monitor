<?php
namespace App\Services;

use App\Models\MonitoringLog;
use App\Models\Website;
use Illuminate\Support\Facades\Http;
use Throwable;

class WebsiteMonitorService
{
    public function __construct(private WebsiteSecurityService $security, private WebsiteHealthService $health, private MonitorAlertService $alerts) {}

    public function check(Website $website): MonitoringLog
    {
        if($website->maintenance_mode){
            return $website->logs()->create(['status'=>'maintenance','error_message'=>'Website is in maintenance mode.','checked_at'=>now(),'security_status'=>$website->security_status ?: 'unknown','security_score'=>$website->security_score,'security_headers'=>$website->security_headers ?: []]);
        }
        $http=config('monitoring.http');
        $started=microtime(true); $code=null; $ms=null; $error=null; $body=''; $dnsOk=true; $finalUrl=$website->url; $chain=[]; $response=null;
        try {
            $this->guardUrl($website->url);
            $host=parse_url($website->url,PHP_URL_HOST);
            if($host && !checkdnsrr($host,'A') && !checkdnsrr($host,'AAAA') && !checkdnsrr($host,'CNAME')) { $dnsOk=false; throw new \RuntimeException('DNS resolution failed for '.$host); }
            [$response,$finalUrl,$chain]=$this->fetch($website->url,$http);
            $code=$response->status(); $ms=(int)round((microtime(true)-$started)*1000);
            $contentLength=(int)($response->header('Content-Length') ?: 0);
            if($contentLength>(int)$http['max_response_bytes']) throw new \RuntimeException('Response exceeds maximum allowed size ('.$contentLength.' bytes).');
            $body=(string)$response->body();
            if(strlen($body)>(int)$http['max_response_bytes']) $body=substr($body,0,(int)$http['max_response_bytes']); // oversized-response guard
        } catch(Throwable $e){ $ms=(int)round((microtime(true)-$started)*1000); $error=$e->getMessage(); }

        // Security scans (existing heuristics preserved for display/posture).
        $responseFindings=$body!=='' ? $this->security->scanResponse($body) : [];
        if(isset($response)) $responseFindings=array_merge($responseFindings,$this->security->scanHeaders($response->headers(), $website->url, $body));

        // Weighted compromise indicators for the response body.
        $indicators=$body!=='' ? $this->security->contentRiskIndicators($body) : [];
        foreach($responseFindings as $finding){
            if(($finding['type'] ?? '')==='content' && ($finding['severity'] ?? '')==='high'){
                $indicators[]=['key'=>$finding['pattern'] ?? 'content_finding','reason'=>$finding['reason'] ?? 'Suspicious content detected','weight'=>25,'severity'=>'high'];
            }
        }

        // File integrity monitoring (optional, read-only, never executes files).
        $integrity = $website->file_integrity_enabled ? $this->security->checkFileIntegrity($website) : null;

        // Homepage baseline.
        $baseline = $website->homepage_baseline ?: null;
        $homepageHash = $body!=='' ? hash('sha256',$body) : null;

        // Multi-level health resolution: HTTP 200 alone is NEVER "up".
        $evaluation=$this->health->evaluate([
            'website'=>$website->only(['url','expected_title','expected_keywords','expected_http_code','content_check_enabled']),
            'code'=>$code,'ms'=>$ms,'body'=>$body,'error'=>$error,'dns_ok'=>$dnsOk,
            'final_url'=>$finalUrl,'redirect_chain'=>$chain,
            'baseline'=>$baseline,'homepage_hash'=>$homepageHash,'integrity'=>$integrity,
            'indicators'=>$indicators,
        ]);
        $status=$evaluation['status']; $reasons=$evaluation['reasons'];
        if($status==='down' && $error===null) $error='HTTP '.$code;

        $existingFileFindings=array_values(array_filter($website->security_findings ?? [], fn($f)=>($f['type'] ?? '')==='file'));
        $integrityFindings=$integrity['findings'] ?? [];
        $securityFindings=array_merge($responseFindings,$existingFileFindings,$integrityFindings);
        $securityHeaders = [];
        if(isset($response)) {
            foreach ($response->headers() as $k=>$v) { $securityHeaders[strtolower($k)] = is_array($v) ? implode('; ', $v) : (string)$v; }
        }
        $securityScore = $this->securityScore($securityFindings, $securityHeaders, $website->url);
        $sslData=null; $urlScheme=strtolower((string)parse_url($website->url,PHP_URL_SCHEME)); $host=parse_url($website->url,PHP_URL_HOST);
        if($urlScheme==='https' && $host){ $sslData=$this->sslInfo($host,(int)(parse_url($website->url,PHP_URL_PORT) ?: 443)); }
        $securityStatus=$this->securityStatusFor($evaluation,$responseFindings,$integrity);
        $integrityStatus = $website->file_integrity_enabled ? (string)($integrity['status'] ?? 'unknown') : 'disabled';

        $previous=$website->status; $previousSecurity=$website->security_status;
        $failed=in_array($status,['down','warning','suspicious'],true);
        $failures=$failed ? ((int)$website->consecutive_failures+1) : 0;
        $successes=!$failed ? ((int)$website->consecutive_successes+1) : 0;
        $firstFailed=$failed ? ($website->first_failed_at ?: now()) : null;
        $recoveredNow=(!$failed && in_array($previous,['down','warning','suspicious'],true));
        $recovered=$recoveredNow ? now() : $website->last_recovered_at;
        $firstSuspicious=$website->first_suspicious_at; $lastSuspicious=$website->last_suspicious_at;
        if($status==='suspicious'){ $firstSuspicious=$firstSuspicious ?: now(); $lastSuspicious=now(); }

        $website->update([
            'status'=>$status,'http_code'=>$code,'response_time_ms'=>$ms,'last_checked_at'=>now(),'last_error'=>$error,
            'security_status'=>$securityStatus,'security_findings'=>$securityFindings,'security_checked_at'=>now(),'security_score'=>$securityScore,'security_headers'=>$securityHeaders,
            'ssl_expires_at'=>($sslData && !empty($sslData['expires_at'])) ? $sslData['expires_at'] : $website->ssl_expires_at,
            'last_ssl_check_at'=>$sslData ? now() : $website->last_ssl_check_at,'last_dns_check_at'=>now(),
            'consecutive_failures'=>$failures,'consecutive_successes'=>$successes,'first_failed_at'=>$firstFailed,'last_recovered_at'=>$recovered,
            'integrity_status'=>$integrityStatus,'last_content_ok'=>$evaluation['content_ok'],'status_reasons'=>$reasons,
            'first_suspicious_at'=>$firstSuspicious,'last_suspicious_at'=>$lastSuspicious,
        ]);

        // Auto-capture a trusted homepage baseline on the first usable check.
        if(empty($baseline) && $code!==null && $code>=200 && $code<400 && $body!==''){
            $this->storeHomepageBaseline($website,$body,$code,$finalUrl);
        }

        $log=$website->logs()->create([
            'status'=>$status,'http_code'=>$code,'response_time_ms'=>$ms,'error_message'=>$error,
            'security_status'=>$securityStatus,'security_findings'=>$securityFindings,'security_score'=>$securityScore,'security_headers'=>$securityHeaders,'checked_at'=>now(),'dns_ok'=>$dnsOk,
            'content_ok'=>$evaluation['content_ok'],'integrity_status'=>$integrityStatus,'status_reasons'=>$reasons,'homepage_hash'=>$homepageHash,
            'diagnostic'=>['previous_status'=>$previous,'recovered'=>$recoveredNow,'final_url'=>$finalUrl,'redirect_chain'=>$chain,'indicators'=>$evaluation['indicators'],'checks'=>$evaluation['checks'],'risk_score'=>$evaluation['risk_score']],
        ]);

        // State-change based alerts (no repeats for unchanged incidents).
        $event=null;
        if($status==='suspicious' && $previousSecurity!=='suspicious') $event='security';
        elseif($status==='down' && $failures===2) $event='down';
        elseif($status==='warning' && !in_array($previous,['warning','down','suspicious'],true) && $previous!==null) $event='warning';
        elseif($recoveredNow && filter_var(config('monitoring.alerts.on_recovery', true), FILTER_VALIDATE_BOOL)) $event='recovered';
        if($event!==null) $this->alerts->notify($website,$event,$reasons);
        return $log;
    }

    /** Capture a trusted baseline for the homepage and (if enabled) important files. */
    public function captureBaseline(Website $website): array
    {
        $this->guardUrl($website->url);
        [$response,$finalUrl,$chain]=$this->fetch($website->url,config('monitoring.http'));
        $code=$response->status(); $body=(string)$response->body();
        if($code<200||$code>=400||$body==='') throw new \RuntimeException('Homepage did not return usable content (HTTP '.$code.').');
        $baseline=$this->storeHomepageBaseline($website,$body,$code,$finalUrl);
        $files=($website->file_integrity_enabled && trim((string)$website->document_root)!=='') ? $this->security->setFileBaselines($website) : 0;
        return ['baseline'=>$baseline,'files'=>$files];
    }

    private function storeHomepageBaseline(Website $website,string $body,int $code,string $finalUrl): array
    {
        $baseline=['hash'=>hash('sha256',$body),'title'=>$this->health->extractTitle($body),'http_code'=>$code,'final_url'=>$finalUrl,'size'=>strlen($body),'recorded_at'=>now()->toIso8601String()];
        $website->forceFill(['homepage_baseline'=>$baseline])->save();
        return $baseline;
    }

    /** Guard against SSRF: only public http(s) URLs without credentials may be monitored. */
    private function guardUrl(string $url): void
    {
        $parts=parse_url($url);
        if(!$parts || empty($parts['host'])) throw new \RuntimeException('Invalid monitoring URL.');
        $scheme=strtolower($parts['scheme'] ?? '');
        if(!in_array($scheme,['http','https'],true)) throw new \RuntimeException('Only http(s) URLs can be monitored.');
        if(isset($parts['user']) || isset($parts['pass'])) throw new \RuntimeException('Credentials in the monitored URL are not allowed.');
        $hostName=$parts['host'];
        $ips=[];
        if(filter_var($hostName,FILTER_VALIDATE_IP)){
            $ips=[$hostName];
        } else {
            $ip=gethostbyname($hostName);
            if($ip && $ip!==$hostName){ $ips[]=$ip; }
            else {
                foreach((@dns_get_record($hostName,DNS_AAAA) ?: []) as $record){ if(!empty($record['ipv6'])) $ips[]=$record['ipv6']; }
            }
        }
        if(!$ips) throw new \RuntimeException('Could not resolve the host to a public IP address.');
        foreach($ips as $ip){
            if(!filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_NO_PRIV_RANGE|FILTER_FLAG_NO_RES_RANGE)){
                throw new \RuntimeException('Monitoring private, reserved or loopback addresses is not allowed.');
            }
        }
    }

    /**
     * Fetch with manually-followed, SSRF-guarded redirects. Returns [response, finalUrl, redirectChain].
     * Protocol is pinned to http/https at the cURL level.
     */
    private function fetch(string $url,array $http): array
    {
        $chain=[]; $current=$url; $response=null;
        for($i=0;$i<=(int)$http['max_redirects'];$i++){
            // Guzzle 8 rejects raw CURLOPT_PROTOCOLS/CURLOPT_REDIR_PROTOCOLS in the "curl"
            // option. Use Guzzle's own "protocols" request option to pin http/https only.
            // Redirects are manually followed below, so no redirect-protocol pinning is needed.
            $response=Http::connectTimeout((int)$http['connect_timeout'])->timeout((int)$http['timeout'])
                ->withHeaders(['User-Agent'=>'EduTechy-WebsiteMonitor/4.1','Accept'=>'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.5'])
                ->withOptions(['allow_redirects'=>false,'protocols'=>['http','https']])
                ->get($current);
            $location=$response->header('Location');
            if($response->status()>=300 && $response->status()<400 && $location!=='' && $i<(int)$http['max_redirects']){
                $next=$this->absoluteUrl($current,trim($location));
                $this->guardUrl($next);
                $chain[]=$next; $current=$next; continue;
            }
            break;
        }
        return [$response,$current,$chain];
    }

    private function absoluteUrl(string $baseUrl,string $location): string
    {
        if(preg_match('#^https?://#i',$location)) return $location;
        $parts=parse_url($baseUrl);
        $base=($parts['scheme'] ?? 'https').'://'.($parts['host'] ?? '').(isset($parts['port']) ? ':'.$parts['port'] : '');
        if(str_starts_with($location,'//')) return ($parts['scheme'] ?? 'https').':'.$location;
        if(str_starts_with($location,'/')) return $base.$location;
        $path=preg_replace('/[^\/]*$/','',$parts['path'] ?? '/');
        return $base.$path.$location;
    }

    /** Map the evaluation result + findings to security_status (clean/review/suspicious). */
    private function securityStatusFor(array $evaluation,array $responseFindings,?array $integrity): string
    {
        $risk=(int)($evaluation['risk_score'] ?? 0);
        $hasHigh=collect($evaluation['indicators'] ?? [])->contains(fn($i)=>($i['severity'] ?? '')==='high');
        if($risk>=(int)config('monitoring.security.suspicious_threshold') || $hasHigh) return 'suspicious';
        $headerFindings=array_filter($responseFindings,fn($f)=>($f['type'] ?? '')==='header');
        if($risk>=(int)config('monitoring.security.elevated_threshold') || $headerFindings) return 'review';
        if(is_array($integrity) && ($integrity['status'] ?? '')==='changed') return 'review';
        return 'clean';
    }

    public function diagnostics(Website $website): array
    {
        $host=parse_url($website->url,PHP_URL_HOST); $dns=[]; $dnsOk=false;
        if($host){ foreach(['A','AAAA','CNAME','MX'] as $type){ $records=@dns_get_record($host,constant('DNS_'.$type)); $dns[$type]=$records ?: []; if(in_array($type,['A','AAAA','CNAME'],true)&&$records) $dnsOk=true; } }
        $ssl=$this->sslInfo($host,parse_url($website->url,PHP_URL_PORT) ?: 443);
        $message=$website->last_error ?: (($website->http_code)?'HTTP '.$website->http_code:null);
        $previousLog=$website->logs()->latest('checked_at')->skip(1)->first();
        return ['dns_ok'=>$dnsOk,'dns'=>$dns,'ssl'=>$ssl,'status'=>$website->status,'http_code'=>$website->http_code,'response_time_ms'=>$website->response_time_ms,'error'=>$message,'security_status'=>$website->security_status,'security_findings'=>$website->security_findings ?: [],'security_score'=>$website->security_score,'security_headers'=>$website->security_headers ?: [],
            'status_reasons'=>$website->status_reasons ?: [],'content_ok'=>$website->last_content_ok,'integrity_status'=>$website->integrity_status,'baseline'=>$website->homepage_baseline,
            'previous_status'=>$previousLog->status ?? null,'first_failed_at'=>$website->first_failed_at,'first_suspicious_at'=>$website->first_suspicious_at,'last_suspicious_at'=>$website->last_suspicious_at,
            'file_integrity_enabled'=>$website->file_integrity_enabled,'likely'=>$this->likelyCause($website,$dnsOk,$ssl)];
    }


    private function securityScore(array $findings, array $headers, string $url): int
    {
        $score = 100;
        foreach ($findings as $f) {
            $severity = strtolower((string)($f['severity'] ?? 'medium'));
            $score -= $severity === 'high' ? 20 : ($severity === 'medium' ? 10 : ($severity === 'info' ? 2 : 5));
        }
        $required = ['x-content-type-options','x-frame-options','referrer-policy','content-security-policy'];
        foreach ($required as $h) if (!isset($headers[$h])) $score -= 5;
        if (str_starts_with(strtolower($url),'https://') && !isset($headers['strict-transport-security'])) $score -= 8;
        return max(0,min(100,$score));
    }

    private function sslInfo(?string $host,int $port=443): array
    {
        if(!$host) return ['ok'=>false,'message'=>'Host unavailable'];
        $ctx=stream_context_create(['ssl'=>['capture_peer_cert'=>true,'verify_peer'=>false,'verify_peer_name'=>false]]);
        $client=@stream_socket_client('ssl://'.$host.':'.$port,$errno,$errstr,8,STREAM_CLIENT_CONNECT,$ctx);
        if(!$client) return ['ok'=>false,'message'=>$errstr ?: 'SSL connection failed'];
        $params=stream_context_get_params($client); fclose($client); $cert=$params['options']['ssl']['peer_certificate']??null;
        if(!$cert) return ['ok'=>false,'message'=>'Certificate not available']; $data=@openssl_x509_parse($cert); $exp=$data['validTo_time_t']??null;
        return ['ok'=>(bool)$exp,'expires_at'=>$exp?date('c',$exp):null,'days_remaining'=>$exp?(int)floor(($exp-time())/86400):null,'subject'=>$data['subject']['CN']??null];
    }
    private function likelyCause(Website $w,bool $dnsOk,array $ssl): string
    {
        if(!$dnsOk) return 'DNS or domain resolution problem. Check A/AAAA/CNAME records and nameservers.';
        if(!$ssl['ok'] && str_starts_with($w->url,'https://')) return 'SSL/TLS problem. Check the certificate, hostname and HTTPS configuration.';
        if($w->status==='suspicious') return 'Possible compromise: the site responds but shows weighted compromise indicators (defacement, injected or obfuscated code, baseline mismatch). Review the indicators and restore trusted files if confirmed.';
        if($w->http_code>=500) return 'Server/application error. Check PHP/OJS/Laravel/CodeIgniter logs, database connection and .htaccess.';
        if($w->http_code===404) return 'Requested URL returns 404. Check the URL/path or application routing.';
        if($w->status==='slow') return 'Response time is high. Check hosting CPU/RAM, database queries, plugins and network latency.';
        if($w->status==='warning') return 'The site responds, but content/integrity validation found problems. Compare against the expected title, keywords and trusted baseline.';
        if(in_array($w->security_status,['suspicious','review'],true)) return 'Security review is recommended. Review the detected code/content indicators and security headers before taking action.';
        return 'No single cause can be confirmed from an external HTTP check.';
    }
}
