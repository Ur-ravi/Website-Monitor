<?php
namespace App\Services;

use App\Models\MonitoringLog;
use App\Models\Website;
use Illuminate\Support\Facades\Http;
use Throwable;

class WebsiteMonitorService
{
    public function __construct(private WebsiteSecurityService $security, private MonitorAlertService $alerts) {}

    public function check(Website $website): MonitoringLog
    {
        if($website->maintenance_mode){
            return $website->logs()->create(['status'=>'maintenance','error_message'=>'Website is in maintenance mode.','checked_at'=>now(),'security_status'=>$website->security_status ?: 'unknown','security_score'=>$website->security_score,'security_headers'=>$website->security_headers ?: []]);
        }
        $started=microtime(true); $status='down'; $code=null; $ms=null; $error=null; $body=''; $dnsOk=true; $sslOk=null;
        try {
            $host=parse_url($website->url,PHP_URL_HOST);
            if($host && !checkdnsrr($host,'A') && !checkdnsrr($host,'AAAA') && !checkdnsrr($host,'CNAME')) { $dnsOk=false; throw new \RuntimeException('DNS resolution failed for '.$host); }
            $response=Http::connectTimeout(3)->timeout(8)->withHeaders(['User-Agent'=>'EduTechy-WebsiteMonitor/3.0','Accept'=>'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.5'])->withOptions(['allow_redirects'=>['max'=>5,'track_redirects'=>true]])->get($website->url);
            $code=$response->status(); $ms=(int)round((microtime(true)-$started)*1000); $body=(string)$response->body();
            $status=($code>=200&&$code<400) ? ($ms>=3000 ? 'slow' : 'up') : (in_array($code,[401,403,429],true) ? 'warning' : 'down');
            if($status==='down') $error='HTTP '.$code;
        } catch(Throwable $e){ $ms=(int)round((microtime(true)-$started)*1000); $error=$e->getMessage(); }

        $responseFindings=$body!=='' ? $this->security->scanResponse($body) : [];
        if(isset($response)) {
            $responseFindings=array_merge($responseFindings,$this->security->scanHeaders($response->headers(), $website->url, $body));
        }
        $existingFileFindings=array_values(array_filter($website->security_findings ?? [], fn($f)=>($f['type'] ?? '')==='file'));
        $securityFindings=array_merge($responseFindings,$existingFileFindings);
        $securityHeaders = [];
        if(isset($response)) {
            foreach ($response->headers() as $k=>$v) { $securityHeaders[strtolower($k)] = is_array($v) ? implode('; ', $v) : (string)$v; }
        }
        $securityScore = $this->securityScore($securityFindings, $securityHeaders, $website->url);
        $sslData=null; $urlScheme=strtolower((string)parse_url($website->url,PHP_URL_SCHEME));
        if($urlScheme==='https' && $host){ $sslData=$this->sslInfo($host,(int)(parse_url($website->url,PHP_URL_PORT) ?: 443)); }
        $threatFindings=array_values(array_filter($securityFindings, function($f){
            $type=$f['type'] ?? '';
            return in_array($type,['response','file','content'],true);
        }));
        $headerFindings=array_values(array_filter($securityFindings, fn($f)=>($f['type'] ?? '')==='header'));
        $securityStatus=$threatFindings ? 'suspicious' : ($headerFindings ? 'review' : 'clean');
        $previous=$website->status; $previousSecurity=$website->security_status;
        $failed=in_array($status,['down','warning'],true);
        $failures=$failed ? ((int)$website->consecutive_failures+1) : 0;
        $successes=!$failed ? ((int)$website->consecutive_successes+1) : 0;
        $firstFailed=$failed ? ($website->first_failed_at ?: now()) : null;
        $recoveredNow=(!$failed && in_array($previous,['down','warning'],true));
        $recovered=$recoveredNow ? now() : $website->last_recovered_at;
        $website->update([
            'status'=>$status,'http_code'=>$code,'response_time_ms'=>$ms,'last_checked_at'=>now(),'last_error'=>$error,
            'security_status'=>$securityStatus,'security_findings'=>$securityFindings,'security_checked_at'=>now(),'security_score'=>$securityScore,'security_headers'=>$securityHeaders,
            'ssl_expires_at'=>($sslData && !empty($sslData['expires_at'])) ? $sslData['expires_at'] : $website->ssl_expires_at,
            'last_ssl_check_at'=>$sslData ? now() : $website->last_ssl_check_at,'last_dns_check_at'=>now(),
            'consecutive_failures'=>$failures,'consecutive_successes'=>$successes,'first_failed_at'=>$firstFailed,'last_recovered_at'=>$recovered,
        ]);
        $log=$website->logs()->create([
            'status'=>$status,'http_code'=>$code,'response_time_ms'=>$ms,'error_message'=>$error,
            'security_status'=>$securityStatus,'security_findings'=>$securityFindings,'security_score'=>$securityScore,'security_headers'=>$securityHeaders,'checked_at'=>now(),'dns_ok'=>$dnsOk,
            'diagnostic'=>['previous_status'=>$previous,'recovered'=>$recoveredNow]
        ]);
        $securityAlert=($securityStatus==='suspicious' && $previousSecurity!=='suspicious');
        $shouldAlert = ($failed && $failures === 2) || ($recoveredNow && filter_var(env('MONITOR_ALERT_ON_RECOVERY', true), FILTER_VALIDATE_BOOL)) || $securityAlert;
        if($shouldAlert) $this->alerts->incident($website,$recoveredNow);
        return $log;
    }

    public function diagnostics(Website $website): array
    {
        $host=parse_url($website->url,PHP_URL_HOST); $dns=[]; $dnsOk=false;
        if($host){ foreach(['A','AAAA','CNAME','MX'] as $type){ $records=@dns_get_record($host,constant('DNS_'.$type)); $dns[$type]=$records ?: []; if(in_array($type,['A','AAAA','CNAME'],true)&&$records) $dnsOk=true; } }
        $ssl=$this->sslInfo($host,parse_url($website->url,PHP_URL_PORT) ?: 443);
        $message=$website->last_error ?: (($website->http_code)?'HTTP '.$website->http_code:null);
        return ['dns_ok'=>$dnsOk,'dns'=>$dns,'ssl'=>$ssl,'status'=>$website->status,'http_code'=>$website->http_code,'response_time_ms'=>$website->response_time_ms,'error'=>$message,'security_status'=>$website->security_status,'security_findings'=>$website->security_findings ?: [],'security_score'=>$website->security_score,'security_headers'=>$website->security_headers ?: [],'likely'=>$this->likelyCause($website,$dnsOk,$ssl)];
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
        if($w->http_code>=500) return 'Server/application error. Check PHP/OJS/Laravel/CodeIgniter logs, database connection and .htaccess.';
        if($w->http_code===404) return 'Requested URL returns 404. Check the URL/path or application routing.';
        if($w->status==='slow') return 'Response time is high. Check hosting CPU/RAM, database queries, plugins and network latency.';
        if(in_array($w->security_status,['suspicious','review'],true)) return 'Security review is recommended. Review the detected code/content indicators and security headers before taking action.';
        return 'No single cause can be confirmed from an external HTTP check.';
    }
}
