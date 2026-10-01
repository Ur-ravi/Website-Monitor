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
}
