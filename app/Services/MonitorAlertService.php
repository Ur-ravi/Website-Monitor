<?php
namespace App\Services;
use App\Models\Website;
use Illuminate\Support\Facades\Mail;
use Throwable;
class MonitorAlertService
{
    public function incident(Website $website, bool $recovered=false): void
    {
        $to=env('MONITOR_ALERT_EMAIL'); if(!$to) return;
        try {
            $subject=$recovered ? 'Website Recovered: '.$website->name : 'Website Alert: '.$website->name.' ['.strtoupper($website->status).']';
            $body=$recovered
                ? $website->name." has recovered.\nURL: {$website->url}\nStatus: {$website->status}\nHTTP: ".($website->http_code ?: 'N/A')."\nTime: ".now()
                : $website->name." requires attention.\nURL: {$website->url}\nStatus: {$website->status}\nHTTP: ".($website->http_code ?: 'N/A')."\nError: ".($website->last_error ?: 'N/A')."\nSecurity: ".($website->security_status ?: 'unknown')."\nTime: ".now();
            Mail::raw($body,function($mail)use($to,$subject){$mail->to($to)->subject($subject);});
        } catch(Throwable $e) { report($e); }
    }
}
