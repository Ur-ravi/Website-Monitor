<?php
namespace App\Services;
use App\Models\Website;
use Illuminate\Support\Facades\Mail;
use Throwable;
class MonitorAlertService
{
    // Event types: security | down | warning | recovered | integrity
    private const TITLES = [
        'security' => 'SECURITY ALERT',
        'down' => 'DOWNTIME ALERT',
        'warning' => 'WARNING',
        'recovered' => 'RECOVERED',
        'integrity' => 'INTEGRITY ALERT',
    ];

    /**
     * State-change based notification. Alerts are only sent on transitions,
     * so an unchanged incident never repeats every monitoring cycle.
     */
    public function notify(Website $website, string $event, array $reasons = []): void
    {
        $to=config('monitoring.alerts.email'); if(!$to) return;
        $title=self::TITLES[$event] ?? 'ALERT';
        try {
            $subject='['.$title.'] '.$website->name.' ['.strtoupper($website->status).']';
            $lines=[
                $website->name.' requires attention.',
                'URL: '.$website->url,
                'Event: '.$title,
                'Status: '.$website->status.' (previous: '.$this->previousStatus($website).')',
                'HTTP: '.($website->http_code ?: 'N/A'),
                'Content check: '.($website->last_content_ok === null ? 'N/A' : ($website->last_content_ok ? 'PASS' : 'FAILED')),
                'Integrity: '.($website->integrity_status ?: 'unknown'),
                'Security: '.($website->security_status ?: 'unknown').' (score '.($website->security_score ?? '—').'/100)',
                'Error: '.($website->last_error ?: 'N/A'),
            ];
            if($reasons){ $lines[]=''; $lines[]='Reasons:'; foreach(array_slice($reasons,0,10) as $reason) $lines[]='- '.$reason; }
            $lines[]=''; $lines[]='Time: '.now();
            Mail::raw(implode("\n",$lines),function($mail)use($to,$subject){$mail->to($to)->subject($subject);});
        } catch(Throwable $e) { report($e); }
    }

    /** Backwards-compatible entry point. */
    public function incident(Website $website, bool $recovered=false): void
    {
        $this->notify($website, $recovered ? 'recovered' : 'down', $website->status_reasons ?: []);
    }

    private function previousStatus(Website $website): string
    {
        $previous=$website->logs()->latest('checked_at')->skip(1)->first();
        return $previous->status ?? 'unknown';
    }
}
