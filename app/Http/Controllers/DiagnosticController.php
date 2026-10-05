<?php
namespace App\Http\Controllers;
use App\Models\Website;
use App\Services\WebsiteMonitorService;
use App\Services\WebsiteSecurityService;
use Illuminate\Http\RedirectResponse;
use Illuminate\View\View;
use Throwable;

class DiagnosticController extends Controller
{
    public function show(Website $website, WebsiteMonitorService $monitor): View
    { return view('diagnostics.show',['website'=>$website,'diagnostics'=>$monitor->diagnostics($website)]); }

    public function recheck(Website $website, WebsiteMonitorService $monitor): RedirectResponse
    { $monitor->check($website); return back()->with('success','Website rechecked.'); }

    public function baseline(Website $website, WebsiteMonitorService $monitor): RedirectResponse
    {
        try {
            $result=$monitor->captureBaseline($website);
            return back()->with('success','Trusted baseline captured: homepage + '.$result['files'].' important file(s).');
        } catch (Throwable $e) {
            return back()->withErrors(['baseline'=>'Baseline capture failed: '.$e->getMessage()]);
        }
    }

    public function security(Website $website, WebsiteSecurityService $security): RedirectResponse
    {
        if($website->document_root){
            $result=$security->scanFiles($website);
            $existingResponse=array_values(array_filter($website->security_findings ?? [], fn($f)=>($f['type'] ?? '')==='response'));
            // The fresh integrity result is authoritative; old file_integrity findings are
            // intentionally dropped so they never accumulate as duplicates across scans.
            $integrity=$website->file_integrity_enabled ? $security->checkFileIntegrity($website) : ['findings'=>[]];
            $merged=array_merge($existingResponse,$result['findings'],$integrity['findings'] ?? []);
            $totalRisk=collect($merged)->sum(fn($f)=>(int)($f['weight'] ?? 0));
            $hasHigh=collect($merged)->contains(fn($f)=>($f['severity'] ?? '')==='high');
            $status = $hasHigh || $totalRisk >= (int)config('monitoring.security.suspicious_threshold') ? 'suspicious' : ($totalRisk >= (int)config('monitoring.security.elevated_threshold') || $merged ? 'review' : ($result['status']==='clean' && ($integrity['status'] ?? 'ok')==='ok' ? 'clean' : 'unknown'));
            $website->update(['security_status'=>$status,'security_findings'=>$merged,'security_checked_at'=>now()]);
            return back()->with('success','File security scan completed: '.($result['scanned']??0).' files scanned. Risk score: '.$totalRisk.'.');
        }
        return back()->withErrors(['security'=>'Document root is not configured for this website. Edit the website and add its Hostinger document root.']);
    }
}
