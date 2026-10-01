<?php
namespace App\Http\Controllers;
use App\Models\Website;
use App\Services\WebsiteMonitorService;
use App\Services\WebsiteSecurityService;
use Illuminate\Http\RedirectResponse;
use Illuminate\View\View;

class DiagnosticController extends Controller
{
    public function show(Website $website, WebsiteMonitorService $monitor): View
    { return view('diagnostics.show',['website'=>$website,'diagnostics'=>$monitor->diagnostics($website)]); }
    public function recheck(Website $website, WebsiteMonitorService $monitor): RedirectResponse
    { $monitor->check($website); return back()->with('success','Website rechecked.'); }
    public function security(Website $website, WebsiteSecurityService $security): RedirectResponse
    {
        if($website->document_root){ $result=$security->scanFiles($website); $existing=array_values(array_filter($website->security_findings ?? [], fn($f)=>($f['type'] ?? '')==='response'));
        $merged=array_merge($existing,$result['findings']);
        $website->update(['security_status'=>count($merged)?'suspicious':($result['status']==='clean'?'clean':'unknown'),'security_findings'=>$merged,'security_checked_at'=>now()]); return back()->with('success','File security scan completed: '.($result['scanned']??0).' files scanned.'); }
        return back()->withErrors(['security'=>'Document root is not configured for this website. Edit the website and add its Hostinger document root.']);
    }
}
