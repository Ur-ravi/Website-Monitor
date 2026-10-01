<?php
namespace App\Console\Commands;
use App\Models\Website;
use App\Services\WebsiteSecurityService;
use Illuminate\Console\Command;
class ScanWebsiteFiles extends Command
{
    protected $signature='websites:file-scan {--full : Scan all eligible files instead of recently modified files}';
    protected $description='Run a heuristic server-side file security scan for configured websites.';
    public function handle(WebsiteSecurityService $scanner): int
    {
        $count=0; Website::where('is_active',true)->where('maintenance_mode',false)->whereNotNull('document_root')->chunkById(5,function($websites)use($scanner,&$count){foreach($websites as $w){$r=$scanner->scanFiles($w,$this->option('full')?false:true);$existing=array_values(array_filter($w->security_findings??[],fn($f)=>($f['type']??'')==='response'));$merged=array_merge($existing,$r['findings']);$w->update(['security_status'=>$merged?'suspicious':($r['status']==='clean'?'clean':'unknown'),'security_findings'=>$merged,'security_checked_at'=>now()]);$count++;$this->line($w->url.' -> '.($r['status']??'unknown').' ('.$r['scanned'].' files)');}});$this->info("Scanned {$count} website(s)."); return self::SUCCESS;
    }
}
