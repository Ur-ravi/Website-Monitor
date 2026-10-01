<?php

namespace App\Console\Commands;

use App\Models\Website;
use App\Services\WebsiteMonitorService;
use Illuminate\Console\Command;

class CheckWebsites extends Command
{
    protected $signature = 'websites:check {--website= : Check a specific website ID}';
    protected $description = 'Check active websites and store uptime results.';

    public function handle(WebsiteMonitorService $monitor): int
    {
        $query = Website::where('is_active', true);
        if ($id = $this->option('website')) $query->whereKey($id);

        $count = 0;
        $query->chunkById(20, function ($websites) use ($monitor, &$count) {
            foreach ($websites as $website) {
                $monitor->check($website);
                $count++;
                $this->line($website->url . ' -> ' . $website->fresh()->status);
            }
        });

        $this->info("Checked {$count} website(s).");
        return self::SUCCESS;
    }
}
