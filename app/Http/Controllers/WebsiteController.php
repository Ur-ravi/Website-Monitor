<?php

namespace App\Http\Controllers;

use App\Models\Website;
use App\Services\WebsiteMonitorService;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Illuminate\View\View;
use Symfony\Component\HttpFoundation\StreamedResponse;

class WebsiteController extends Controller
{
    public function index(): View
    {
        $websites = Website::latest()->paginate(30);
        return view('websites.index', compact('websites'));
    }

    public function create(): View
    {
        return view('websites.create');
    }

    public function store(Request $request): RedirectResponse
    {
        $data = $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'url' => ['required', 'url', 'max:2048', 'unique:websites,url'],
            'technology' => ['nullable', 'string', 'max:100'],
            'document_root' => ['nullable', 'string', 'max:1024'],
            'expected_title' => ['nullable', 'string', 'max:255'],
            'expected_keywords' => ['nullable', 'string', 'max:2000'],
            'expected_http_code' => ['nullable', 'integer', 'min:100', 'max:599'],
        ]);

        Website::create($data + [
            'is_active' => $request->boolean('is_active', true),
            'maintenance_mode' => false,
            'status' => 'unknown',
            'content_check_enabled' => $request->boolean('content_check_enabled', true),
            'file_integrity_enabled' => $request->boolean('file_integrity_enabled'),
        ]);
        return redirect()->route('websites.index')->with('success', 'Website added successfully.');
    }

    public function edit(Website $website): View
    {
        return view('websites.edit', compact('website'));
    }

    public function update(Request $request, Website $website): RedirectResponse
    {
        $data = $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'url' => ['required', 'url', 'max:2048', \Illuminate\Validation\Rule::unique('websites', 'url')->ignore($website->id)],
            'technology' => ['nullable', 'string', 'max:100'],
            'document_root' => ['nullable', 'string', 'max:1024'],
            'expected_title' => ['nullable', 'string', 'max:255'],
            'expected_keywords' => ['nullable', 'string', 'max:2000'],
            'expected_http_code' => ['nullable', 'integer', 'min:100', 'max:599'],
        ]);
        $website->update($data + [
            'is_active' => $request->boolean('is_active'),
            'maintenance_mode' => $request->boolean('maintenance_mode'),
            'content_check_enabled' => $request->boolean('content_check_enabled'),
            'file_integrity_enabled' => $request->boolean('file_integrity_enabled'),
        ]);
        return redirect()->route('websites.index')->with('success', 'Website updated.');
    }

    public function destroy(Website $website): RedirectResponse
    {
        $website->delete();
        return back()->with('success', 'Website deleted.');
    }

    public function check(Request $request, Website $website, WebsiteMonitorService $monitor)
    {
        $log = $monitor->check($website);
        $fresh = $website->fresh();
        if ($request->expectsJson() || $request->ajax()) {
            return response()->json([
                'ok' => true,
                'website_id' => $fresh->id,
                'name' => $fresh->name,
                'status' => $fresh->status,
                'http_code' => $fresh->http_code,
                'response_time_ms' => $fresh->response_time_ms,
                'security_status' => $fresh->security_status,
                'security_findings_count' => count($fresh->security_findings ?? []),
                'content_ok' => $fresh->last_content_ok,
                'integrity_status' => $fresh->integrity_status,
                'reasons' => $fresh->status_reasons ?? [],
                'error' => $fresh->last_error,
                'checked_at' => optional($fresh->last_checked_at)->toIso8601String(),
            ]);
        }
        return back()->with('success', 'Website checked successfully.');
    }

    public function logs(Website $website): View
    {
        $logs = $website->logs()->latest('checked_at')->paginate(50);
        return view('websites.logs', compact('website', 'logs'));
    }

    public function import(Request $request): RedirectResponse
    {
        $request->validate(['csv' => ['required', 'file', 'mimes:csv,txt', 'max:10240']]);
        $file = $request->file('csv');
        $handle = fopen($file->getRealPath(), 'r');
        if (!$handle) return back()->withErrors(['csv' => 'Could not read the CSV file.']);

        $first = fgetcsv($handle);
        if (!$first) {
            fclose($handle);
            return back()->withErrors(['csv' => 'CSV is empty.']);
        }

        $normalize = fn($v) => Str::of((string) $v)->trim()->lower()->replace([' ', '-', '/'], '_')->toString();
        $header = array_map($normalize, $first);
        $hasHeader = in_array('url', $header, true) || in_array('website_url', $header, true);
        $created = 0; $updated = 0; $skipped = 0;

        if (!$hasHeader) {
            rewind($handle);
            $header = ['url'];
        }

        while (($row = fgetcsv($handle)) !== false) {
            if (count(array_filter($row, fn($v) => trim((string)$v) !== '')) === 0) continue;

            $map = [];
            foreach ($header as $i => $key) $map[$key] = trim((string)($row[$i] ?? ''));
            $url = $map['url'] ?? $map['website_url'] ?? '';
            if (!$url || !filter_var($url, FILTER_VALIDATE_URL)) { $skipped++; continue; }
            if (!preg_match('#^https?://#i', $url)) { $url = 'https://' . $url; }

            $name = $map['name'] ?? $map['website_name'] ?? parse_url($url, PHP_URL_HOST) ?? $url;
            $technology = $map['technology'] ?? $map['tech'] ?? null;
            $documentRoot = $map['document_root'] ?? $map['root_path'] ?? $map['path'] ?? null;
            $existing = Website::where('url', $url)->first();

            if ($existing) {
                $existing->update(['name' => $name, 'technology' => $technology ?: $existing->technology, 'document_root' => $documentRoot ?: $existing->document_root]);
                $updated++;
            } else {
                Website::create(['name' => $name, 'url' => $url, 'technology' => $technology, 'document_root' => $documentRoot, 'is_active' => true, 'status' => 'unknown']);
                $created++;
            }
        }
        fclose($handle);

        return back()->with('success', "CSV imported: {$created} added, {$updated} updated, {$skipped} skipped.");
    }

    public function template(): StreamedResponse
    {
        return response()->streamDownload(function () {
            $out = fopen('php://output', 'w');
            fputcsv($out, ['name', 'url', 'technology', 'document_root']);
            fputcsv($out, ['Journal 1', 'https://example.com', 'OJS', '']);
            fputcsv($out, ['Website 2', 'https://example.org', 'Laravel', '']);
            fclose($out);
        }, 'website-monitor-template.csv', ['Content-Type' => 'text/csv']);
    }
}
