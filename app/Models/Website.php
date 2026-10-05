<?php
namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Website extends Model
{
    protected $fillable = [
        'name','url','technology','is_active','status','http_code','response_time_ms',
        'last_checked_at','last_error','security_status','security_findings','security_checked_at',
        'consecutive_failures','consecutive_successes','first_failed_at','last_recovered_at',
        'maintenance_mode','document_root','ssl_expires_at','last_dns_check_at','last_ssl_check_at','security_score','security_headers',
        'expected_title','expected_keywords','expected_http_code','content_check_enabled','file_integrity_enabled',
        'homepage_baseline','integrity_status','last_content_ok','status_reasons','first_suspicious_at','last_suspicious_at',
    ];

    protected function casts(): array
    {
        return [
            'is_active'=>'boolean','maintenance_mode'=>'boolean','last_checked_at'=>'datetime',
            'security_checked_at'=>'datetime','first_failed_at'=>'datetime','last_recovered_at'=>'datetime',
            'ssl_expires_at'=>'datetime','last_dns_check_at'=>'datetime','last_ssl_check_at'=>'datetime',
            'security_findings'=>'array','security_headers'=>'array','security_score'=>'integer','response_time_ms'=>'integer','http_code'=>'integer',
            'consecutive_failures'=>'integer','consecutive_successes'=>'integer',
            'homepage_baseline'=>'array','status_reasons'=>'array','expected_http_code'=>'integer',
            'content_check_enabled'=>'boolean','file_integrity_enabled'=>'boolean','last_content_ok'=>'boolean',
            'first_suspicious_at'=>'datetime','last_suspicious_at'=>'datetime',
        ];
    }

    public function logs(): HasMany { return $this->hasMany(MonitoringLog::class); }
    public function fileBaselines(): HasMany { return $this->hasMany(WebsiteFileBaseline::class); }

    public function scopeProblems($query)
    {
        return $query->where(function($q){
            $q->whereIn('status',['down','slow','warning','suspicious'])
              ->orWhere('security_status','suspicious');
        });
    }

    public function expectedKeywordList(): array
    {
        $raw = (string)($this->expected_keywords ?? '');
        $items = preg_split('/[\r\n,]+/', $raw) ?: [];
        return array_values(array_filter(array_map('trim', $items), fn($k) => $k !== ''));
    }
}
