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
    ];

    protected function casts(): array
    {
        return [
            'is_active'=>'boolean','maintenance_mode'=>'boolean','last_checked_at'=>'datetime',
            'security_checked_at'=>'datetime','first_failed_at'=>'datetime','last_recovered_at'=>'datetime',
            'ssl_expires_at'=>'datetime','last_dns_check_at'=>'datetime','last_ssl_check_at'=>'datetime',
            'security_findings'=>'array','security_headers'=>'array','security_score'=>'integer','response_time_ms'=>'integer','http_code'=>'integer',
            'consecutive_failures'=>'integer','consecutive_successes'=>'integer',
        ];
    }

    public function logs(): HasMany { return $this->hasMany(MonitoringLog::class); }

    public function scopeProblems($query)
    {
        return $query->where(function($q){
            $q->whereIn('status',['down','slow','warning'])
              ->orWhere('security_status','suspicious');
        });
    }
}
