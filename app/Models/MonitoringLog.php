<?php
namespace App\Models;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
class MonitoringLog extends Model
{
    protected $fillable=['website_id','status','http_code','response_time_ms','error_message','security_status','security_findings','checked_at','dns_ok','ssl_ok','diagnostic','security_score','security_headers'];
    protected function casts(): array { return ['checked_at'=>'datetime','security_findings'=>'array','diagnostic'=>'array','security_headers'=>'array','security_score'=>'integer','response_time_ms'=>'integer','http_code'=>'integer','dns_ok'=>'boolean','ssl_ok'=>'boolean']; }
    public function website(): BelongsTo { return $this->belongsTo(Website::class); }
}
