<?php
namespace App\Models;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
class WebsiteFileBaseline extends Model
{
    protected $fillable=['website_id','path','sha256','size','recorded_at'];
    protected function casts(): array { return ['size'=>'integer','recorded_at'=>'datetime']; }
    public function website(): BelongsTo { return $this->belongsTo(Website::class); }
}
