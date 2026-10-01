<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void {
        Schema::create('monitoring_logs', function (Blueprint $table) {
            $table->id(); $table->foreignId('website_id')->constrained()->cascadeOnDelete();
            $table->string('status'); $table->unsignedSmallInteger('http_code')->nullable();
            $table->unsignedInteger('response_time_ms')->nullable(); $table->text('error_message')->nullable();
            $table->string('security_status')->default('unknown'); $table->json('security_findings')->nullable(); $table->boolean('dns_ok')->nullable(); $table->boolean('ssl_ok')->nullable(); $table->json('diagnostic')->nullable(); $table->unsignedTinyInteger('security_score')->nullable(); $table->json('security_headers')->nullable(); $table->timestamp('checked_at')->index(); $table->timestamps();
            $table->index(['website_id','checked_at']);
        });
    }
    public function down(): void { Schema::dropIfExists('monitoring_logs'); }
};
