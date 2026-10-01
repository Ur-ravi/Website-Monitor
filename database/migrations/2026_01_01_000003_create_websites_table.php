<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void {
        Schema::create('websites', function (Blueprint $table) {
            $table->id(); $table->string('name'); $table->text('url'); $table->string('technology')->nullable();
            $table->boolean('is_active')->default(true); $table->string('status')->default('unknown');
            $table->unsignedSmallInteger('http_code')->nullable(); $table->unsignedInteger('response_time_ms')->nullable();
            $table->timestamp('last_checked_at')->nullable(); $table->text('last_error')->nullable(); $table->string('security_status')->default('unknown'); $table->json('security_findings')->nullable(); $table->timestamp('security_checked_at')->nullable(); $table->unsignedInteger('consecutive_failures')->default(0); $table->unsignedInteger('consecutive_successes')->default(0); $table->timestamp('first_failed_at')->nullable(); $table->timestamp('last_recovered_at')->nullable(); $table->boolean('maintenance_mode')->default(false); $table->string('document_root',1024)->nullable(); $table->timestamp('ssl_expires_at')->nullable(); $table->timestamp('last_dns_check_at')->nullable(); $table->timestamp('last_ssl_check_at')->nullable(); $table->unsignedTinyInteger('security_score')->nullable(); $table->json('security_headers')->nullable(); $table->timestamps();
            $table->index(['status','is_active']);
        });
    }
    public function down(): void { Schema::dropIfExists('websites'); }
};
