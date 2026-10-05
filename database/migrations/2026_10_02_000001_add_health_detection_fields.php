<?php
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
return new class extends Migration {
 public function up(): void {
  Schema::table('websites',function(Blueprint $t){
   if(!Schema::hasColumn('websites','expected_title')) $t->string('expected_title')->nullable();
   if(!Schema::hasColumn('websites','expected_keywords')) $t->text('expected_keywords')->nullable();
   if(!Schema::hasColumn('websites','expected_http_code')) $t->unsignedSmallInteger('expected_http_code')->nullable();
   if(!Schema::hasColumn('websites','content_check_enabled')) $t->boolean('content_check_enabled')->default(true);
   if(!Schema::hasColumn('websites','file_integrity_enabled')) $t->boolean('file_integrity_enabled')->default(false);
   if(!Schema::hasColumn('websites','homepage_baseline')) $t->json('homepage_baseline')->nullable();
   if(!Schema::hasColumn('websites','integrity_status')) $t->string('integrity_status')->default('unknown');
   if(!Schema::hasColumn('websites','last_content_ok')) $t->boolean('last_content_ok')->nullable();
   if(!Schema::hasColumn('websites','status_reasons')) $t->json('status_reasons')->nullable();
   if(!Schema::hasColumn('websites','first_suspicious_at')) $t->timestamp('first_suspicious_at')->nullable();
   if(!Schema::hasColumn('websites','last_suspicious_at')) $t->timestamp('last_suspicious_at')->nullable();
  });
  Schema::table('monitoring_logs',function(Blueprint $t){
   if(!Schema::hasColumn('monitoring_logs','content_ok')) $t->boolean('content_ok')->nullable();
   if(!Schema::hasColumn('monitoring_logs','integrity_status')) $t->string('integrity_status')->default('unknown');
   if(!Schema::hasColumn('monitoring_logs','status_reasons')) $t->json('status_reasons')->nullable();
   if(!Schema::hasColumn('monitoring_logs','homepage_hash')) $t->string('homepage_hash',64)->nullable();
  });
 }
 public function down(): void {}
};
