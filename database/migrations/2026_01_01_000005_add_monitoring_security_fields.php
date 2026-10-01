<?php
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
return new class extends Migration {
 public function up(): void {
  Schema::table('websites',function(Blueprint $t){
   if(!Schema::hasColumn('websites','security_status')) $t->string('security_status')->default('unknown');
   if(!Schema::hasColumn('websites','security_findings')) $t->json('security_findings')->nullable();
   if(!Schema::hasColumn('websites','security_checked_at')) $t->timestamp('security_checked_at')->nullable();
   if(!Schema::hasColumn('websites','consecutive_failures')) $t->unsignedInteger('consecutive_failures')->default(0);
   if(!Schema::hasColumn('websites','consecutive_successes')) $t->unsignedInteger('consecutive_successes')->default(0);
   if(!Schema::hasColumn('websites','first_failed_at')) $t->timestamp('first_failed_at')->nullable();
   if(!Schema::hasColumn('websites','last_recovered_at')) $t->timestamp('last_recovered_at')->nullable();
   if(!Schema::hasColumn('websites','maintenance_mode')) $t->boolean('maintenance_mode')->default(false);
   if(!Schema::hasColumn('websites','document_root')) $t->string('document_root',1024)->nullable();
   if(!Schema::hasColumn('websites','ssl_expires_at')) $t->timestamp('ssl_expires_at')->nullable();
   if(!Schema::hasColumn('websites','last_dns_check_at')) $t->timestamp('last_dns_check_at')->nullable();
   if(!Schema::hasColumn('websites','last_ssl_check_at')) $t->timestamp('last_ssl_check_at')->nullable();
  });
  Schema::table('monitoring_logs',function(Blueprint $t){
   if(!Schema::hasColumn('monitoring_logs','security_status')) $t->string('security_status')->default('unknown');
   if(!Schema::hasColumn('monitoring_logs','security_findings')) $t->json('security_findings')->nullable();
   if(!Schema::hasColumn('monitoring_logs','dns_ok')) $t->boolean('dns_ok')->nullable();
   if(!Schema::hasColumn('monitoring_logs','ssl_ok')) $t->boolean('ssl_ok')->nullable();
   if(!Schema::hasColumn('monitoring_logs','diagnostic')) $t->json('diagnostic')->nullable();
  });
 }
 public function down(): void {}
};
