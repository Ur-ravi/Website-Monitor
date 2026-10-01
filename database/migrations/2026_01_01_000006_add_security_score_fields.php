<?php
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
return new class extends Migration {
 public function up(): void {
  Schema::table('websites', function(Blueprint $t){ if(!Schema::hasColumn('websites','security_score')) $t->unsignedTinyInteger('security_score')->nullable(); if(!Schema::hasColumn('websites','security_headers')) $t->json('security_headers')->nullable(); });
  Schema::table('monitoring_logs', function(Blueprint $t){ if(!Schema::hasColumn('monitoring_logs','security_score')) $t->unsignedTinyInteger('security_score')->nullable(); if(!Schema::hasColumn('monitoring_logs','security_headers')) $t->json('security_headers')->nullable(); });
 }
 public function down(): void {}
};
