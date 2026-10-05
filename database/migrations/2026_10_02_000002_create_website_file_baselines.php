<?php
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
return new class extends Migration {
 public function up(): void {
  if(Schema::hasTable('website_file_baselines')) return;
  Schema::create('website_file_baselines',function(Blueprint $table){
   $table->id();
   $table->foreignId('website_id')->constrained()->cascadeOnDelete();
   $table->string('path',512);
   $table->string('sha256',64);
   $table->unsignedBigInteger('size')->nullable();
   $table->timestamp('recorded_at')->nullable();
   $table->timestamps();
   $table->unique(['website_id','path']);
  });
 }
 public function down(): void { Schema::dropIfExists('website_file_baselines'); }
};
