<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\DB;

class DatabaseSeeder extends Seeder
{
    public function run(): void
    {
        DB::table('users')->updateOrInsert(
            ['email' => env('ADMIN_EMAIL', 'admin@example.com')],
            ['name' => env('ADMIN_NAME', 'Administrator'), 'password' => Hash::make(env('ADMIN_PASSWORD', 'ChangeThisPassword!')), 'created_at' => now(), 'updated_at' => now()]
        );
    }
}
