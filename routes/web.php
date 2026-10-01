<?php
use App\Http\Controllers\AuthController;
use App\Http\Controllers\DashboardController;
use App\Http\Controllers\DiagnosticController;
use App\Http\Controllers\SettingsController;
use App\Http\Controllers\WebsiteController;
use Illuminate\Support\Facades\Route;

Route::get('/login',[AuthController::class,'showLogin'])->name('login');
Route::post('/login',[AuthController::class,'login'])->name('login.perform');
Route::post('/logout',[AuthController::class,'logout'])->middleware('auth')->name('logout');
Route::middleware('auth')->group(function(){
    Route::get('/',[DashboardController::class,'index'])->name('dashboard');
    Route::post('/check-all',[DashboardController::class,'checkAll'])->name('dashboard.checkAll');
    Route::resource('websites',WebsiteController::class)->except(['show']);
    Route::post('/websites/{website}/check',[WebsiteController::class,'check'])->name('websites.check');
    Route::get('/websites/{website}/logs',[WebsiteController::class,'logs'])->name('websites.logs');
    Route::post('/websites/import',[WebsiteController::class,'import'])->name('websites.import');
    Route::get('/websites-template.csv',[WebsiteController::class,'template'])->name('websites.template');
    Route::get('/websites/{website}/diagnose',[DiagnosticController::class,'show'])->name('websites.diagnose');
    Route::post('/websites/{website}/recheck',[DiagnosticController::class,'recheck'])->name('websites.recheck');
    Route::post('/websites/{website}/security-scan',[DiagnosticController::class,'security'])->name('websites.security');
    Route::get('/settings/admin',[SettingsController::class,'edit'])->name('settings.admin');
    Route::post('/settings/admin',[SettingsController::class,'update'])->name('settings.admin.update');
});
