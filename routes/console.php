<?php
use Illuminate\Support\Facades\Schedule;
Schedule::command('websites:check')->everyFiveMinutes()->withoutOverlapping(4);
Schedule::command('websites:file-scan')->hourly()->withoutOverlapping(30);
