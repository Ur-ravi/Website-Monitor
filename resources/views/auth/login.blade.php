<!doctype html>
<html>

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Login - Website Monitor</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>

<body class="min-h-screen bg-slate-100 flex items-center justify-center p-4">
    <div class="bg-white shadow-xl rounded-2xl p-8 w-full max-w-md">
        <h1 class="text-2xl font-bold mb-2">Website Monitor</h1>
        <p class="text-slate-500 mb-6">Admin Login</p>
        <form method="POST" action="{{ route('login.perform') }}" class="space-y-4">@csrf<div><label class="block text-sm font-medium mb-1">Email</label><input name="email" type="email" value="admin@edutechy.in" required class="w-full rounded-lg border px-3 py-2"></div>
            <div><label class="block text-sm font-medium mb-1">Password</label><input name="password" type="password" required class="w-full rounded-lg border px-3 py-2" value="ChangeMe@12345"></div><label class="flex items-center gap-2 text-sm"><input type="checkbox" name="remember"> Remember me</label><button class="w-full rounded-lg bg-slate-900 text-white py-2.5 font-semibold">Login</button>
        </form>
    </div>
</body>

</html>