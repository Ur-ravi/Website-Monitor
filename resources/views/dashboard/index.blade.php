@extends('layouts.app')
@section('content')
<div class="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 mb-6">
  <div><h1 class="text-3xl font-bold">Website Monitor</h1><p class="text-slate-500">Automatic monitoring for 100+ websites.</p></div>
  <button id="checkAllBtn" type="button" class="rounded-lg bg-blue-600 hover:bg-blue-700 text-white px-5 py-2.5 font-semibold shadow-sm">🔄 Check All Websites</button>
</div>

<div class="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-7 gap-3 mb-4">
@php $cards=[['Total',$total,'',''],['Online',$up,'bg-emerald-50 border-emerald-100','up'],['Down',$down,'bg-red-50 border-red-100','down'],['Slow',$slow,'bg-amber-50 border-amber-100','slow'],['Warning',$warning,'bg-orange-50 border-orange-100','warning'],['Suspicious',$suspicious,'bg-fuchsia-50 border-fuchsia-100','suspicious'],['Security Review',$securityReview,'bg-yellow-50 border-yellow-100','review'],['SSL <30d',$sslExpiring,'bg-purple-50 border-purple-100','ssl']]; @endphp
@foreach($cards as $c)<a href="{{ $c[3]==='ssl' ? route('dashboard',['ssl'=>'1']) : ($c[3]==='review' ? route('dashboard',['security'=>'review']) : ($c[3] ? route('dashboard',['status'=>$c[3]]) : route('dashboard'))) }}" class="rounded-xl border p-4 {{ $c[2] }} hover:shadow-md transition"><div class="text-sm text-slate-500">{{ $c[0] }}</div><div class="text-3xl font-bold mt-1">{{ $c[1] }}</div></a>@endforeach
</div>
<div class="grid grid-cols-3 gap-3 mb-6">
@foreach(['OJS'=>'bg-indigo-50 border-indigo-100 text-indigo-900','PHP'=>'bg-cyan-50 border-cyan-100 text-cyan-900','React'=>'bg-sky-50 border-sky-100 text-sky-900'] as $tech=>$cls)
<a href="{{ route('dashboard',['technology'=>$tech]) }}" class="rounded-xl border p-4 {{ $cls }} hover:shadow-md transition"><div class="text-sm font-medium">{{ $tech }} Websites</div><div class="text-2xl font-bold mt-1">{{ $technologyCounts[$tech] ?? 0 }}</div></a>
@endforeach
</div>

<div class="bg-white rounded-xl border overflow-hidden mb-6"><div class="p-4 border-b flex items-center justify-between"><div><h2 class="font-bold text-lg">🚨 Problems Requiring Attention</h2><p class="text-sm text-slate-500">Only current actionable issues are shown here.</p></div><span class="text-xs text-slate-500">Auto-updated by scheduler</span></div>
@if($problems->count())<div>@foreach($problems as $w)<div class="p-4 border-b last:border-b-0 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3">
<div class="min-w-0"><div class="font-semibold">{{ $w->name }}</div><a href="{{ $w->url }}" target="_blank" class="text-xs text-slate-500 break-all">{{ $w->url }}</a><div class="text-xs text-slate-600 mt-1">{{ $w->status==='down' ? ($w->last_error ?: 'Website is not responding') : ($w->status==='slow' ? 'Response: '.($w->response_time_ms ?? '—').' ms' : ($w->security_status==='suspicious' ? 'Security findings: '.count($w->security_findings ?? []) : (($w->ssl_expires_at && $w->ssl_expires_at->lte(now()->addDays(30))) ? 'SSL expires in '.$w->ssl_expires_at->diffInDays(now()).' days' : 'Needs attention'))) }}</div></div>
<div class="flex flex-wrap gap-2 items-center"><span class="px-2.5 py-1 rounded-full text-xs font-semibold bg-slate-100">{{ strtoupper($w->status) }}</span>@if($w->security_status==='suspicious')<span class="px-2.5 py-1 rounded-full text-xs font-semibold bg-fuchsia-100 text-fuchsia-700">SECURITY: SUSPICIOUS</span>@endif<a href="{{ route('websites.diagnose',$w) }}" class="px-3 py-1.5 rounded-lg bg-blue-50 text-blue-700 text-sm font-semibold">Diagnose</a><button type="button" data-single-check="{{ $w->id }}" class="px-3 py-1.5 rounded-lg bg-slate-100 text-sm font-semibold">Recheck</button></div>
</div>@endforeach</div>@else<div class="p-8 text-center text-emerald-700">✓ No current problems requiring attention.</div>@endif</div>

<div class="bg-white rounded-xl border p-4 mb-6"><form id="searchForm" method="GET" class="grid grid-cols-1 md:grid-cols-4 gap-3"><input name="search" value="{{ $search }}" placeholder="Search name, URL or technology..." class="border rounded-lg px-3 py-2"><select name="status" class="border rounded-lg px-3 py-2"><option value="">All statuses</option>@foreach(['up','down','slow','warning'] as $s)<option value="{{ $s }}" @selected($status===$s)>{{ strtoupper($s) }}</option>@endforeach<option value="suspicious" @selected($status==='suspicious')>SUSPICIOUS</option></select><select name="technology" class="border rounded-lg px-3 py-2"><option value="">All technologies</option>@foreach($technologies as $t)<option value="{{ $t }}" @selected($technology===$t)>{{ $t }}</option>@endforeach</select><div class="flex gap-2"><button id="searchBtn" class="bg-slate-900 text-white rounded-lg px-4 py-2">Search</button><a href="{{ route('dashboard') }}" class="border rounded-lg px-4 py-2">Reset</a></div></form></div>

<div class="bg-white rounded-xl border overflow-hidden"><div class="p-4 border-b flex justify-between"><h2 class="font-bold">Websites</h2><a href="{{ route('websites.index') }}" class="text-blue-600 text-sm">Manage →</a></div><div class="overflow-x-auto"><table class="w-full text-sm"><thead class="bg-slate-50"><tr><th class="text-left p-3">Website</th><th class="text-left p-3">Technology</th><th class="text-left p-3">Status</th><th class="text-left p-3">HTTP</th><th class="text-left p-3">Response</th><th class="text-left p-3">Security</th><th class="text-left p-3">Last Check</th><th class="text-left p-3">Action</th></tr></thead><tbody>@forelse($websites as $w)<tr class="border-t"><td class="p-3"><div class="font-semibold">{{ $w->name }}</div><a class="text-xs text-slate-500" target="_blank" href="{{ $w->url }}">{{ $w->url }}</a></td><td class="p-3">{{ $w->technology ?: '—' }}</td><td class="p-3"><span class="px-2 py-1 rounded-full text-xs font-semibold {{ $w->status==='down'?'bg-red-100 text-red-700':($w->status==='slow'?'bg-amber-100 text-amber-700':($w->status==='warning'?'bg-orange-100 text-orange-700':'bg-emerald-100 text-emerald-700')) }}">{{ strtoupper($w->status) }}</span></td><td class="p-3">{{ $w->http_code ?: '—' }}</td><td class="p-3">{{ $w->response_time_ms ? $w->response_time_ms.' ms' : '—' }}</td><td class="p-3">{{ strtoupper($w->security_status ?: 'unknown') }}{{ $w->security_score !== null ? ' · '.$w->security_score.'/100' : '' }}</td><td class="p-3">{{ $w->last_checked_at?->diffForHumans() ?: 'Never' }}</td><td class="p-3"><a href="{{ route('websites.diagnose',$w) }}" class="text-blue-700 font-semibold">Diagnose</a></td></tr>@empty<tr><td colspan="8" class="p-8 text-center text-slate-500">No websites found.</td></tr>@endforelse</tbody></table></div><div class="p-4">{{ $websites->links() }}</div></div>

<div id="progressModal" class="hidden fixed inset-0 z-50 bg-slate-950/60 backdrop-blur-sm items-center justify-center p-4"><div class="bg-white rounded-2xl shadow-2xl max-w-lg w-full p-6"><div class="flex justify-between items-center"><h2 id="progressTitle" class="text-xl font-bold">Checking websites...</h2><span id="progressPercent" class="text-lg font-bold">0%</span></div><p id="progressText" class="text-sm text-slate-500 mt-1">Starting...</p><div class="w-full bg-slate-200 rounded-full h-3 mt-5 overflow-hidden"><div id="progressBar" class="bg-blue-600 h-3 rounded-full transition-all duration-300" style="width:0%"></div></div><div class="flex justify-between text-xs text-slate-500 mt-2"><span id="progressCurrent">0 / {{ count($monitorableIds) }}</span><span>One website at a time</span></div><div id="progressResult" class="mt-4 max-h-56 overflow-y-auto space-y-2"></div><div class="mt-5 flex justify-end"><button id="closeProgress" type="button" class="hidden px-4 py-2 rounded-lg bg-slate-900 text-white">Close & Refresh</button></div></div></div>

<script>
(() => {
 const csrf='{{ csrf_token() }}';
 const ids=@json($monitorableIds);
 const modal=document.getElementById('progressModal'), bar=document.getElementById('progressBar'), pct=document.getElementById('progressPercent'), text=document.getElementById('progressText'), current=document.getElementById('progressCurrent'), results=document.getElementById('progressResult'), close=document.getElementById('closeProgress');
 function showModal(){modal.classList.remove('hidden');modal.classList.add('flex');document.body.classList.add('overflow-hidden');}
 function finish(){close.classList.remove('hidden');}
 close?.addEventListener('click',()=>location.reload());
 document.getElementById('checkAllBtn')?.addEventListener('click', async()=>{
   if(!ids.length){alert('No active websites to check.');return;}
   showModal(); results.innerHTML=''; close.classList.add('hidden');
   for(let i=0;i<ids.length;i++){
     const id=ids[i], percent=Math.round((i/ids.length)*100); bar.style.width=percent+'%'; pct.textContent=percent+'%'; current.textContent=i+' / '+ids.length; text.textContent='Checking website '+(i+1)+' of '+ids.length+'...';
     try{
       const r=await fetch('{{ url('/websites') }}/'+id+'/check',{method:'POST',headers:{'X-CSRF-TOKEN':csrf,'Accept':'application/json','X-Requested-With':'XMLHttpRequest'}});
       const data=await r.json();
       const color=data.status==='up'?'emerald':(data.status==='down'?'red':(data.status==='slow'?'amber':'orange'));
       results.insertAdjacentHTML('afterbegin',`<div class="text-xs p-2 rounded bg-${color}-50 text-${color}-800"><strong>${escapeHtml(data.name)}</strong> — ${escapeHtml(data.status.toUpperCase())}${data.http_code?' · HTTP '+data.http_code:''}${data.response_time_ms?' · '+data.response_time_ms+'ms':''}${data.security_status==='suspicious'?' · 🛡 SUSPICIOUS':''}</div>`);
     }catch(e){results.insertAdjacentHTML('afterbegin',`<div class="text-xs p-2 rounded bg-red-50 text-red-800">Check failed for website ID ${id}. You can retry from Diagnose.</div>`);}
   }
   bar.style.width='100%';pct.textContent='100%';current.textContent=ids.length+' / '+ids.length;text.textContent='All checks completed.';finish();
 });
 document.querySelectorAll('[data-single-check]').forEach(btn=>btn.addEventListener('click',async()=>{btn.disabled=true;btn.textContent='Checking...';try{const r=await fetch('{{ url('/websites') }}/'+btn.dataset.singleCheck+'/check',{method:'POST',headers:{'X-CSRF-TOKEN':csrf,'Accept':'application/json','X-Requested-With':'XMLHttpRequest'}});if(r.ok) location.reload(); else alert('Check failed.');}catch(e){alert('Could not complete the check.');}finally{btn.disabled=false;btn.textContent='Recheck';}}));
 document.getElementById('searchForm')?.addEventListener('submit',()=>{
   showModal(); document.getElementById('progressTitle').textContent='Loading search results...'; document.getElementById('progressText').textContent='Filtering websites and preparing the results...'; document.getElementById('progressCurrent').textContent='Please wait...'; results.innerHTML=''; close.classList.add('hidden');
   let n=5; bar.style.width=n+'%'; pct.textContent=n+'%'; const timer=setInterval(()=>{ if(n<90){n+=5;bar.style.width=n+'%';pct.textContent=n+'%';} else clearInterval(timer); },120);
 });
 function escapeHtml(v){return String(v??'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));}
})();
</script>
@endsection
